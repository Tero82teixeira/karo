'use strict';
const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');

const URL_DB = process.env.DATABASE_URL;
const USER = process.env.PROMOS_ADMIN_USER || 'admin';
const PASSWORD = process.env.PROMOS_ADMIN_PASSWORD;
const SECRET = process.env.PROMOS_SESSION_SECRET;
if (!URL_DB || !PASSWORD || !SECRET || PASSWORD.length < 16 || SECRET.length < 32) {
  throw new Error('Configurar DATABASE_URL, PROMOS_ADMIN_PASSWORD (16+) e PROMOS_SESSION_SECRET (32+) no Render');
}
const pool = new Pool({ connectionString: URL_DB, max: 4, connectionTimeoutMillis: 14000, idleTimeoutMillis: 20000 });
const attempts = new Map();
const lookupAttempts = new Map();
const NOW = () => new Date().toISOString();
const TZ = 'America/Sao_Paulo';
const json = (res, status, obj) => {
  res.writeHead(status, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});
  res.end(JSON.stringify(obj));
};
const error = (res,code,message) => json(res,code,{error:message});
const hmac = s => crypto.createHmac('sha256', SECRET).update(s).digest('hex');
const safeEqual = (a,b) => Buffer.byteLength(a) === Buffer.byteLength(b) && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const parseCookies = req => Object.fromEntries((req.headers.cookie||'').split(';').map(s=>s.trim()).filter(s=>s.includes('=')).map(s=>{const i=s.indexOf('=');return [s.slice(0,i),s.slice(i+1)];}));
function auth(req) {
  const cookie = parseCookies(req).promos_session||'';
  const i=cookie.lastIndexOf('.');
  if(i<1)return null;
  const body=cookie.slice(0,i), sig=cookie.slice(i+1);
  if(!safeEqual(hmac(body),sig))return null;
  const parts=body.split('.');
  if(parts.length!==3||parts[0]!=='admin'||!Number.isSafeInteger(Number(parts[1]))||Number(parts[1])<Date.now())return null;
  return {token:cookie,csrf:hmac('csrf:'+cookie)};
}
function originOk(req) {
  const origin=req.headers.origin;
  if(!origin)return req.headers['sec-fetch-site']!=='cross-site';
  try {const u=new URL(origin);return u.host===req.headers.host && u.protocol==='https:';}catch{return false;}
}
async function body(req) {
  let data=''; for await(const buf of req){data+=buf.toString();if(data.length>18000)throw Object.assign(new Error('Dados muito grandes'),{status:413});}
  try{return JSON.parse(data||'{}');}catch{throw Object.assign(new Error('JSON inválido'),{status:400});}
}
function csrf(req,session) {
  return session && originOk(req) && safeEqual(String(req.headers['x-csrf-token']||''),session.csrf);
}
function isAffiliateLink(raw,platform) {
  try {
    const u=new URL(raw);
    if(u.protocol!=='https:'||u.username||u.password||u.port&&u.port!=='443')return false;
    const shopee=['shopee.com.br','www.shopee.com.br','shope.ee','s.shopee.com.br','affiliate.shopee.com.br'];
    const ml=['mercadolivre.com.br','www.mercadolivre.com.br','produto.mercadolivre.com.br','mercadolivre.com','www.mercadolivre.com','meli.la'];
    return (platform==='shopee'?shopee:ml).includes(u.hostname.toLowerCase());
  }catch{return false;}
}
const restricted=/\b(arma|armas|muni[cç][aã]o|cigarro|tabaco|vape|maconha|cannabis|cassino|apostas|anabolizante|falsificado)\b/i;
function num(x,min,max) {
  if(x===null||x===undefined||x==='')return null;
  const n=Number(x);
  if(!Number.isFinite(n)||n<min||n>max)throw Object.assign(new Error('Valor numérico inválido'),{status:422});
  return n;
}
function evaluate(p) {
  let score=0;
  const details={};
  if(p.rating!==null){details.avaliacao=Math.round(p.rating/5*25);score+=details.avaliacao;}
  if(p.sales!==null){details.vendas=Math.round(Math.min(1,Math.log10(p.sales+1)/Math.log10(1001))*25);score+=details.vendas;}
  if(p.commission_rate!==null){details.comissao=Math.round(Math.min(1,p.commission_rate/20)*25);score+=details.comissao;}
  if(p.discount!==null){details.desconto=Math.round(Math.min(1,p.discount/50)*15);score+=details.desconto;}
  details.qualidade=Math.round([p.name,p.seller,p.image_url,p.affiliate_url].filter(Boolean).length/4*10);
  score+=details.qualidade;
  const missing=['rating','sales','commission_rate','discount','price'].filter(k=>p[k]===null);
  const why=[];
  if(missing.length)why.push('Dados insuficientes: '+missing.join(', '));
  if(!isAffiliateLink(p.affiliate_url,p.platform))why.push('Link de afiliado ausente ou inválido');
  if(!p.price||p.price<=0)why.push('Preço inválido');
  if(restricted.test(p.name+' '+p.category))why.push('Categoria restrita');
  return {score:Math.min(100,score),eligible:why.length===0?1:0,reason:why.join('; ')||'Dados suficientes para seleção',details};
}
const currency = v => 'R$ '+Number(v).toFixed(2).replace('.',',');
const dateSP = d => new Intl.DateTimeFormat('sv-SE',{timeZone:TZ,year:'numeric',month:'2-digit',day:'2-digit'}).format(d);
const clockSP = d => new Intl.DateTimeFormat('en-GB',{timeZone:TZ,hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).format(d);
function campaignCopy(p) {
  const lines=['✨ '+p.name,'💰 '+currency(p.price)];
  if(p.discount && p.discount>0)lines.push('🏷️ Desconto informado: '+p.discount+'%');
  lines.push('','🛒 Link de afiliado:',p.affiliate_url,'','Preço e disponibilidade podem mudar.','#publi #PromosDoRo');
  return lines.join('\n');
}
async function log(client,action,description) {
  await client.query('INSERT INTO audit(event,message,created_at) VALUES ($1,$2,$3)',[action,String(description).slice(0,700),NOW()]);
}
async function init() {
  const rows = await pool.query('SELECT id FROM settings WHERE id=1');
  if(!rows.rowCount)await pool.query('INSERT INTO settings(id) VALUES(1)');
}
async function state() {
  const [s,p,c,a,k] = await Promise.all([
    pool.query('SELECT * FROM settings WHERE id=1'),
    pool.query('SELECT * FROM products ORDER BY updated_at DESC LIMIT 300'),
    pool.query('SELECT c.*,p.name AS product_name,p.platform AS product_platform FROM campaigns c JOIN products p ON p.id=c.product_id ORDER BY c.created_at DESC LIMIT 200'),
    pool.query('SELECT id,event,message,created_at FROM audit ORDER BY id DESC LIMIT 80'),
    pool.query("SELECT (SELECT COUNT(*)::int FROM products) products, (SELECT COUNT(*)::int FROM campaigns WHERE status='simulated') simulated, (SELECT COUNT(*)::int FROM campaigns WHERE status='published') published, (SELECT COUNT(*)::int FROM products WHERE eligible=1 AND score >= (SELECT min_score FROM settings WHERE id=1)) eligible")
  ]);
  return {settings:s.rows[0],products:p.rows,campaigns:c.rows,audit:a.rows,stats:k.rows[0],integrations:{shopee:false,telegram:false,instagram:false,whatsapp:false},simulation_only:true};
}

// Consulta restrita a domínios oficiais: não faz scraping, não armazena cookies e não acessa páginas arbitrárias.
function cleanMlUrl(value){
  if(typeof value!=='string'||value.length>1800||!isAffiliateLink(value,'mercado_livre'))
    throw Object.assign(new Error('Informe um link HTTPS oficial do Mercado Livre ou meli.la'),{status:422});
  const u=new URL(value);
  if(u.hash)u.hash='';
  return u;
}
function mlReference(u){
  const q=u.searchParams.get('item_id')||u.searchParams.get('itemId')||'';
  const path=u.pathname||'';
  const listing=(q.match(/^MLB[-]?(\d{7,15})$/i)||path.match(/MLB[-]?(\d{7,15})/i));
  const cat=path.match(/\/p\/MLB(\d{7,15})(?:\/|$)/i);
  return {
    item_id:listing && !cat?'MLB'+listing[1]:null,
    catalog_id:cat?'MLB'+cat[1]:null
  };
}
async function resolveMlLink(raw){
  const source=cleanMlUrl(raw);
  if(source.hostname!=='meli.la')return {final_url:source.origin+source.pathname,reference:mlReference(source),redirect_checked:false,redirect_error:null};
  let current=source,problem=null;
  try{
    for(let hops=0;hops<4&&current.hostname==='meli.la';hops++){
      let location=null;
      for(const method of ['HEAD','GET']){
        const response=await fetch(current.toString(),{method,redirect:'manual',signal:AbortSignal.timeout(5000),headers:{Accept:'*/*'}});
        location=response.headers.get('location');
        if(response.body)await response.body.cancel();
        if(location)break;
        if(method==='GET')problem='Este link não retornou um redirecionamento verificável';
      }
      if(!location)break;
      const next=new URL(location,current);
      cleanMlUrl(next.toString());
      current=next;
    }
  }catch(e){problem=e.name==='TimeoutError'?'Tempo de consulta esgotado':'Não foi possível confirmar o redirecionamento';}
  return {final_url:current.origin+current.pathname,reference:mlReference(current),redirect_checked:current.hostname!=='meli.la',redirect_error:problem};
}
async function officialMlItem(itemId){
  const token=process.env.MERCADOLIVRE_ACCESS_TOKEN;
  if(!token)return {data:null,status:'not_configured'};
  if(!/^MLB\d{7,15}$/.test(itemId||''))return {data:null,status:'item_id_unknown'};
  try{
    const response=await fetch('https://api.mercadolibre.com/items/'+encodeURIComponent(itemId),{
      method:'GET',redirect:'error',signal:AbortSignal.timeout(6500),headers:{Authorization:'Bearer '+token,Accept:'application/json'}
    });
    if(!response.ok)return {data:null,status:'api_http_'+response.status};
    const data=await response.json();
    if(data.id!==itemId||typeof data.title!=='string')return {data:null,status:'invalid_api_response'};
    return {data,status:'confirmed_api'};
  }catch(e){return {data:null,status:e.name==='TimeoutError'?'api_timeout':'api_unavailable'};}
}
async function importMercadoLivreLink(raw){
  const input=cleanMlUrl(raw).toString();
  const previous=await pool.query('SELECT * FROM products WHERE platform=$1 AND affiliate_url=$2 LIMIT 1',['mercado_livre',input]);
  if(previous.rowCount)return {created:false,product:previous.rows[0],identified:previous.rows[0].source==='mercado_livre_api',message:'Este link já estava cadastrado; informações anteriores preservadas'};
  const resolution=await resolveMlLink(input);
  const {item_id:itemId,catalog_id:catalogId}=resolution.reference;
  const api=await officialMlItem(itemId);
  const info=api.data;
  const ident=itemId||catalogId;
  const title=info?.title?.trim().slice(0,250)||(ident?'Produto Mercado Livre '+ident:'Produto Mercado Livre — identificação pendente');
  const price=info?.price!==undefined&&Number.isFinite(Number(info.price))&&Number(info.price)>0?Number(info.price):null;
  const originalPrice=info?.original_price!==undefined&&Number(info.original_price)>0?Number(info.original_price):null;
  const discount=price!==null&&originalPrice!==null&&originalPrice>price?Math.round((originalPrice-price)*100/originalPrice):null;
  const photo=info?.pictures?.[0]?.secure_url||info?.pictures?.[0]?.url||info?.thumbnail||null;
  const p={platform:'mercado_livre',name:title,category:'A identificar',seller:null,price,discount,sales:info&&Number.isFinite(info.sold_quantity)&&info.sold_quantity>=0?info.sold_quantity:null,rating:null,commission_rate:null,image_url:photo,affiliate_url:input};
  const scoring=evaluate(p);
  let score=info?scoring.score:0;
  const reason=info?'Dados oficiais do item recuperados; comissão e avaliações ainda precisam de confirmação':(ident?'ID identificado, porém detalhes indisponíveis sem acesso autorizado à API':'Não foi possível identificar o anúncio somente pelo link');
  const saved=await pool.query(
    'INSERT INTO products(id,platform,item_key,name,category,seller,price,discount,sales,rating,commission_rate,commission_amount,image_url,affiliate_url,original_url,source,score,eligible,reason,score_details,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULL,$12,$13,$14,$15,$16,0,$17,$18,$19,$19) ON CONFLICT DO NOTHING RETURNING *',
    [crypto.randomUUID(),'mercado_livre',ident,title,p.category,p.seller,p.price,p.discount,p.sales,p.rating,null,p.image_url,input,resolution.final_url,info?'mercado_livre_api':'link_pendente',score,reason,JSON.stringify({...scoring.details,api_status:api.status,redirect_checked:resolution.redirect_checked,redirect_error:resolution.redirect_error}),NOW()]
  );
  if(!saved.rowCount){
    const exists=await pool.query('SELECT * FROM products WHERE platform=$1 AND (affiliate_url=$2 OR item_key=$3) ORDER BY updated_at DESC LIMIT 1',['mercado_livre',input,ident]);
    return {created:false,product:exists.rows[0]||null,identified:!!info,message:'Produto já cadastrado ou associado a outro link. O link existente foi preservado'};
  }
  await pool.query('INSERT INTO audit(event,message,created_at) VALUES ($1,$2,$3)',['ml_link_import',saved.rows[0].id,NOW()]);
  return {created:true,product:saved.rows[0],identified:!!info,api_status:api.status,redirect_checked:resolution.redirect_checked,message:info?'Informações obtidas pela API oficial. Comissão ainda pendente':reason};
}

async function createProduct(input) {
  const platform=input.platform==='mercado_livre'?'mercado_livre':'shopee';
  const name=String(input.name||'').trim().slice(0,250),category=String(input.category||'Diversos').trim().slice(0,80)||'Diversos';
  if(name.length<3)throw Object.assign(new Error('Informe o nome do produto'),{status:422});
  const p={platform,name,category,seller:String(input.seller||'').trim().slice(0,120)||null,price:num(input.price,0,10000000),rating:num(input.rating,0,5),sales:num(input.sales,0,100000000),commission_rate:num(input.commission_rate,0,100),discount:num(input.discount,0,100),image_url:String(input.image_url||'').trim().slice(0,1800)||null,affiliate_url:String(input.affiliate_url||'').trim().slice(0,1800)||null,original_url:null};
  if(p.sales!==null && !Number.isInteger(p.sales))throw Object.assign(new Error('Vendas precisam ser inteiras'),{status:422});
  const r=evaluate(p),id=crypto.randomUUID(),now=NOW();
  await pool.query('INSERT INTO products (id,platform,item_key,name,category,seller,price,discount,sales,rating,commission_rate,commission_amount,image_url,affiliate_url,original_url,source,score,eligible,reason,score_details,created_at,updated_at) VALUES ($1,$2,NULL,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NULL,$14,$15,$16,$17,$18,$19,$20)',[id,p.platform,p.name,p.category,p.seller,p.price,p.discount,p.sales,p.rating,p.commission_rate,p.price!==null&&p.commission_rate!==null?+(p.price*p.commission_rate/100).toFixed(2):null,p.image_url,p.affiliate_url,'manual',r.score,r.eligible,r.reason,JSON.stringify(r.details),now,now]);
  await pool.query('INSERT INTO audit(event,message,created_at) VALUES($1,$2,$3)',['product_saved',id,NOW()]);
  return {id,...r};
}
async function runCycle() {
  const cx=await pool.connect();
  try {
    await cx.query('BEGIN');
    const sr=await cx.query('SELECT * FROM settings WHERE id=1 FOR UPDATE');
    const s=sr.rows[0];
    if(s.paused){await log(cx,'cycle_paused','Automação pausada');await cx.query('COMMIT');return {created:0,message:'Automação pausada'};}
    const products=(await cx.query('SELECT * FROM products WHERE eligible=1 AND score>=$1 ORDER BY score DESC,updated_at DESC',[s.min_score])).rows;
    const existing=(await cx.query("SELECT c.product_id,c.scheduled_at FROM campaigns c WHERE c.status IN ('simulated','scheduled','queued','published','publishing') ORDER BY c.scheduled_at DESC")).rows;
    let count=0;
    const now=new Date();
    let day=new Date(now);
    const allowed=(s.allowed_categories||'').split(',').map(x=>x.trim().toLowerCase()).filter(Boolean);
    for(const p of products){
      if(allowed.length && !allowed.includes(p.category.toLowerCase()))continue;
      if(!isAffiliateLink(p.affiliate_url,p.platform))continue;
      const last=existing.find(c=>c.product_id===p.id);
      if(last && new Date(last.scheduled_at).getTime()>now.getTime()-s.cooldown_days*86400000)continue;
      let slot=null;
      for(let offset=0;offset<14 && !slot;offset++){
        const dayRef=new Date(now.getTime()+offset*86400000), target=dateSP(dayRef);
        const used=existing.map(c=>new Date(c.scheduled_at)).filter(d=>dateSP(d)===target);
        if(used.length>=s.posts_per_day)continue;
        for(let hr=9;hr<=20;hr++){
          const t=new Date(target+'T'+String(hr).padStart(2,'0')+':00:00-03:00');
          if(t<now)continue;
          if(used.every(d=>Math.abs(t-d)>=s.min_hours*3600000)){slot=t;break;}
        }
      }
      if(!slot)break;
      const id=crypto.randomUUID();
      await cx.query("INSERT INTO campaigns(id,product_id,channel,status,copy,scheduled_at,attempt_count,created_at,updated_at) VALUES($1,$2,'telegram','simulated',$3,$4,0,$5,$5)",[id,p.id,campaignCopy(p),slot.toISOString(),NOW()]);
      existing.push({product_id:p.id,scheduled_at:slot.toISOString()});
      count++;
      if(count>=s.posts_per_day)break;
    }
    await cx.query('UPDATE settings SET last_run_at=$1 WHERE id=1',[NOW()]);
    await log(cx,'cycle_completed',count+' campanhas criadas (simulação)');
    await cx.query('COMMIT');
    return {created:count,message:count+' campanhas criadas em simulação'};
  }catch(e){await cx.query('ROLLBACK');throw e;}finally{cx.release();}
}
async function router(req,res) {
  const u=new URL(req.url,'https://localhost');
  const route=u.pathname;
  if(route==='/health'){
    try{await pool.query('SELECT 1');return json(res,200,{ok:true,database:'connected'});}
    catch{return json(res,503,{ok:false,database:'unavailable'});}
  }
  if(req.method==='GET' && ['/','/app.js','/styles.css'].includes(route)){
    const file=route==='/'?'index.html':route.slice(1);
    const type=file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':'text/html';
    res.writeHead(200,{'Content-Type':type+'; charset=utf-8','Cache-Control':'no-store'});
    return fs.createReadStream(path.join(__dirname,'public',file)).pipe(res);
  }
  if(route==='/api/login'&&req.method==='POST'){
    if(!originOk(req))return error(res,403,'Origem não autorizada');
    const ip=req.socket.remoteAddress||'unknown',record=attempts.get(ip)||{count:0,until:0};
    if(Date.now()>record.until){record.count=0;record.until=Date.now()+900000;}
    if(record.count>=8)return error(res,429,'Muitas tentativas. Tente novamente mais tarde.');
    const b=await body(req);
    const ok=safeEqual(hmac(String(b.password||'')),hmac(PASSWORD))&&safeEqual(hmac(String(b.username||'')),hmac(USER));
    if(!ok){record.count++;attempts.set(ip,record);return error(res,401,'Usuário ou senha inválidos');}
    attempts.delete(ip);
    const payload='admin.'+(Date.now()+8*3600000)+'.'+crypto.randomBytes(16).toString('hex');
    const token=payload+'.'+hmac(payload);
    res.setHeader('Set-Cookie','promos_session='+token+'; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800');
    return json(res,200,{ok:true});
  }
  const session=auth(req);
  if(!session)return error(res,401,'Entre com sua conta para continuar');
  if(route==='/api/session'&&req.method==='GET')return json(res,200,{username:USER,csrf:session.csrf});
  if(!['GET','HEAD'].includes(req.method)&&!csrf(req,session))return error(res,403,'Sessão ou CSRF inválido');
  if(route==='/api/logout'&&req.method==='POST'){
    res.setHeader('Set-Cookie','promos_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0');
    return json(res,200,{ok:true});
  }
  if(route==='/api/state'&&req.method==='GET')return json(res,200,await state());
  if(route==='/api/ml/import-link'&&req.method==='POST'){
    const ip=req.socket.remoteAddress||'unknown',key='ml:'+ip;
    const rate=lookupAttempts.get(key)||{count:0,until:Date.now()+600000};
    if(Date.now()>rate.until){rate.count=0;rate.until=Date.now()+600000;}
    if(rate.count>=18)return error(res,429,'Limite de consultas atingido. Tente novamente mais tarde');
    rate.count++;lookupAttempts.set(key,rate);
    const b=await body(req);
    return json(res,200,{ok:true,...await importMercadoLivreLink(b.link)});
  }
  if(route==='/api/products/bulk'&&req.method==='POST'){
    const b=await body(req);
    if(!Array.isArray(b.items)||b.items.length===0||b.items.length>30)return error(res,422,'Envie de 1 a 30 produtos por lote');
    const report={created:0,duplicates:0,errors:[]};
    for(let i=0;i<b.items.length;i++){
      const item=b.items[i];
      if(!item||typeof item!=='object'||Array.isArray(item)){report.errors.push({line:i+1,error:'Formato de produto inválido'});continue;}
      try{await createProduct(item);report.created++;}
      catch(e){
        if(e.code==='23505'){report.duplicates++;continue;}
        report.errors.push({line:i+1,error:e.status===422?e.message:'Não foi possível importar esta linha'});
      }
    }
    return json(res,200,{ok:true,...report});
  }
  if(route==='/api/products'&&req.method==='POST'){
    try{return json(res,201,{ok:true,...await createProduct(await body(req))});}
    catch(e){if(e.code==='23505')return error(res,409,'Produto duplicado');throw e;}
  }
  if(route.startsWith('/api/products/')&&req.method==='DELETE'){
    const id=route.slice('/api/products/'.length);
    const c=await pool.query('SELECT COUNT(*)::int AS n FROM campaigns WHERE product_id=$1',[id]);
    if(c.rows[0].n)return error(res,409,'Produto possui campanhas e não pode ser excluído');
    const r=await pool.query('DELETE FROM products WHERE id=$1',[id]);
    return r.rowCount?json(res,200,{ok:true}):error(res,404,'Produto não encontrado');
  }
  if(route==='/api/cycle'&&req.method==='POST')return json(res,200,await runCycle());
  if(route==='/api/settings'&&req.method==='PATCH'){
    const b=await body(req);
    const score=num(b.min_score,0,100),posts=num(b.posts_per_day,1,6),hours=num(b.min_hours,1,24),cool=num(b.cooldown_days,1,60);
    if(b.live_mode===true)return error(res,409,'Publicação real bloqueada até configurar APIs oficiais e executor');
    const paused=b.paused===true?1:0;
    await pool.query('UPDATE settings SET min_score=COALESCE($1,min_score),posts_per_day=COALESCE($2,posts_per_day),min_hours=COALESCE($3,min_hours),cooldown_days=COALESCE($4,cooldown_days),paused=$5,live_mode=0 WHERE id=1',[score,posts,hours,cool,paused]);
    return json(res,200,{ok:true});
  }
  if(route==='/api/export.csv'&&req.method==='GET'){
    const rows=(await pool.query('SELECT c.created_at,p.name,c.channel,c.status,c.scheduled_at,c.copy FROM campaigns c JOIN products p ON p.id=c.product_id ORDER BY c.created_at DESC LIMIT 5000')).rows;
    const quote=v=>'"'+String(v??'').replaceAll('"','""').replace(/^[=+\-@]/,"'"+'$&')+'"';
    const lines=[['Criado','Produto','Canal','Status','Agendado','Texto'].map(quote).join(';')];
    for(const r of rows)lines.push([r.created_at,r.name,r.channel,r.status,r.scheduled_at,r.copy].map(quote).join(';'));
    res.writeHead(200,{'Content-Type':'text/csv; charset=utf-8','Content-Disposition':'attachment; filename="campanhas-promos-do-ro.csv"','Cache-Control':'no-store'});
    return res.end('\uFEFF'+lines.join('\r\n'));
  }
  return error(res,404,'Rota não encontrada');
}
const server=http.createServer(async(req,res)=>{
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('Referrer-Policy','no-referrer');
  res.setHeader('X-Frame-Options','DENY');
  res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' https: data:; connect-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'");
  try{await router(req,res);}catch(e){console.error('Error request:',e.message);if(!res.headersSent)error(res,e.status||500,e.status?e.message:'Falha interna, tente novamente');else res.end();}
});
init().then(()=>server.listen(Number(process.env.PORT||10000),'0.0.0.0',()=>console.log('Promos do Rô IA online em execução'))).catch(e=>{console.error('Falha inicializando base:',e.message);process.exit(1);});
