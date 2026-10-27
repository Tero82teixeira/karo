'use strict';
let csrf='',current=null;
const $=id=>document.getElementById(id);
const currency=n=>n===null||n===undefined?'—':new Intl.NumberFormat('pt-BR',{style:'currency',currency:'BRL'}).format(Number(n));
const day=s=>s?new Date(s).toLocaleString('pt-BR',{timeZone:'America/Sao_Paulo',dateStyle:'short',timeStyle:'short'}):'—';
const el=(tag,text,cls)=>{const x=document.createElement(tag);if(text!==undefined&&text!==null)x.textContent=String(text);if(cls)x.className=cls;return x;};
const clear=node=>{node.replaceChildren();};
const flash=(msg,isError=false)=>{const x=$('flash');x.textContent=msg;x.style.color=isError?'#ffadb2':'#b4e0bb';};
async function api(url,method='GET',data){
  const opts={method,credentials:'same-origin',headers:{'Accept':'application/json'}};
  if(method!=='GET')opts.headers['X-CSRF-Token']=csrf;
  if(data!==undefined){opts.headers['Content-Type']='application/json';opts.body=JSON.stringify(data);}
  const res=await fetch(url,opts);
  if(res.status===401&&url!=='/api/login'){showLogin();throw new Error('Sua sessão expirou. Entre novamente.');}
  const j=await res.json().catch(()=>({error:'Resposta inválida do servidor'}));
  if(!res.ok)throw new Error(j.error||'Ocorreu um erro');
  return j;
}
function showLogin(){
  $('appScreen').classList.add('hidden');$('loginScreen').classList.remove('hidden');csrf='';current=null;
}
async function showApp(){
  const session=await api('/api/session');csrf=session.csrf;
  $('loginScreen').classList.add('hidden');$('appScreen').classList.remove('hidden');
  await refresh();
}
function tab(name){
  document.querySelectorAll('.section').forEach(x=>x.classList.toggle('active',x.id===name));
  document.querySelectorAll('.nav').forEach(x=>x.classList.toggle('active',x.dataset.tab===name));
  const labels={dashboard:'Central de operações',products:'Catálogo de produtos',new:'Cadastrar produto',campaigns:'Fila de campanhas',marketplaces:'Shopee e Mercado Livre',rules:'Regras e limites',integrations:'Canais de divulgação'};
  $('pageTitle').textContent=labels[name]||'Promos do Rô IA';flash('');
}
function renderProducts(rows){
  const filter=$('platformFilter').value;
  rows=rows.filter(p=>filter==='all'||p.platform===filter);
  const target=$('productsRows');clear(target);
  if(!rows.length){const tr=el('tr');const td=el('td','Nenhum produto cadastrado ainda. Cadastre seu primeiro produto.','empty');td.colSpan=6;tr.append(td);target.append(tr);return;}
  for(const p of rows){
    const tr=el('tr');
    const td1=el('td');td1.append(el('div',p.name,'name'),el('div',p.platform==='shopee'?'Shopee • '+p.category:'Mercado Livre • '+p.category,'muted'));
    const td2=el('td',currency(p.price));
    const td3=el('td',p.commission_rate===null?'—':p.commission_rate+'%');
    const td4=el('td');td4.append(el('span',p.score+'/100','score '+(p.score>=80?'ok':'low')));
    const td5=el('td');td5.append(el('div',p.eligible?'Dados suficientes':'Não elegível','status'),el('div',p.reason||'—','muted'));
    const td6=el('td');const button=el('button','Excluir','btn btn-danger');button.addEventListener('click',async()=>{
      if(!window.confirm('Excluir este produto?'))return;
      try{await api('/api/products/'+encodeURIComponent(p.id),'DELETE');flash('Produto excluído.');await refresh();}catch(e){flash(e.message,true);}
    });td6.append(button);tr.append(td1,td2,td3,td4,td5,td6);target.append(tr);
  }
}
function renderCampaigns(rows){
  const target=$('campaignRows');clear(target);
  if(!rows.length){const tr=el('tr');const td=el('td','Ainda não existem campanhas. Execute uma simulação após cadastrar produtos elegíveis.','empty');td.colSpan=6;tr.append(td);target.append(tr);return;}
  for(const c of rows){
    const tr=el('tr');const copy=el('button','Copiar texto','btn');copy.addEventListener('click',async()=>{
      try{await navigator.clipboard.writeText(c.copy);flash('Texto copiado!');}catch{flash('Não foi possível copiar automaticamente.',true);}
    });
    const td=el('td');td.append(copy);tr.append(el('td',c.product_name),el('td',c.product_platform==='shopee'?'Shopee':'Mercado Livre'),el('td','Telegram (simulação)'),el('td',day(c.scheduled_at)),el('td',c.status),td);target.append(tr);
  }
}
function renderAudit(rows){
  const target=$('recentAudit');clear(target);
  if(!rows.length){target.className='empty';target.textContent='Ainda não há atividades registradas.';return;}
  target.className='';
  for(const a of rows.slice(0,6)){
    const line=el('div');line.style.padding='12px 0';line.style.borderBottom='1px solid #333b49';
    line.append(el('strong',a.event),el('div',a.message,'muted'),el('small',day(a.created_at),'muted'));
    target.append(line);
  }
}
function render(data){
  current=data;
  $('countProducts').textContent=data.stats.products??0;
  $('countEligible').textContent=data.stats.eligible??0;
  $('countSimulated').textContent=data.stats.simulated??0;
  $('countPublished').textContent=data.stats.published??0;
  $('shopeeCount').textContent=(data.products||[]).filter(p=>p.platform==='shopee').length;
  $('mercadoCount').textContent=(data.products||[]).filter(p=>p.platform==='mercado_livre').length;
  renderProducts(data.products||[]);
  renderCampaigns(data.campaigns||[]);
  renderAudit(data.audit||[]);
  const s=data.settings;
  for(const key of ['min_score','posts_per_day','min_hours','cooldown_days'])$('rulesForm').elements[key].value=s[key];
  $('rulesForm').elements.paused.checked=Boolean(s.paused);
}
async function refresh(){try{render(await api('/api/state'));}catch(e){flash(e.message,true);}}
async function cycle(){
  try{const x=await api('/api/cycle','POST',{});await refresh();flash(x.message);tab('campaigns');flash(x.message);}
  catch(e){flash(e.message,true);}
}
window.addEventListener('DOMContentLoaded',()=>{
  document.querySelectorAll('.nav').forEach(b=>b.addEventListener('click',()=>tab(b.dataset.tab)));
  document.querySelectorAll('[data-jump]').forEach(b=>b.addEventListener('click',()=>tab(b.dataset.jump)));
  $('refresh').addEventListener('click',refresh);
  $('platformFilter').addEventListener('change',()=>current&&renderProducts(current.products||[]));
  $('cycleButton').addEventListener('click',cycle);
  $('cycleFromHome').addEventListener('click',cycle);
  $('exportCsv').addEventListener('click',()=>{window.location.href='/api/export.csv';});
  $('logout').addEventListener('click',async()=>{try{await api('/api/logout','POST',{});}catch(e){}showLogin();});
  $('loginForm').addEventListener('submit',async e=>{
    e.preventDefault();const f=e.currentTarget;
    try{await api('/api/login','POST',{username:f.elements.username.value,password:f.elements.password.value});f.elements.password.value='';$('loginError').textContent='';await showApp();}
    catch(err){$('loginError').textContent=err.message;}
  });
  document.querySelectorAll('.quickImportForm').forEach(form=>form.addEventListener('submit',async e=>{
    e.preventDefault();
    const btn=form.querySelector('button[type="submit"]'),result=form.parentElement.querySelector('.quickImportResult');
    const link=form.elements.link.value.trim();
    btn.disabled=true;btn.textContent='Identificando…';result.textContent='Consultando o link com segurança…';
    try{
      const data=await api('/api/ml/import-link','POST',{link});
      const p=data.product||{};
      result.textContent=(data.created?'Link importado. ':'Link já cadastrado. ')+(data.message||'')+(p.name?' • '+p.name:'');
      result.style.color=data.identified?'#92dfbc':'#f4d2a2';
      await refresh();
      tab('products');
      flash(result.textContent,!data.identified);
    }catch(err){result.textContent=err.message;result.style.color='#ffadb2';}
    finally{btn.disabled=false;btn.textContent='Importar link';}
  }));
  $('productForm').addEventListener('submit',async e=>{
    e.preventDefault();const f=e.currentTarget,b=Object.fromEntries(new FormData(f).entries());
    for(const k of ['price','rating','sales','commission_rate','discount'])b[k]=b[k]===''?null:Number(b[k]);
    try{const r=await api('/api/products','POST',b);await refresh();tab('products');flash('Produto cadastrado! Nota: '+r.score+'/100. '+r.reason);f.reset();}
    catch(err){flash(err.message,true);}
  });
  $('bulkSubmit').addEventListener('click',async()=>{
    const button=$('bulkSubmit'),raw=$('bulkLines').value.trim();
    if(!raw){flash('Cole ao menos uma linha de produto.',true);return;}
    const rows=raw.split(/\r?\n/).map(x=>x.trim()).filter(Boolean).filter(x=>!/^nome\s*[;|]/i.test(x));
    if(rows.length>30){flash('Limite de 30 produtos por lote.',true);return;}
    const decimal=x=>{const v=(x||'').trim().replace(',','.');return v?Number(v):null;};
    const items=rows.map(row=>{
      const c=row.split(';').map(x=>x.trim());
      return {platform:$('bulkPlatform').value,name:c[0]||'',affiliate_url:c[1]||'',price:decimal(c[2]),rating:decimal(c[3]),sales:decimal(c[4]),commission_rate:decimal(c[5]),discount:decimal(c[6]),category:c[7]||'Diversos'};
    });
    try{
      button.disabled=true;button.textContent='Importando…';
      const result=await api('/api/products/bulk','POST',{items});
      await refresh();tab('products');
      const problems=(result.errors||[]).slice(0,3).map(x=>'Linha '+x.line+': '+x.error).join(' • ');
      flash(result.created+' produtos importados; '+result.duplicates+' duplicados. '+(result.errors||[]).length+' erros. '+problems,(result.errors||[]).length>0);
      if(result.created>0)$('bulkLines').value='';
    }catch(err){flash(err.message,true);}
    finally{button.disabled=false;button.textContent='Importar e avaliar lote';}
  });
  $('rulesForm').addEventListener('submit',async e=>{
    e.preventDefault();const f=e.currentTarget;
    const o={min_score:Number(f.elements.min_score.value),posts_per_day:Number(f.elements.posts_per_day.value),min_hours:Number(f.elements.min_hours.value),cooldown_days:Number(f.elements.cooldown_days.value),paused:f.elements.paused.checked};
    try{await api('/api/settings','PATCH',o);await refresh();flash('Regras atualizadas. Modo simulação continua ativo.');}
    catch(err){flash(err.message,true);}
  });
  showApp().catch(()=>showLogin());
});
