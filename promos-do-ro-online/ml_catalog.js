'use strict';
// Consulta oficial do catálogo, sem scraping, sessões ou cookies de terceiros.
async function officialMlCatalog(catalogId,getToken){
  if(!/^MLB\d{7,15}$/.test(catalogId||''))return {data:null,status:'catalog_id_unknown'};
  const token=await getToken().catch(()=>null);
  if(!token)return {data:null,status:'not_configured'};
  try{
    const response=await fetch('https://api.mercadolibre.com/products/'+encodeURIComponent(catalogId),{
      method:'GET',redirect:'error',signal:AbortSignal.timeout(6500),
      headers:{Authorization:'Bearer '+token,Accept:'application/json'}
    });
    if(!response.ok)return {data:null,status:'catalog_http_'+response.status};
    const data=await response.json();
    if(data.id!==catalogId||typeof data.name!=='string')return {data:null,status:'invalid_catalog_response'};
    return {data:{
      id:data.id,title:data.name,price:null,original_price:null,
      pictures:Array.isArray(data.pictures)?data.pictures:[],
      thumbnail:data.pictures?.[0]?.url||null,
      source_kind:'catalog',catalog_price:data.buy_box_winner?.price??null,
      catalog_winner_id:data.buy_box_winner?.item_id||null,
      currency_id:data.buy_box_winner?.currency_id||'BRL',sold_quantity:null
    },status:'confirmed_catalog_api'};
  }catch(e){return {data:null,status:e.name==='TimeoutError'?'catalog_timeout':'catalog_unavailable'};}
}
async function lookupMlOfficial(ref,getToken,getItem){
  if(ref.item_id){
    const item=await getItem(ref.item_id);
    if(item.data||!ref.catalog_id)return item;
    const catalog=await officialMlCatalog(ref.catalog_id,getToken);
    return catalog.data?catalog:{data:null,status:item.status+'; '+catalog.status};
  }
  if(ref.catalog_id)return officialMlCatalog(ref.catalog_id,getToken);
  return {data:null,status:'item_id_unknown'};
}
module.exports={lookupMlOfficial};
