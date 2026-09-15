const fs=require('fs');

const serverPath='server.js';
if(!fs.existsSync(serverPath)) throw new Error('Uruchom ten plik w głównym folderze STARXV (tam gdzie server.js).');
let s=fs.readFileSync(serverPath,'utf8');

function replaceOnce(oldText,newText,label){
  if(!s.includes(oldText)) throw new Error('Nie znaleziono fragmentu: '+label+' — projekt może mieć nowszą wersję.');
  s=s.replace(oldText,newText);
}

replaceOnce(
"if(req.path==='/inpost/webhook'||req.path==='/p24/status')return next();",
"if(req.path==='/inpost/webhook'||req.path==='/p24/status'||req.path==='/simpay/ipn')return next();",
'wyjątek CSRF dla SimPay IPN'
);

const oldStart = "app.get('/api/payments/config',(req,res)=>{const c=p24Config();res.json({ok:true,provider:'przelewy24',configured:p24Configured(),sandbox:c.sandbox,currency:'PLN',methods:['blik','card','apple_pay','google_pay','bank_transfer']})});";
const newStart = `function simpayConfig(){
  return {
    serviceId:String(process.env.SIMPAY_SERVICE_ID||'fa2a4d63').trim(),
    apiToken:String(process.env.SIMPAY_API_TOKEN||'').trim(),
    ipnKey:String(process.env.SIMPAY_IPN_KEY||'').trim(),
    apiBase:'https://api.simpay.pl'
  };
}
function simpayConfigured(){const c=simpayConfig();return /^[0-9a-f]{8}$/i.test(c.serviceId)&&Boolean(c.apiToken&&c.ipnKey)}
async function simpayRequest(pathName,options={}){
  const c=simpayConfig();
  const response=await fetch(c.apiBase+pathName,{...options,headers:{'Authorization':'Bearer '+c.apiToken,'Accept':'application/json','Content-Type':'application/json',...(options.headers||{})}});
  const data=await response.json().catch(()=>({}));
  if(!response.ok||data?.success===false){
    const msg=data?.message||data?.error||data?.errors||('SimPay HTTP '+response.status);
    const e=new Error(typeof msg==='string'?msg:JSON.stringify(msg));e.status=response.status;throw e;
  }
  return data;
}
function simpayFlattenValues(value,out=[]){
  if(value===null||value===undefined){out.push('');return out}
  if(Array.isArray(value)){for(const x of value)simpayFlattenValues(x,out);return out}
  if(typeof value==='object'){for(const k of Object.keys(value))simpayFlattenValues(value[k],out);return out}
  out.push(String(value));return out;
}
function simpayValidSignature(payload,key){
  if(!payload||typeof payload!=='object'||!key||typeof payload.signature!=='string')return false;
  const copy={};
  for(const k of Object.keys(payload))if(k!=='signature')copy[k]=payload[k];
  const values=simpayFlattenValues(copy,[]);
  values.push(key);
  const expected=crypto.createHash('sha256').update(values.join('|')).digest('hex');
  const got=String(payload.signature||'').toLowerCase();
  if(!/^[0-9a-f]{64}$/.test(got))return false;
  return crypto.timingSafeEqual(Buffer.from(expected,'hex'),Buffer.from(got,'hex'));
}
function simpayAmountMatches(order,data){
  const amount=data?.amount||{};
  const value=Number(amount.final_value??amount.value??amount.original_value);
  const currency=String(amount.final_currency??amount.currency??amount.original_currency??'');
  return Number.isFinite(value)&&Math.abs(value-Number(order.total||0))<0.005&&currency==='PLN';
}

app.get('/api/payments/config',(req,res)=>res.json({ok:true,provider:'simpay',configured:simpayConfigured(),currency:'PLN',methods:['simpay']}));`;
replaceOnce(oldStart,newStart,'konfiguracja płatności');

const startMarker="app.post('/api/create-checkout-session',auth,async(req,res)=>{";
const endMarker="\n\napp.post('/api/p24/status',async(req,res)=>{";
const a=s.indexOf(startMarker), b=s.indexOf(endMarker,a);
if(a<0||b<0) throw new Error('Nie znaleziono starego checkoutu Przelewy24.');

const simpayCheckout = `app.post('/api/create-checkout-session',auth,async(req,res)=>{
  try{
    if(!simpayConfigured())return res.status(503).json({error:'SimPay nie jest jeszcze skonfigurowany na serwerze.'});
    ensureStore(req.db);
    const orderId=String(req.body?.orderId||'');
    const order=req.db.orders.find(o=>o.id===orderId&&o.userId===req.user.id);
    if(!order)return res.status(404).json({error:'Nie znaleziono zamówienia.'});
    if(order.paymentStatus==='paid')return res.status(409).json({error:'To zamówienie jest już opłacone.'});
    if(order.paymentStatus==='cancelled')return res.status(409).json({error:'To zamówienie zostało anulowane.'});
    const amount=Math.round(Number(order.total)*100)/100;
    if(!Number.isFinite(amount)||amount<=0)return res.status(400).json({error:'Nieprawidłowa kwota zamówienia.'});
    if(order.paymentStatus==='failed')order.paymentStatus='pending';
    reserveStockForOrder(req.db,order);
    const c=simpayConfig(),base=paymentBaseUrl(req);
    const payload={
      amount,
      currency:'PLN',
      control:order.id,
      description:('STARXV zamówienie '+order.orderNo).slice(0,128),
      returns:{
        success:base+'/?payment=return&order='+encodeURIComponent(order.id),
        failure:base+'/?payment=failed&order='+encodeURIComponent(order.id)
      }
    };
    let data;
    try{data=await simpayRequest('/payment/'+encodeURIComponent(c.serviceId)+'/transactions',{method:'POST',body:JSON.stringify(payload)})}
    catch(e){releaseStockReservation(req.db,order);save(req.db);throw e}
    const transactionId=String(data?.data?.transactionId||'');
    const redirectUrl=String(data?.data?.redirectUrl||'');
    if(!transactionId||!/^https:\\/\\//i.test(redirectUrl)){releaseStockReservation(req.db,order);save(req.db);throw new Error('SimPay nie zwrócił poprawnego linku płatności.')}
    order.simpayTransactionId=transactionId;
    order.simpayCreatedAt=Date.now();
    order.paymentProvider='simpay';
    order.updatedAt=Date.now();
    save(req.db);
    res.json({ok:true,url:redirectUrl,transactionId,orderId:order.id,provider:'simpay'});
  }catch(e){
    console.error('SimPay checkout error:',e);
    res.status(e.status&&e.status>=400&&e.status<600?e.status:400).json({error:e?.message||'Nie udało się uruchomić płatności.'});
  }
});

app.post('/api/simpay/ipn',async(req,res)=>{
  try{
    const c=simpayConfig();
    if(!c.ipnKey)return res.status(503).type('text/plain').send('NOT_CONFIGURED');
    const payload=req.body||{};
    if(!simpayValidSignature(payload,c.ipnKey))return res.status(403).type('text/plain').send('INVALID_SIGNATURE');
    if(String(payload.type||'')==='ipn:test')return res.status(200).type('text/plain').send('OK');
    if(String(payload.type||'')!=='transaction:status_changed')return res.status(200).type('text/plain').send('OK');
    const data=payload.data||{};
    if(String(data.service_id||'')!==c.serviceId)return res.status(403).type('text/plain').send('INVALID_SERVICE');
    const notificationId=String(payload.notification_id||'');
    const transactionId=String(data.id||'');
    const control=String(data.control||'');
    if(!notificationId||!transactionId||!control)return res.status(400).type('text/plain').send('INVALID_NOTIFICATION');

    const db=load();ensureStore(db);
    if(!Array.isArray(db.simpayNotifications))db.simpayNotifications=[];
    if(db.simpayNotifications.some(x=>x.id===notificationId))return res.status(200).type('text/plain').send('OK');

    const order=db.orders.find(o=>String(o.id)===control);
    if(!order)return res.status(404).type('text/plain').send('ORDER_NOT_FOUND');
    if(order.simpayTransactionId&&String(order.simpayTransactionId)!==transactionId)return res.status(409).type('text/plain').send('TRANSACTION_MISMATCH');
    if(!simpayAmountMatches(order,data))return res.status(409).type('text/plain').send('AMOUNT_MISMATCH');

    const status=String(data.status||'');
    const wasPaid=order.paymentStatus==='paid';
    if(status==='transaction_paid'){
      markOrderPaid(db,order);
      order.simpayPaidAt=Date.now();
    }else if(['transaction_failure','transaction_cancelled','transaction_expired'].includes(status)){
      if(order.paymentStatus!=='paid'){
        releaseStockReservation(db,order);
        order.paymentStatus='failed';
      }
    }
    order.simpayStatus=status;
    order.simpayLastNotificationId=notificationId;
    order.simpayUpdatedAt=Date.now();
    order.updatedAt=Date.now();
    db.simpayNotifications.push({id:notificationId,transactionId,orderId:order.id,status,at:Date.now()});
    if(db.simpayNotifications.length>5000)db.simpayNotifications=db.simpayNotifications.slice(-3000);
    save(db);
    if(status==='transaction_paid'&&!wasPaid)await sendPaidOrderEmail(db,order);
    return res.status(200).type('text/plain').send('OK');
  }catch(e){
    console.error('SimPay IPN error:',e);
    return res.status(500).type('text/plain').send('ERROR');
  }
});`;

s=s.slice(0,a)+simpayCheckout+s.slice(b);

fs.writeFileSync(serverPath,s,'utf8');

const envPath='.env.example';
if(fs.existsSync(envPath)){
  let e=fs.readFileSync(envPath,'utf8');
  if(!e.includes('SIMPAY_API_TOKEN=')){
    e += `\n# SimPay — Płatności online (sekrety tylko po stronie serwera)\nSIMPAY_SERVICE_ID=fa2a4d63\nSIMPAY_API_TOKEN=\nSIMPAY_IPN_KEY=\n`;
    fs.writeFileSync(envPath,e,'utf8');
  }
}

console.log('OK: SimPay został dodany do server.js. Teraz sprawdź git diff, zacommituj i wdroż na Render.');
