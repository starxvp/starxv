const fs=require('fs');

for(const p of ['server.js','public/index.html','.env.example']){
  if(!fs.existsSync(p)) throw new Error('Brakuje '+p+'. Uruchom w głównym folderze STARXV.');
}
let server=fs.readFileSync('server.js','utf8');
let html=fs.readFileSync('public/index.html','utf8');
let env=fs.readFileSync('.env.example','utf8');

server=server.replace('// Przelewy24 uses JSON requests, so the normal JSON parser can handle both checkout and callbacks.','// Payment and webhook APIs use JSON.');
server=server.replace("if(req.path==='/inpost/webhook'||req.path==='/p24/status'||req.path==='/simpay/ipn')return next();","if(req.path==='/inpost/webhook'||req.path==='/simpay/ipn')return next();");

// Remove old P24 helper block only if it is still present.
const p24Start=server.indexOf('function p24Config(){');
const p24End=server.indexOf('async function sendPaidOrderEmail',p24Start);
if(p24Start>=0&&p24End>p24Start) server=server.slice(0,p24Start)+server.slice(p24End);

// Remove old P24 callback route only if it is still present.
const routeStart=server.indexOf("app.post('/api/p24/status'");
if(routeStart>=0){
  const routeEnd=server.indexOf("\n\napp.get('/api/orders/:id/payment-status'",routeStart);
  if(routeEnd<0) throw new Error('Nie udało się bezpiecznie znaleźć końca endpointu P24.');
  server=server.slice(0,routeStart)+server.slice(routeEnd);
}

// Frontend: replace the whole payment stage with one SimPay hosted-gateway option.
const stageRe=/<section class="checkout-stage" data-stage="4">[\s\S]*?<\/section>/;
const m=html.match(stageRe);
if(!m) throw new Error('Nie znaleziono etapu płatności w public/index.html.');
const newStage=`<section class="checkout-stage" data-stage="4"><h2>Płatność.</h2><p>Płatność zostanie bezpiecznie obsłużona przez SimPay. Po kliknięciu przycisku przejdziesz do bramki płatniczej, gdzie wybierzesz dostępną metodę płatności.</p><div class="payment-grid" id="paymentGrid"><div class="pay-card selected" data-method="simpay"><div><b>Płatność online</b><span>Bezpieczna bramka płatnicza SimPay</span></div><span class="pay-badge">SIMPAY</span></div></div><div class="sx-checkout-legal"><label><input id="sxCheckoutLegal" type="checkbox"/><span>Akceptuję <a href="/terms.html" target="_blank" rel="noopener">Regulamin</a> i zapoznałem/am się z <a href="/privacy.html" target="_blank" rel="noopener">Polityką prywatności</a>.</span></label><div class="sx-checkout-legal-note">Kliknięcie przycisku poniżej oznacza złożenie zamówienia z obowiązkiem zapłaty.</div></div><div class="checkout-actions"><button class="btn secondary" id="backToDelivery">← WSTECZ</button><button class="btn primary" id="payNow" disabled>ZAMÓWIENIE Z OBOWIĄZKIEM ZAPŁATY</button></div></section>`;
html=html.replace(stageRe,newStage);

// Keep the existing checkout logic, but change the selected preference and visible P24-only wording.
html=html.replace(/paymentPreference\s*=\s*['"][^'"]*['"]/g,"paymentPreference='simpay'");
html=html.replace(/ŁĄCZENIE Z PRZELEWY24\.\.\./g,'ŁĄCZENIE Z SIMPAY...');
html=html.replace(/Prawdziwa płatność Przelewy24 wymaga uruchomienia backendu i konfiguracji danych P24 na serwerze\./g,'Płatność SimPay wymaga uruchomionego backendu i konfiguracji SimPay na serwerze.');
html=html.replace(/Przelewy24/g,'SimPay');
html=html.replace(/PRZELEWY24/g,'SIMPAY');

// Remove P24 env example and keep only SimPay.
env=env.replace(/\n# Przelewy24[\s\S]*?P24_SANDBOX=true\s*/m,'\n');
if(!env.includes('SIMPAY_API_TOKEN=')){
  env += '\n# SimPay — Płatności online. Token i klucz IPN przechowuj wyłącznie po stronie serwera.\nSIMPAY_SERVICE_ID=fa2a4d63\nSIMPAY_API_TOKEN=\nSIMPAY_IPN_KEY=\n';
}

// Sanity checks: old integration must be gone from these files.
const leftovers=[
  ['server.js',server,/p24Config|p24Configured|p24Request|\/api\/p24\/status|P24_/i],
  ['public/index.html',html,/Przelewy24|PRZELEWY24/i],
  ['.env.example',env,/P24_MERCHANT_ID|P24_POS_ID|P24_API_KEY|P24_CRC|P24_SANDBOX/i]
];
for(const [name,text,re] of leftovers) if(re.test(text)) throw new Error('Pozostałość P24 w '+name+'. Nic nie zapisano.');

fs.writeFileSync('server.js',server,'utf8');
fs.writeFileSync('public/index.html',html,'utf8');
fs.writeFileSync('.env.example',env,'utf8');
console.log('OK: Przelewy24 usunięte. Checkout STARXV korzysta z SimPay.');
