const fs=require('fs');
const p='public/index.html';
if(!fs.existsSync(p)) throw new Error('Brakuje public/index.html');
let s=fs.readFileSync(p,'utf8');
const before=s;

// Exact current STARXV checkout block.
const start=s.indexOf('<section class="checkout-stage" data-stage="4"><h2>Płatność.</h2>');
const legal=s.indexOf('<div class="sx-checkout-legal">',start);
if(start<0||legal<0) throw new Error('Nie znaleziono aktualnego etapu płatności. Nic nie zapisano.');

const simpay=`<section class="checkout-stage" data-stage="4"><h2>Płatność.</h2><p>Płatność zostanie bezpiecznie obsłużona przez SimPay. Po złożeniu zamówienia przejdziesz do zabezpieczonej bramki płatniczej.</p><div class="payment-grid" id="paymentGrid"><div class="pay-card selected" data-method="simpay"><div><b>SimPay</b><span>Dostępne metody płatności wybierzesz w bezpiecznej bramce SimPay</span></div><span class="pay-badge">PŁATNOŚĆ ONLINE</span></div></div><div class="stripe-note"><strong>Bezpieczna płatność:</strong> po kliknięciu przycisku STARXV utworzy transakcję i przekieruje Cię do zabezpieczonego panelu SimPay. STARXV nie zapisuje danych Twojej karty ani danych logowania do banku.</div><div class="secure-mark">🔒 SIMPAY • SZYFROWANE POŁĄCZENIE</div>
`;
s=s.slice(0,start)+simpay+s.slice(legal);

// JS/payment messages.
s=s.replace(/let paymentPreference\s*=\s*['"]auto['"]/g,"let paymentPreference='simpay'");
s=s.replace(/paymentPreference\s*=\s*['"]auto['"]/g,"paymentPreference='simpay'");
s=s.replaceAll('ŁĄCZENIE Z PRZELEWY24...','ŁĄCZENIE Z SIMPAY...');
s=s.replaceAll('Prawdziwa płatność Przelewy24 wymaga uruchomienia backendu i konfiguracji danych P24 na serwerze.','Prawdziwa płatność SimPay wymaga uruchomienia backendu i konfiguracji SimPay na serwerze.');
s=s.replaceAll('Wróciłeś z Przelewy24. Czekamy na bezpieczne potwierdzenie płatności z serwera…','Wróciłeś z SimPay. Czekamy na bezpieczne potwierdzenie płatności z serwera…');
s=s.replaceAll('Przelewy24 weryfikuje transakcję. Status zamówienia zaktualizuje się po potwierdzeniu płatności.','SimPay weryfikuje transakcję. Status zamówienia zaktualizuje się po potwierdzeniu płatności.');

// Catch remaining visible legacy names, including uppercase variants missed previously.
s=s.replace(/PRZELEWY24/g,'SIMPAY').replace(/Przelewy24/g,'SimPay');

// Reject any remaining legacy payment identifiers/content in the frontend.
const bad=/Przelewy24|PRZELEWY24|data-method="p24"|ŁĄCZENIE Z P24/i;
if(bad.test(s)) throw new Error('Nadal znaleziono pozostałość P24. Nic nie zapisano.');

if(s===before) throw new Error('Brak zmian.');
fs.writeFileSync(p,s,'utf8');
console.log('OK: checkout public/index.html korzysta z SimPay.');
console.log('OK: stare kafelki i teksty P24 usunięte.');
console.log('OK: brak odwołań Przelewy24/P24 w checkout frontend.');
