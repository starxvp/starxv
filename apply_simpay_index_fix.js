const fs = require('fs');

const path = 'public/index.html';
let s = fs.readFileSync(path, 'utf8');
const original = s;

const oldStage = `<section class="checkout-stage" data-stage="4"><h2>Płatność.</h2><p>Wybierz preferowaną metodę. Płatność zostanie bezpiecznie obsłużona przez Przelewy24.</p><div class="payment-grid" id="paymentGrid"><div class="pay-card selected" data-method="auto"><div><b>Wszystkie metody</b><span>BLIK, karta, portfele i szybkie przelewy</span></div><span class="pay-badge">POLECANE</span></div><div class="pay-card" data-method="blik"><div><b>BLIK</b><span>Kod z aplikacji banku</span></div><span class="pay-badge">PLN</span></div><div class="pay-card" data-method="card"><div><b>Karta</b><span>Visa / Mastercard</span></div><span class="pay-badge">3D SECURE</span></div><div class="pay-card" data-method="p24"><div><b>Szybki przelew</b><span>Bankowość online przez Przelewy24</span></div><span class="pay-badge">BANK</span></div><div class="pay-card" data-method="wallet"><div><b>Apple Pay / Google Pay</b><span>Jeśli portfel jest dostępny na urządzeniu</span></div><span class="pay-badge">WALLET</span></div></div><div class="stripe-note"><strong>Bezpieczna płatność:</strong> po kliknięciu przycisku STARXV utworzy transakcję i przekieruje Cię do zabezpieczonego panelu Przelewy24. STARXV nie zapisuje danych Twojej karty.</div><div class="secure-mark">🔒 PRZELEWY24 • SZYFROWANE POŁĄCZENIE</div>`;

const newStage = `<section class="checkout-stage" data-stage="4"><h2>Płatność.</h2><p>Płatność zostanie bezpiecznie obsłużona przez SimPay. Po złożeniu zamówienia przejdziesz do zabezpieczonej bramki płatniczej.</p><div class="payment-grid" id="paymentGrid"><div class="pay-card selected" data-method="simpay"><div><b>SimPay</b><span>Dostępne metody płatności wybierzesz w bezpiecznej bramce SimPay</span></div><span class="pay-badge">BEZPIECZNA PŁATNOŚĆ</span></div></div><div class="stripe-note"><strong>Bezpieczna płatność:</strong> po kliknięciu przycisku STARXV utworzy transakcję i przekieruje Cię do zabezpieczonego panelu SimPay. STARXV nie zapisuje danych Twojej karty ani danych logowania do banku.</div><div class="secure-mark">🔒 SIMPAY • SZYFROWANE POŁĄCZENIE</div>`;

if (!s.includes(oldStage)) throw new Error('Nie znaleziono aktualnego bloku P24 w etapie płatności. Przerwano bez zmian.');
s = s.replace(oldStage, newStage);

s = s.replace("let paymentPreference='auto'", "let paymentPreference='simpay'");
s = s.replace("let paymentPreference = 'auto'", "let paymentPreference = 'simpay'");
s = s.replace("btn.textContent='ŁĄCZENIE Z PRZELEWY24...'", "btn.textContent='ŁĄCZENIE Z SIMPAY...'");
s = s.replace(
  "location.protocol==='file:'?'Prawdziwa płatność Przelewy24 wymaga uruchomienia backendu i konfiguracji danych P24 na serwerze.':(err.message||'Spróbuj ponownie za chwilę.')",
  "location.protocol==='file:'?'Prawdziwa płatność SimPay wymaga uruchomienia backendu i konfiguracji SimPay na serwerze.':(err.message||'Spróbuj ponownie za chwilę.')"
);
s = s.replace(
  "showStatus('success','Sprawdzamy płatność','Wróciłeś z Przelewy24. Czekamy na bezpieczne potwierdzenie płatności z serwera…',9000);",
  "showStatus('success','Sprawdzamy płatność','Wróciłeś z SimPay. Czekamy na bezpieczne potwierdzenie płatności z serwera…',9000);"
);
s = s.replace(
  "showStatus('success','Płatność jest weryfikowana','Przelewy24 weryfikuje transakcję. Status zamówienia zaktualizuje się po potwierdzeniu płatności.',7000);",
  "showStatus('success','Płatność jest weryfikowana','SimPay weryfikuje transakcję. Status zamówienia zaktualizuje się po potwierdzeniu płatności.',7000);"
);

// Safety: no visible P24/Przelewy24 references should remain in index.html.
const leftovers = [...s.matchAll(/Przelewy24|PRZELEWY24|P24/g)].map(m => m[0]);
if (leftovers.length) {
  throw new Error('Po poprawce nadal znaleziono odwołania do P24 w index.html: ' + leftovers.join(', ') + '. Przerwano bez zapisu.');
}

if (s === original) throw new Error('Brak zmian.');
fs.writeFileSync(path, s, 'utf8');
console.log('OK: public/index.html przełączony z P24 na SimPay.');
console.log('OK: usunięto widoczne metody P24 i teksty Przelewy24.');
console.log('OK: loading i komunikaty powrotu używają SimPay.');
