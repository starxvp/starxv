# STARXV — frontend + backend

Projekt używa dokładnie przekazanego `now.html` jako `public/index.html`, z podłączonym backendem kont.

## Uruchomienie lokalnie
1. Zainstaluj Node.js 20+.
2. Otwórz terminal w tym folderze.
3. `npm install`
4. `npm start`
5. Otwórz `http://localhost:3000`

Nie otwieraj `public/index.html` przez `file://`, bo API backendu wtedy nie będzie działać.

## Rejestracja
- formularz wysyła dane do backendu,
- backend generuje 6-cyfrowy kod ważny 10 minut,
- konto jest tworzone dopiero po poprawnym kodzie,
- hasło jest hashowane przez `scrypt`,
- po weryfikacji użytkownik dostaje sesję HttpOnly.

## E-mail
Bez SMTP kod jest wypisywany w terminalu serwera (tryb developerski). Do prawdziwych maili skopiuj `.env.example` do `.env`, uzupełnij dane SMTP i uruchamiaj serwer z tymi zmiennymi środowiskowymi. Sam Cloudflare Email Routing nie jest serwerem SMTP do wysyłania kodów.

## Ważne przed publikacją
GitHub Pages może nadal hostować statyczny frontend, ale ten backend musi działać na hostingu Node.js. Najprościej docelowo hostować frontend i backend razem, tak jak w tym projekcie, dzięki czemu `/api/...` działa pod tą samą domeną.

`data/store.json` tworzy się automatycznie i nie powinien być commitowany do publicznego repozytorium.
