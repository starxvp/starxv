'use strict';

require('dotenv').config();
const { Resend } = require('resend');

const express=require('express');const fs=require('fs');const path=require('path');const crypto=require('crypto');const nodemailer=require('nodemailer');
const app=express(),PORT=Number(process.env.PORT||3000);
const LEGAL_VERSION='2026-10-01';
const DIGITAL_CONSENT_TEXT='Żądam rozpoczęcia dostarczania zakupionej treści cyfrowej przed upływem 14-dniowego terminu do odstąpienia od umowy i przyjmuję do wiadomości, że po rozpoczęciu dostarczania treści cyfrowej utracę prawo odstąpienia od umowy w zakresie przewidzianym prawem.';
const DATA_DIR=path.join(__dirname,'data');
const LEGACY_DATA=path.join(DATA_DIR,'store.json');
const SQLITE_FILE=path.join(DATA_DIR,'starxv.sqlite');
app.disable('x-powered-by');
if(process.env.NODE_ENV==='production')app.set('trust proxy',1);

// --- STARXV security hardening -------------------------------------------------
// Security headers chosen to work with the current single-file storefront (which
// still contains inline CSS/JS). A stricter CSP can be added after those assets
// are moved to separate files.
app.use((req,res,next)=>{
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('X-Frame-Options','DENY');
  res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=(self), payment=(self)');
  res.setHeader('Cross-Origin-Opener-Policy','same-origin-allow-popups');
  res.setHeader('Cross-Origin-Resource-Policy','same-origin');
  // The storefront still uses inline JS/CSS, so 'unsafe-inline' is temporarily
  // required. External origins are kept to the services STARXV actually uses.
  res.setHeader('Content-Security-Policy',[
    "default-src 'self'","base-uri 'self'","object-src 'none'","frame-ancestors 'none'","form-action 'self'",
    "script-src 'self' 'unsafe-inline' https://accounts.google.com",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com data:",
    "img-src 'self' data: blob: https:",
    "connect-src 'self' https://accounts.google.com",
    "frame-src 'self' https://accounts.google.com",
    "worker-src 'self' blob:"
  ].join('; '));
  if(process.env.NODE_ENV==='production')res.setHeader('Strict-Transport-Security','max-age=31536000; includeSubDomains');
  next();
});

const rateBuckets=new Map();
function clientKey(req){return String(req.ip||req.socket?.remoteAddress||'unknown')}
function rateLimit(name,max,windowMs){
  return (req,res,next)=>{
    const now=Date.now(),key=name+'|'+clientKey(req);
    let b=rateBuckets.get(key);
    if(!b||b.resetAt<=now)b={count:0,resetAt:now+windowMs};
    b.count++;rateBuckets.set(key,b);
    const remaining=Math.max(0,max-b.count);
    res.setHeader('X-RateLimit-Limit',String(max));
    res.setHeader('X-RateLimit-Remaining',String(remaining));
    if(b.count>max){
      const retry=Math.max(1,Math.ceil((b.resetAt-now)/1000));
      res.setHeader('Retry-After',String(retry));
      return res.status(429).json({error:'Za dużo prób. Spróbuj ponownie za chwilę.'});
    }
    next();
  };
}
setInterval(()=>{const now=Date.now();for(const [k,b] of rateBuckets)if(b.resetAt<=now)rateBuckets.delete(k)},10*60*1000).unref?.();

// --- STARXV persistence: PostgreSQL on Render + SQLite fallback ----------------------
// In production set DATABASE_URL to Render's Internal Database URL.
// PostgreSQL is the durable source of truth. Local development can still use SQLite.
fs.mkdirSync(DATA_DIR,{recursive:true});

let sqlite=null;
let pgPool=null;
let persistenceMode='sqlite';
let pgStateCache=null;
let pgSessions=new Map();
let pgWriteQueue=Promise.resolve();

function defaultState(){return {users:[],pending:[]}}

function queuePgWrite(work){
  pgWriteQueue=pgWriteQueue.then(work).catch(err=>{
    console.error('PostgreSQL write error:',err);
  });
  return pgWriteQueue;
}

function pgSessionRow(row){
  if(!row)return undefined;
  return {
    token:String(row.token),
    userId:String(row.user_id),
    expires:Number(row.expires_at)
  };
}

let sqliteGetState,sqlitePutState,sqliteGetSession,sqliteInsertSession,sqliteDeleteSession,
    sqliteDeleteUserSessions,sqliteDeleteOtherUserSessions,sqliteDeleteExpiredSessions;

function normalizedDatabaseUrl(){
  const raw=String(process.env.DATABASE_URL||'').trim();
  if(!raw)return raw;
  try{
    const url=new URL(raw);
    const sslmode=String(url.searchParams.get('sslmode')||'').toLowerCase();
    // pg/pg-connection-string currently treats prefer, require and verify-ca
    // as aliases of verify-full. Make that existing behaviour explicit so
    // future pg versions do not change it and no deprecation warning is emitted.
    if(['prefer','require','verify-ca'].includes(sslmode)){
      url.searchParams.set('sslmode','verify-full');
    }
    return url.toString();
  }catch{
    return raw;
  }
}

async function initPostgres(){
  const {Pool}=require('pg');
  pgPool=new Pool({
    connectionString:normalizedDatabaseUrl(),
    max:5,
    idleTimeoutMillis:30000,
    connectionTimeoutMillis:10000
  });

  await pgPool.query('SELECT 1');
  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS app_state (
      id SMALLINT PRIMARY KEY CHECK(id=1),
      json JSONB NOT NULL,
      updated_at BIGINT NOT NULL
    )
  `);
  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      expires_at BIGINT NOT NULL,
      created_at BIGINT NOT NULL
    )
  `);
  await pgPool.query('CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)');
  await pgPool.query('CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)');

  const existing=await pgPool.query('SELECT json FROM app_state WHERE id=1');
  if(existing.rowCount){
    const raw=existing.rows[0].json;
    pgStateCache=typeof raw==='string'?JSON.parse(raw):raw;
  }else{
    let initial=defaultState();
    try{
      if(fs.existsSync(LEGACY_DATA))initial=JSON.parse(fs.readFileSync(LEGACY_DATA,'utf8'));
    }catch(e){console.warn('Nie udało się odczytać starego store.json:',e.message)}
    pgStateCache=initial;
    await pgPool.query(
      `INSERT INTO app_state(id,json,updated_at) VALUES(1,$1::jsonb,$2)
       ON CONFLICT(id) DO UPDATE SET json=EXCLUDED.json, updated_at=EXCLUDED.updated_at`,
      [JSON.stringify(initial),Date.now()]
    );
  }

  const now=Date.now();
  await pgPool.query('DELETE FROM sessions WHERE expires_at<$1',[now]);
  const sessions=await pgPool.query('SELECT token,user_id,expires_at FROM sessions WHERE expires_at>=$1',[now]);
  pgSessions.clear();
  for(const row of sessions.rows)pgSessions.set(String(row.token),pgSessionRow(row));

  sqliteGetState={
    get:()=>({json:JSON.stringify(pgStateCache||defaultState())})
  };
  sqlitePutState={
    run:(json,updatedAt)=>{
      pgStateCache=JSON.parse(String(json));
      return queuePgWrite(()=>pgPool.query(
        `INSERT INTO app_state(id,json,updated_at) VALUES(1,$1::jsonb,$2)
         ON CONFLICT(id) DO UPDATE SET json=EXCLUDED.json, updated_at=EXCLUDED.updated_at`,
        [String(json),Number(updatedAt||Date.now())]
      ));
    }
  };
  sqliteGetSession={
    get:(token)=>pgSessions.get(String(token))
  };
  sqliteInsertSession={
    run:(token,userId,expires,createdAt)=>{
      const key=String(token);
      pgSessions.set(key,{token:key,userId:String(userId),expires:Number(expires)});
      return queuePgWrite(()=>pgPool.query(
        `INSERT INTO sessions(token,user_id,expires_at,created_at)
         VALUES($1,$2,$3,$4)
         ON CONFLICT(token) DO UPDATE SET user_id=EXCLUDED.user_id, expires_at=EXCLUDED.expires_at, created_at=EXCLUDED.created_at`,
        [key,String(userId),Number(expires),Number(createdAt)]
      ));
    }
  };
  sqliteDeleteSession={
    run:(token)=>{
      const key=String(token);pgSessions.delete(key);
      return queuePgWrite(()=>pgPool.query('DELETE FROM sessions WHERE token=$1',[key]));
    }
  };
  sqliteDeleteUserSessions={
    run:(userId)=>{
      const id=String(userId);
      for(const [k,s] of pgSessions)if(s.userId===id)pgSessions.delete(k);
      return queuePgWrite(()=>pgPool.query('DELETE FROM sessions WHERE user_id=$1',[id]));
    }
  };
  sqliteDeleteOtherUserSessions={
    run:(userId,keepToken)=>{
      const id=String(userId),keep=String(keepToken);
      for(const [k,s] of pgSessions)if(s.userId===id&&k!==keep)pgSessions.delete(k);
      return queuePgWrite(()=>pgPool.query('DELETE FROM sessions WHERE user_id=$1 AND token<>$2',[id,keep]));
    }
  };
  sqliteDeleteExpiredSessions={
    run:(cutoff)=>{
      const n=Number(cutoff);
      for(const [k,s] of pgSessions)if(Number(s.expires)<n)pgSessions.delete(k);
      return queuePgWrite(()=>pgPool.query('DELETE FROM sessions WHERE expires_at<$1',[n]));
    }
  };

  persistenceMode='postgres';
  console.log('STARXV: PostgreSQL connected — persistent database enabled.');
}

function initSqlite(){
  try{
    const {DatabaseSync}=require('node:sqlite');
    sqlite=new DatabaseSync(SQLITE_FILE);
  }catch(err){
    throw new Error('STARXV wymaga Node.js 22 lub nowszego (node:sqlite). '+err.message);
  }
  sqlite.exec(`
    PRAGMA journal_mode=WAL;
    PRAGMA foreign_keys=ON;
    CREATE TABLE IF NOT EXISTS app_state (
      id INTEGER PRIMARY KEY CHECK(id=1),
      json TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
  `);
  sqliteGetState=sqlite.prepare('SELECT json FROM app_state WHERE id=1');
  sqlitePutState=sqlite.prepare(`INSERT INTO app_state(id,json,updated_at) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET json=excluded.json, updated_at=excluded.updated_at`);
  sqliteGetSession=sqlite.prepare('SELECT token,user_id AS userId,expires_at AS expires FROM sessions WHERE token=?');
  sqliteInsertSession=sqlite.prepare('INSERT OR REPLACE INTO sessions(token,user_id,expires_at,created_at) VALUES(?,?,?,?)');
  sqliteDeleteSession=sqlite.prepare('DELETE FROM sessions WHERE token=?');
  sqliteDeleteUserSessions=sqlite.prepare('DELETE FROM sessions WHERE user_id=?');
  sqliteDeleteOtherUserSessions=sqlite.prepare('DELETE FROM sessions WHERE user_id=? AND token<>?');
  sqliteDeleteExpiredSessions=sqlite.prepare('DELETE FROM sessions WHERE expires_at<?');

  if(!sqliteGetState.get()){
    let initial=defaultState();
    try{
      if(fs.existsSync(LEGACY_DATA))initial=JSON.parse(fs.readFileSync(LEGACY_DATA,'utf8'));
    }catch(e){console.warn('Nie udało się odczytać starego store.json:',e.message)}
    sqlitePutState.run(JSON.stringify(initial),Date.now());
    if(fs.existsSync(LEGACY_DATA))console.log('STARXV: zaimportowano data/store.json do SQLite.');
  }
  persistenceMode='sqlite';
  console.log('STARXV: DATABASE_URL not set — using local SQLite.');
}

async function initPersistence(){
  if(String(process.env.DATABASE_URL||'').trim()){
    try{
      await initPostgres();
      return;
    }catch(err){
      console.error('STARXV PostgreSQL startup error:',err);
      throw new Error('Nie udało się połączyć z PostgreSQL. Sprawdź DATABASE_URL. '+err.message);
    }
  }
  initSqlite();
}

function load(){
  try{
    const row=sqliteGetState.get();
    return row?JSON.parse(row.json):defaultState();
  }catch(e){
    console.error(`${persistenceMode} load error:`,e);
    return defaultState();
  }
}
function save(db){return sqlitePutState.run(JSON.stringify(db),Date.now())}
function cleanupExpiredSessions(){
  try{return sqliteDeleteExpiredSessions.run(Date.now())}
  catch(e){console.error('Session cleanup error:',e)}
}
setInterval(cleanupExpiredSessions,60*60*1000).unref?.();
setInterval(()=>{try{const db=load();expirePendingOrders(db)}catch(e){console.error('Order expiry cleanup error:',e)}},60*1000).unref?.();

async function closePersistence(){
  try{
    if(persistenceMode==='postgres'){
      await pgWriteQueue;
      await pgPool?.end();
    }else{
      sqlite?.close?.();
    }
  }catch(e){console.error('Persistence shutdown error:',e)}
}

for(const sig of ['SIGTERM','SIGINT']){
  process.once(sig,async()=>{
    await closePersistence();
    process.exit(0);
  });
}

// JSON API parser for checkout, account actions and server-to-server callbacks.
app.use(express.json({limit:'5mb'}));

// Browser CSRF protection: unsafe API calls must come from this site. Requests
// without Origin are blocked in production except authenticated server-to-server callbacks.
app.use('/api',(req,res,next)=>{
  if(!['POST','PUT','PATCH','DELETE'].includes(req.method))return next();
  const origin=String(req.headers.origin||'').trim();
  // Browser state-changing requests must carry a same-site Origin.
  if(!origin){
    if(req.path==='/simpay/ipn')return next();
    if(process.env.NODE_ENV==='production')return res.status(403).json({error:'Brak nagłówka Origin.'});
    return next();
  }
  try{
    const originUrl=new URL(origin);
    const host=String(req.headers.host||'');
    const publicUrl=String(process.env.PUBLIC_URL||'').trim();
    const allowed=new Set();
    if(host)allowed.add(host.toLowerCase());
    if(publicUrl){try{allowed.add(new URL(publicUrl).host.toLowerCase())}catch{}}
    if(!allowed.has(originUrl.host.toLowerCase()))return res.status(403).json({error:'Żądanie zostało zablokowane ze względów bezpieczeństwa.'});
  }catch{return res.status(403).json({error:'Nieprawidłowe źródło żądania.'})}
  next();
});

app.use('/api/auth',(req,res,next)=>{res.setHeader('Cache-Control','no-store');next()});
app.use('/api/account',(req,res,next)=>{res.setHeader('Cache-Control','no-store');next()});
app.use('/api/admin',(req,res,next)=>{res.setHeader('Cache-Control','no-store');next()});
app.use('/api/auth/login',rateLimit('login',10,15*60*1000));
app.use('/api/auth/register',rateLimit('register',6,15*60*1000));
app.use('/api/auth/verify',rateLimit('verify',15,15*60*1000));
app.use('/api/auth/forgot-password',rateLimit('forgot',6,15*60*1000));
app.use('/api/auth/reset-password',rateLimit('reset',10,15*60*1000));
app.use('/api/account/change-password',rateLimit('change-password',10,15*60*1000));
app.use('/api/account/change-email',rateLimit('change-email',10,15*60*1000));
app.use('/api/account/profile',rateLimit('profile-edit',30,15*60*1000));
app.use('/api/create-checkout-session',rateLimit('checkout',25,10*60*1000));
function cleanEmail(v){return String(v||'').trim().toLowerCase()}
function validBirthDate(v){
  const s=String(v||'').trim();
  if(!/^\d{4}-\d{2}-\d{2}$/.test(s))return false;
  const d=new Date(s+'T00:00:00Z');
  if(Number.isNaN(d.getTime())||d.toISOString().slice(0,10)!==s)return false;
  const now=new Date(),today=Date.UTC(now.getUTCFullYear(),now.getUTCMonth(),now.getUTCDate());
  if(d.getTime()>today)return false;
  const ageDate=new Date(today-d.getTime());
  const age=Math.abs(ageDate.getUTCFullYear()-1970);
  return age>=13&&age<=120;
}
const ACCOUNT_TITLE_PRESETS={
  owner:{label:'OWNER',name:'Właściciel'},
  admin:{label:'ADMIN',name:'Administrator'},
  support:{label:'SUPPORT',name:'Support'},
  team:{label:'TEAM',name:'Zespół'},
  creator:{label:'CREATOR',name:'Twórca'},
  moderator:{label:'MODERATOR',name:'Moderator'},
  custom:{label:'',name:'Własny tytuł'}
};
function cleanAccountTitleLabel(v){
  return String(v||'').trim().replace(/\s+/g,' ').slice(0,32);
}
function accountTitleData(u){
  const raw=u?.displayTitle;
  if(!raw||typeof raw!=='object')return null;
  const key=Object.prototype.hasOwnProperty.call(ACCOUNT_TITLE_PRESETS,String(raw.key||''))?String(raw.key):'custom';
  const label=cleanAccountTitleLabel(raw.label||ACCOUNT_TITLE_PRESETS[key]?.label||'');
  return label?{key,label}:null;
}
function publicUser(u){
  return {
    id:u.id,
    firstName:u.firstName||'',
    lastName:u.lastName||'',
    email:u.email,
    createdAt:u.createdAt,
    avatarData:u.avatarData||'',
    birthDate:u.birthDate||'',
    title:accountTitleData(u),
    authMethod:primaryAuthMethod(u),
    profileSetupRequired:Boolean(u.profileSetupRequired)
  };
}
function hashPassword(password,salt=crypto.randomBytes(16).toString('hex')){const hash=crypto.scryptSync(password,salt,64).toString('hex');return `${salt}:${hash}`}
function checkPassword(password,stored){try{const [salt,hex]=stored.split(':');const a=Buffer.from(hex,'hex'),b=crypto.scryptSync(password,salt,64);return a.length===b.length&&crypto.timingSafeEqual(a,b)}catch{return false}}
function codeHash(email,code){return crypto.createHash('sha256').update(email+'|'+code).digest('hex')}
function cookie(req,name){const m=String(req.headers.cookie||'').split(';').map(x=>x.trim().split('='));const p=m.find(x=>x[0]===name);return p?decodeURIComponent(p.slice(1).join('=')):''}
function sessionKey(token){return crypto.createHash('sha256').update(String(token||'')).digest('hex')}
function deleteSessionToken(token){if(!token)return;sqliteDeleteSession.run(sessionKey(token));sqliteDeleteSession.run(token)}
function setNamedSession(res,userId,cookieName){
  const token=crypto.randomBytes(32).toString('hex'),now=Date.now(),expires=now+1000*60*60*24*14;
  sqliteInsertSession.run(sessionKey(token),userId,expires,now);
  res.setHeader('Cache-Control','no-store');
  res.setHeader('Set-Cookie',`${cookieName}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=1209600${process.env.NODE_ENV==='production'?'; Secure':''}`);
}
function setSession(res,userId){return setNamedSession(res,userId,'starxv_session')}
function setAdminSession(res,userId){return setNamedSession(res,userId,'starxv_admin_session')}
function authWithCookie(req,res,next,cookieName){
  const t=cookie(req,cookieName);
  if(!t)return res.status(401).json({error:'Musisz się zalogować.'});
  const key=sessionKey(t);
  let s=sqliteGetSession.get(key);
  if(!s){
    const legacy=sqliteGetSession.get(t);
    if(legacy){sqliteDeleteSession.run(t);sqliteInsertSession.run(key,legacy.userId,legacy.expires,Date.now());s=sqliteGetSession.get(key)}
  }
  if(!s||s.expires<Date.now()){deleteSessionToken(t);return res.status(401).json({error:'Musisz się zalogować.'})}
  const db=load(),u=db.users.find(x=>x.id===s.userId);
  if(!u){deleteSessionToken(t);return res.status(401).json({error:'Sesja wygasła.'})}
  res.setHeader('Cache-Control','no-store');
  req.user=u;req.db=db;req.sessionToken=t;req.sessionKey=key;
  next();
}
function auth(req,res,next){return authWithCookie(req,res,next,'starxv_session')}
function adminAuth(req,res,next){return authWithCookie(req,res,next,'starxv_admin_session')}
function validEmail(v){return v.length<=320&&/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)}
function validPassword(v){return v.length>=8&&v.length<=256}
function cleanName(v){return String(v||'').trim().replace(/\s+/g,' ').slice(0,80)}
function authMethods(user){
  const explicit=Array.isArray(user?.authProviders)?user.authProviders.map(x=>String(x).toLowerCase()).filter(Boolean):[];
  if(explicit.length)return Array.from(new Set(explicit));
  if(user?.googleSub)return ['google'];
  return ['email'];
}
function primaryAuthMethod(user){
  const methods=authMethods(user);
  if(methods.length===1)return methods[0];
  return methods.includes('email')?'email':methods[0]||'email';
}

function googleClientId(){return String(process.env.GOOGLE_CLIENT_ID||'').trim()}
async function googleTokenInfo(accessToken){
  const token=String(accessToken||'').trim();
  if(!token||token.length>4096)throw new Error('Brak tokenu Google.');
  const r=await fetch(`https://oauth2.googleapis.com/tokeninfo?access_token=${encodeURIComponent(token)}`,{
    headers:{'Accept':'application/json'}
  });
  const data=await r.json().catch(()=>({}));
  if(!r.ok)throw new Error('Nie udało się zweryfikować logowania Google.');
  return data;
}
async function googleUserInfo(accessToken){
  const r=await fetch('https://openidconnect.googleapis.com/v1/userinfo',{
    headers:{'Authorization':`Bearer ${accessToken}`,'Accept':'application/json'}
  });
  const data=await r.json().catch(()=>({}));
  if(!r.ok)throw new Error('Nie udało się pobrać danych konta Google.');
  return data;
}

async function sendCode(email, code) {
  const apiKey = process.env.RESEND_API_KEY;

  if (!apiKey) {
    console.log(`[STARXV DEV] Kod dla ${email}: ${code}`);
    return { dev: true };
  }

  const resend = new Resend(apiKey);

  const { data, error } = await resend.emails.send({
    from: process.env.MAIL_FROM || 'STARXV <no-reply@starxv.pl>',
    to: email,
    subject: 'STARXV — kod weryfikacyjny',
    text: `Twój kod weryfikacyjny STARXV: ${code}

Kod wygasa po 10 minutach.
Jeśli to nie Ty, zignoruj tę wiadomość.`,

    html: `
      <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:32px;">
        <h1 style="font-size:28px;margin:0 0 28px;">STARXV</h1>

        <p>Twój kod weryfikacyjny:</p>

        <div style="font-size:36px;font-weight:800;letter-spacing:8px;margin:24px 0;">
          ${code}
        </div>

        <p style="color:#666;">Kod wygasa po 10 minutach.</p>

        <p style="color:#888;font-size:12px;margin-top:30px;">
          Jeśli to nie Ty próbowałeś utworzyć konto STARXV,
          możesz zignorować tę wiadomość.
        </p>
      </div>
    `
  });

  if (error) {
    console.error('Resend error:', error);
    throw new Error('Nie udało się wysłać wiadomości.');
  }

  console.log(`Kod STARXV został wysłany na ${email}. ID: ${data?.id}`);
  return { dev: false };
}

async function sendPasswordResetCode(email, code) {
  const apiKey=process.env.RESEND_API_KEY;
  if(!apiKey){console.log(`[STARXV DEV] Kod resetu hasła dla ${email}: ${code}`);return {dev:true};}
  const resend=new Resend(apiKey);
  const {data,error}=await resend.emails.send({
    from:process.env.MAIL_FROM||'STARXV <no-reply@starxv.pl>',to:email,
    subject:'STARXV — reset hasła',
    text:`Kod do resetu hasła STARXV: ${code}\n\nKod wygasa po 10 minutach.\nJeśli to nie Ty, zignoruj tę wiadomość.`,
    html:`<div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:32px"><h1 style="font-size:28px;margin:0 0 28px">STARXV</h1><p>Otrzymaliśmy prośbę o zmianę hasła.</p><p>Twój kod:</p><div style="font-size:36px;font-weight:800;letter-spacing:8px;margin:24px 0">${code}</div><p style="color:#666">Kod wygasa po 10 minutach.</p><p style="color:#888;font-size:12px;margin-top:30px">Jeśli to nie Ty poprosiłeś o reset hasła, zignoruj tę wiadomość.</p></div>`
  });
  if(error){console.error('Resend reset error:',error);throw new Error('Nie udało się wysłać wiadomości.');}
  console.log(`Kod resetu STARXV wysłany na ${email}. ID: ${data?.id}`);return {dev:false};
}
function invalidateUserSessions(userId){sqliteDeleteUserSessions.run(userId)}

function invalidateOtherUserSessions(userId,keepToken){sqliteDeleteOtherUserSessions.run(userId,sessionKey(keepToken))}
async function sendEmailChangeCode(email,code){
  const apiKey=process.env.RESEND_API_KEY;
  if(!apiKey){console.log(`[STARXV DEV] Kod zmiany e-maila dla ${email}: ${code}`);return {dev:true};}
  const resend=new Resend(apiKey);
  const {data,error}=await resend.emails.send({
    from:process.env.MAIL_FROM||'STARXV <no-reply@starxv.pl>',to:email,
    subject:'STARXV — potwierdź nowy adres e-mail',
    text:`Kod do potwierdzenia nowego adresu e-mail STARXV: ${code}

Kod wygasa po 10 minutach.
Jeśli to nie Ty, zignoruj tę wiadomość.`,
    html:`<div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:32px"><h1 style="font-size:28px;margin:0 0 28px">STARXV</h1><p>Potwierdź nowy adres e-mail dla swojego konta.</p><p>Twój kod:</p><div style="font-size:36px;font-weight:800;letter-spacing:8px;margin:24px 0">${code}</div><p style="color:#666">Kod wygasa po 10 minutach.</p><p style="color:#888;font-size:12px;margin-top:30px">Jeśli to nie Ty zmieniasz adres e-mail, zignoruj tę wiadomość.</p></div>`
  });
  if(error){console.error('Resend email change error:',error);throw new Error('Nie udało się wysłać wiadomości.');}
  console.log(`Kod zmiany e-maila STARXV wysłany na ${email}. ID: ${data?.id}`);return {dev:false};
}

app.post('/api/auth/forgot-password',async(req,res)=>{try{
  const email=cleanEmail(req.body?.email),now=Date.now(),db=load();
  db.passwordResets=(db.passwordResets||[]).filter(x=>x.expiresAt>now);
  const generic={ok:true,message:'Jeśli konto z tym adresem istnieje, wysłaliśmy kod resetu hasła.',expiresIn:600};
  const user=db.users.find(u=>cleanEmail(u.email)===email);
  if(!user){save(db);return res.json(generic)}
  if(!authMethods(user).includes('email')){
    return res.status(409).json({
      error:'To konto zostało utworzone metodą Google. Zaloguj się przez Google — to konto nie ma hasła STARXV do zresetowania.',
      code:'AUTH_METHOD_GOOGLE'
    });
  }
  const previous=db.passwordResets.find(x=>x.email===email);
  if(previous&&now-Number(previous.createdAt||0)<60000){save(db);return res.json(generic)}
  db.passwordResets=db.passwordResets.filter(x=>x.email!==email);
  const code=String(crypto.randomInt(100000,1000000));
  db.passwordResets.push({email,userId:user.id,codeHash:codeHash(email,code),expiresAt:now+10*60*1000,attempts:0,createdAt:now});
  save(db);await sendPasswordResetCode(email,code);return res.json(generic);
}catch(e){console.error(e);return res.status(500).json({error:'Nie udało się rozpocząć resetu hasła. Spróbuj ponownie.'})}});
app.post('/api/auth/reset-password',(req,res)=>{
  const email=cleanEmail(req.body?.email),code=String(req.body?.code||'').replace(/\D/g,''),password=String(req.body?.password||'');
  if(code.length!==6||!validPassword(password))return res.status(400).json({error:'Wpisz poprawny kod i nowe hasło 8–256 znaków.'});
  const db=load(),now=Date.now();db.passwordResets=(db.passwordResets||[]).filter(x=>x.expiresAt>now);
  const reset=db.passwordResets.find(x=>x.email===email),user=db.users.find(u=>cleanEmail(u.email)===email);
  if(user&&!authMethods(user).includes('email'))return res.status(409).json({error:'To konto zostało utworzone metodą Google. Zaloguj się przez Google.',code:'AUTH_METHOD_GOOGLE'});
  if(!reset||!user||reset.userId!==user.id)return res.status(400).json({error:'Kod jest nieprawidłowy lub wygasł. Wyślij nowy kod.'});
  if(reset.attempts>=5){db.passwordResets=db.passwordResets.filter(x=>x.email!==email);save(db);return res.status(429).json({error:'Za dużo błędnych prób. Wyślij nowy kod.'})}
  if(reset.codeHash!==codeHash(email,code)){reset.attempts++;save(db);return res.status(400).json({error:'Nieprawidłowy kod.'})}
  user.passwordHash=hashPassword(password);db.passwordResets=db.passwordResets.filter(x=>x.email!==email);save(db);invalidateUserSessions(user.id);
  res.setHeader('Set-Cookie',`starxv_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${process.env.NODE_ENV==='production'?'; Secure':''}`);res.json({ok:true});
});
app.post('/api/auth/register',async(req,res)=>{try{
  const email=cleanEmail(req.body?.email),password=String(req.body?.password||'');
  if(!validEmail(email)||!validPassword(password))return res.status(400).json({error:'Wpisz poprawny e-mail i hasło 8–256 znaków.'});
  const db=load();
  const existingUser=db.users.find(u=>cleanEmail(u.email)===email);
  if(existingUser)return res.status(409).json({
    error:'Konto zostało już utworzone. Zaloguj się.',
    code:'ACCOUNT_EXISTS',
    loginMethod:primaryAuthMethod(existingUser)
  });
  const now=Date.now();
  db.pending=(db.pending||[]).filter(p=>p.expiresAt>now&&p.email!==email);
  const code=String(crypto.randomInt(100000,1000000));
  db.pending.push({email,passwordHash:hashPassword(password),codeHash:codeHash(email,code),expiresAt:now+10*60*1000,attempts:0,createdAt:now});
  save(db);
  const sent=await sendCode(email,code);
  res.json({ok:true,expiresIn:600,developmentCode:sent.dev?code:undefined});
}catch(e){console.error(e);res.status(500).json({error:'Nie udało się wysłać kodu. Spróbuj ponownie.'})}});
app.post('/api/auth/verify',(req,res)=>{
  const email=cleanEmail(req.body?.email),code=String(req.body?.code||'').replace(/\D/g,''),db=load(),now=Date.now(),p=db.pending.find(x=>x.email===email);
  if(!p||p.expiresAt<now)return res.status(400).json({error:'Kod wygasł. Wróć do rejestracji i wyślij nowy.'});
  if(p.attempts>=5)return res.status(429).json({error:'Za dużo błędnych prób. Wyślij nowy kod.'});
  if(p.codeHash!==codeHash(email,code)){p.attempts++;save(db);return res.status(400).json({error:'Nieprawidłowy kod.'})}
  if(db.users.some(u=>u.email===email))return res.status(409).json({error:'To konto już istnieje.'});
  const u={
    id:crypto.randomUUID(),firstName:'',lastName:'',birthDate:'',
    profileSetupRequired:true,email,passwordHash:p.passwordHash,createdAt:now,avatarData:'',
    authProviders:['email']
  };
  db.users.push(u);
  db.pending=db.pending.filter(x=>x.email!==email);
  save(db);
  setSession(res,u.id);
  res.json({ok:true,user:publicUser(u)});
});
app.post('/api/auth/login',(req,res)=>{
  const email=cleanEmail(req.body?.email),password=String(req.body?.password||'');
  if(!validEmail(email)||password.length>256)return res.status(401).json({error:'Nieprawidłowy e-mail lub hasło.',code:'INVALID_CREDENTIALS'});
  const db=load(),u=db.users.find(x=>cleanEmail(x.email)===email);
  if(!u)return res.status(401).json({error:'Nieprawidłowy e-mail lub hasło.',code:'INVALID_CREDENTIALS'});
  const methods=authMethods(u);
  if(!methods.includes('email')){
    return res.status(409).json({error:'To konto zostało utworzone metodą Google. Zaloguj się przez Google.',code:'AUTH_METHOD_GOOGLE'});
  }
  if(!checkPassword(password,u.passwordHash))return res.status(401).json({error:'Nieprawidłowy e-mail lub hasło.',code:'INVALID_CREDENTIALS'});
  setSession(res,u.id);
  res.json({ok:true,user:publicUser(u)});
});
app.post('/api/auth/logout',(req,res)=>{const t=cookie(req,'starxv_session');if(t)deleteSessionToken(t);res.setHeader('Set-Cookie',`starxv_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${process.env.NODE_ENV==='production'?'; Secure':''}`);res.json({ok:true})});
app.get('/api/auth/me',auth,(req,res)=>res.json({user:publicUser(req.user)}));

app.get('/api/auth/google-config',(req,res)=>{
  const clientId=googleClientId();
  res.setHeader('Cache-Control','no-store');
  res.json({enabled:!!clientId,clientId:clientId||null});
});

app.post('/api/auth/google',async(req,res)=>{
  try{
    const clientId=googleClientId();
    if(!clientId)return res.status(503).json({error:'Logowanie Google nie jest jeszcze skonfigurowane.'});

    const intent=String(req.body?.intent||'login').toLowerCase()==='register'?'register':'login';
    const accessToken=String(req.body?.accessToken||'').trim();
    const info=await googleTokenInfo(accessToken);
    const audience=String(info.audience||info.issued_to||info.aud||info.azp||'');
    if(audience!==clientId)return res.status(401).json({error:'Nieprawidłowy token Google.'});
    if(Number(info.expires_in||0)<=0)return res.status(401).json({error:'Sesja Google wygasła. Spróbuj ponownie.'});

    const profile=await googleUserInfo(accessToken);
    const email=cleanEmail(profile.email);
    const verified=profile.email_verified===true||String(profile.email_verified)==='true';
    if(!verified||!validEmail(email))return res.status(401).json({error:'Google nie potwierdził adresu e-mail.'});

    const db=load();
    let user=db.users.find(u=>cleanEmail(u.email)===email);

    if(user){
      const methods=authMethods(user);

      if(intent==='register'){
        return res.status(409).json({
          error:'Konto zostało już utworzone. Zaloguj się.',
          code:'ACCOUNT_EXISTS',
          loginMethod:primaryAuthMethod(user),
          email
        });
      }

      if(!methods.includes('google')){
        return res.status(409).json({
          error:'To konto zostało utworzone metodą e-mail. Zaloguj się adresem e-mail i hasłem.',
          code:'AUTH_METHOD_EMAIL',
          email
        });
      }

      const storedSub=String(user.googleSub||'');
      const incomingSub=String(profile.sub||'');
      if(storedSub&&incomingSub&&storedSub!==incomingSub){
        return res.status(401).json({error:'To konto Google nie pasuje do konta STARXV.'});
      }
      if(!storedSub)user.googleSub=incomingSub;
      user.authProviders=['google'];
      await Promise.resolve(save(db));
      setSession(res,user.id);
      return res.json({ok:true,user:publicUser(user)});
    }

    if(intent==='login'){
      return res.status(404).json({
        error:'Nie znaleziono konta STARXV dla tego konta Google. Utwórz konto.',
        code:'ACCOUNT_NOT_FOUND',
        email
      });
    }

    const firstName=cleanName(profile.given_name||String(profile.name||'').split(' ')[0]||'');
    const lastName=cleanName(profile.family_name||String(profile.name||'').split(' ').slice(1).join(' ')||'');
    user={
      id:crypto.randomUUID(),
      firstName:firstName||'',
      lastName:lastName||'',
      birthDate:'',
      profileSetupRequired:true,
      email,
      passwordHash:hashPassword(crypto.randomBytes(32).toString('hex')),
      createdAt:Date.now(),
      avatarData:'',
      favorites:[],
      addresses:[],
      defaultAddressId:'',
      cart:[],
      googleSub:String(profile.sub||''),
      authProviders:['google']
    };
    db.users.push(user);
    await Promise.resolve(save(db));
    setSession(res,user.id);
    res.json({ok:true,user:publicUser(user)});
  }catch(e){
    console.error('Google auth error:',e);
    res.status(401).json({error:e?.message||'Nie udało się zalogować przez Google.'});
  }
});



// --- STARXV account security: change password + verified e-mail change ---
app.post('/api/account/change-password',auth,(req,res)=>{
  const currentPassword=String(req.body?.currentPassword||''),newPassword=String(req.body?.newPassword||'');
  if(!currentPassword||currentPassword.length>256||!validPassword(newPassword))return res.status(400).json({error:'Wpisz obecne hasło i nowe hasło 8–256 znaków.'});
  if(!checkPassword(currentPassword,req.user.passwordHash))return res.status(401).json({error:'Obecne hasło jest nieprawidłowe.'});
  if(checkPassword(newPassword,req.user.passwordHash))return res.status(400).json({error:'Nowe hasło musi być inne niż obecne.'});
  req.user.passwordHash=hashPassword(newPassword);
  req.db.passwordResets=(req.db.passwordResets||[]).filter(x=>x.userId!==req.user.id&&cleanEmail(x.email)!==cleanEmail(req.user.email));
  save(req.db);
  invalidateOtherUserSessions(req.user.id,req.sessionToken);
  res.json({ok:true,message:'Hasło zostało zmienione.'});
});

app.post('/api/account/change-email/start',auth,async(req,res)=>{try{
  const newEmail=cleanEmail(req.body?.newEmail),currentPassword=String(req.body?.currentPassword||''),now=Date.now();
  if(!validEmail(newEmail))return res.status(400).json({error:'Wpisz poprawny nowy adres e-mail.'});
  if(!currentPassword||currentPassword.length>256||!checkPassword(currentPassword,req.user.passwordHash))return res.status(401).json({error:'Obecne hasło jest nieprawidłowe.'});
  if(newEmail===cleanEmail(req.user.email))return res.status(400).json({error:'To jest już adres e-mail tego konta.'});
  if(req.db.users.some(u=>u.id!==req.user.id&&cleanEmail(u.email)===newEmail))return res.status(409).json({error:'Konto z tym adresem e-mail już istnieje.'});
  req.db.emailChanges=(req.db.emailChanges||[]).filter(x=>x.expiresAt>now);
  const previous=req.db.emailChanges.find(x=>x.userId===req.user.id);
  if(previous&&now-Number(previous.createdAt||0)<60000)return res.status(429).json({error:'Poczekaj chwilę przed wysłaniem kolejnego kodu.'});
  req.db.emailChanges=req.db.emailChanges.filter(x=>x.userId!==req.user.id);
  const code=String(crypto.randomInt(100000,1000000));
  req.db.emailChanges.push({userId:req.user.id,oldEmail:cleanEmail(req.user.email),newEmail,codeHash:codeHash(newEmail,code),expiresAt:now+10*60*1000,attempts:0,createdAt:now});
  save(req.db);
  await sendEmailChangeCode(newEmail,code);
  res.json({ok:true,expiresIn:600,newEmail});
}catch(e){console.error(e);res.status(500).json({error:'Nie udało się wysłać kodu. Spróbuj ponownie.'})}});

app.post('/api/account/change-email/confirm',auth,(req,res)=>{
  const newEmail=cleanEmail(req.body?.newEmail),code=String(req.body?.code||'').replace(/\D/g,''),now=Date.now();
  if(code.length!==6||!validEmail(newEmail))return res.status(400).json({error:'Wpisz poprawny adres e-mail i 6-cyfrowy kod.'});
  req.db.emailChanges=(req.db.emailChanges||[]).filter(x=>x.expiresAt>now);
  const change=req.db.emailChanges.find(x=>x.userId===req.user.id);
  if(!change||change.newEmail!==newEmail||change.oldEmail!==cleanEmail(req.user.email))return res.status(400).json({error:'Kod jest nieprawidłowy lub wygasł. Wyślij nowy kod.'});
  if(change.attempts>=5){req.db.emailChanges=req.db.emailChanges.filter(x=>x.userId!==req.user.id);save(req.db);return res.status(429).json({error:'Za dużo błędnych prób. Wyślij nowy kod.'})}
  if(change.codeHash!==codeHash(newEmail,code)){change.attempts++;save(req.db);return res.status(400).json({error:'Nieprawidłowy kod.'})}
  if(req.db.users.some(u=>u.id!==req.user.id&&cleanEmail(u.email)===newEmail))return res.status(409).json({error:'Konto z tym adresem e-mail już istnieje.'});
  const oldEmail=cleanEmail(req.user.email);
  req.user.email=newEmail;
  req.db.emailChanges=req.db.emailChanges.filter(x=>x.userId!==req.user.id);
  req.db.pending=(req.db.pending||[]).filter(p=>cleanEmail(p.email)!==newEmail);
  req.db.passwordResets=(req.db.passwordResets||[]).filter(x=>x.userId!==req.user.id&&cleanEmail(x.email)!==oldEmail&&cleanEmail(x.email)!==newEmail);
  save(req.db);
  invalidateOtherUserSessions(req.user.id,req.sessionToken);
  res.json({ok:true,user:publicUser(req.user)});
});


// --- STARXV account profile: personal data + verified phone -------------------
app.post('/api/account/profile',auth,async(req,res)=>{
  try{
    const body=req.body||{};
    const hasFirst=Object.prototype.hasOwnProperty.call(body,'firstName');
    const hasLast=Object.prototype.hasOwnProperty.call(body,'lastName');
    const hasBirth=Object.prototype.hasOwnProperty.call(body,'birthDate');

    if(hasFirst){
      const value=cleanName(body.firstName);
      if(!value||value.length<2)return res.status(400).json({error:'Wpisz poprawne imię.'});
      req.user.firstName=value;
    }
    if(hasLast){
      const value=cleanName(body.lastName);
      if(!value||value.length<2)return res.status(400).json({error:'Wpisz poprawne nazwisko.'});
      req.user.lastName=value;
    }
    if(hasBirth){
      const value=String(body.birthDate||'').trim();
      if(!validBirthDate(value))return res.status(400).json({error:'Wpisz poprawną datę urodzenia. Konto STARXV wymaga ukończonych 13 lat.'});
      req.user.birthDate=value;
    }

    if(req.user.profileSetupRequired){
      if(!cleanName(req.user.firstName)||!cleanName(req.user.lastName)||!validBirthDate(req.user.birthDate)){
        return res.status(400).json({error:'Uzupełnij imię, nazwisko i datę urodzenia.'});
      }
      req.user.profileSetupRequired=false;
    }

    await Promise.resolve(save(req.db));
    res.json({ok:true,user:publicUser(req.user)});
  }catch(e){
    res.status(400).json({error:e.message||'Nie udało się zapisać danych.'});
  }
});

// Permanently delete the currently logged-in STARXV account.
// Existing paid/order records are kept as standalone store records, but the account itself
// (profile, saved addresses, favorites, avatar and password hash) is removed.
app.delete('/api/account',auth,rateLimit('delete-account',8,15*60*1000),async(req,res)=>{
  try{
    const methods=authMethods(req.user);
    const googleOnly=methods.includes('google')&&!methods.includes('email');

    if(googleOnly){
      const accessToken=String(req.body?.accessToken||'').trim();
      if(!accessToken)return res.status(400).json({error:'Potwierdź konto przez Google, aby usunąć konto.',code:'GOOGLE_CONFIRM_REQUIRED'});

      const clientId=googleClientId();
      if(!clientId)return res.status(503).json({error:'Logowanie Google nie jest skonfigurowane.'});

      const info=await googleTokenInfo(accessToken);
      const audience=String(info.audience||info.issued_to||info.aud||info.azp||'');
      if(audience!==clientId)return res.status(401).json({error:'Nieprawidłowe potwierdzenie Google.'});
      if(Number(info.expires_in||0)<=0)return res.status(401).json({error:'Potwierdzenie Google wygasło. Spróbuj ponownie.'});

      const profile=await googleUserInfo(accessToken);
      const verified=profile.email_verified===true||String(profile.email_verified)==='true';
      const incomingEmail=cleanEmail(profile.email);
      const incomingSub=String(profile.sub||'');
      const storedSub=String(req.user.googleSub||'');

      if(!verified||!validEmail(incomingEmail))return res.status(401).json({error:'Google nie potwierdził adresu e-mail.'});
      if(incomingEmail!==cleanEmail(req.user.email))return res.status(401).json({error:'Wybrane konto Google nie pasuje do konta STARXV.'});
      if(storedSub&&incomingSub&&storedSub!==incomingSub)return res.status(401).json({error:'Wybrane konto Google nie pasuje do konta STARXV.'});
    }else{
      const password=String(req.body?.password||'');
      if(!password)return res.status(400).json({error:'Wpisz hasło, aby usunąć konto.'});
      if(!checkPassword(password,req.user.passwordHash))return res.status(401).json({error:'Nieprawidłowe hasło.'});
    }

    const userId=req.user.id;
    const email=req.user.email;
    ensureStore(req.db);

    // Unpaid draft orders can be discarded; completed/paid records stay in the shop records.
    req.db.orders=(req.db.orders||[]).filter(o=>!(o.userId===userId && String(o.paymentStatus||'pending')!=='paid'));
    req.db.reviews=(req.db.reviews||[]).filter(r=>r.userId!==userId);
    req.db.users=(req.db.users||[]).filter(u=>u.id!==userId);
    req.db.pending=(req.db.pending||[]).filter(p=>cleanEmail(p.email)!==cleanEmail(email));
    save(req.db);

    invalidateUserSessions(userId);
    res.setHeader('Set-Cookie',`starxv_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${process.env.NODE_ENV==='production'?'; Secure':''}`);
    res.json({ok:true});
  }catch(e){
    console.error('Account delete confirmation error:',e);
    res.status(401).json({error:e?.message||'Nie udało się potwierdzić usunięcia konta.'});
  }
});

// Account preferences stored on the backend.
function accountPreferences(u){
  return {marketingEmails:u.marketingEmails===true};
}
app.get('/api/account/preferences',auth,(req,res)=>{
  res.json({ok:true,preferences:accountPreferences(req.user)});
});


app.post('/api/support/reports/:id/reply',auth,rateLimit('support-customer-reply',20,15*60*1000),(req,res)=>{
  const report=(Array.isArray(req.db.supportReports)?req.db.supportReports:[]).find(r=>r.id===req.params.id&&r.userId===req.user.id);
  if(!report)return res.status(404).json({error:'Nie znaleziono zgłoszenia.'});
  if((report.status||'new')==='resolved'||report.closedByCustomer)return res.status(409).json({error:'To zgłoszenie jest zamknięte. Otwórz je ponownie, aby odpowiedzieć.'});
  const text=String(req.body?.text||'').trim().slice(0,2000);
  if(text.length<2)return res.status(400).json({error:'Wpisz wiadomość.'});
  supportMessages(report).push({id:crypto.randomUUID(),author:'customer',text,createdAt:new Date().toISOString()});
  report.supportReadAt=null;
  report.updatedAt=new Date().toISOString();
  if((report.status||'new')==='resolved')report.status='progress';
  save(req.db);
  res.json({ok:true,report:supportForUser(report)});
});
app.post('/api/support/reports/:id/close',auth,(req,res)=>{
  const report=(Array.isArray(req.db.supportReports)?req.db.supportReports:[]).find(r=>r.id===req.params.id&&r.userId===req.user.id);
  if(!report)return res.status(404).json({error:'Nie znaleziono zgłoszenia.'});
  report.status='resolved';report.closedByCustomer=true;report.updatedAt=new Date().toISOString();save(req.db);
  res.json({ok:true,report:supportForUser(report)});
});
app.post('/api/support/reports/:id/reopen',auth,(req,res)=>{
  const report=(Array.isArray(req.db.supportReports)?req.db.supportReports:[]).find(r=>r.id===req.params.id&&r.userId===req.user.id);
  if(!report)return res.status(404).json({error:'Nie znaleziono zgłoszenia.'});
  report.status='progress';report.closedByCustomer=false;report.updatedAt=new Date().toISOString();save(req.db);
  res.json({ok:true,report:supportForUser(report)});
});

app.use('/api/support/report',rateLimit('support-report',8,15*60*1000));

app.post('/api/support/reports/read',auth,(req,res)=>{
  const now=new Date().toISOString();let changed=false;
  for(const r of (Array.isArray(req.db.supportReports)?req.db.supportReports:[])){
    if(r.userId!==req.user.id)continue;
    const lastSupport=[...supportMessages(r)].reverse().find(m=>m.author==='support');
    if(lastSupport&&(!r.customerReadAt||new Date(r.customerReadAt)<new Date(lastSupport.createdAt||0))){
      r.customerReadAt=now;changed=true;
    }
  }
  if(changed)save(req.db);
  res.json({ok:true});
});


function supportMessages(report){
  if(!Array.isArray(report.messages))report.messages=[];

  // Remove accidental exact duplicates that could have been created by the old
  // supportReply compatibility field. Keep genuinely separate messages intact.
  const seen=new Set();
  report.messages=report.messages.filter(m=>{
    const key=[String(m?.author||''),String(m?.text||''),String(m?.createdAt||'')].join('\u0000');
    if(seen.has(key))return false;
    seen.add(key);return true;
  });

  // Backward compatibility for tickets created before threaded support messages.
  if(report.supportReply && !report.messages.some(m=>m.legacySupportReply)){
    const legacyText=String(report.supportReply);
    const legacyAt=report.supportRepliedAt||report.updatedAt||report.createdAt||new Date().toISOString();
    const alreadyThere=report.messages.some(m=>m.author==='support'&&String(m.text||'')===legacyText&&String(m.createdAt||'')===String(legacyAt));
    if(!alreadyThere){
      report.messages.push({
        id:crypto.randomUUID(),
        author:'support',
        text:legacyText,
        createdAt:legacyAt,
        legacySupportReply:true
      });
    }
  }
  return report.messages;
}
function supportForUser(report){
  const messages=supportMessages(report).map(m=>({
    id:m.id,author:m.author==='support'?'support':'customer',
    title:m.author==='support'&&m.authorTitle?m.authorTitle:null,
    text:String(m.text||''),createdAt:m.createdAt||report.createdAt
  }));
  const lastSupport=[...messages].reverse().find(m=>m.author==='support');
  const unread=Boolean(lastSupport && (!report.customerReadAt || new Date(report.customerReadAt)<new Date(lastSupport.createdAt||0)));
  return {
    id:report.id,ticketNo:report.ticketNo||'',type:report.type,description:report.description,
    orderId:String(report.orderId||''),orderNo:String(report.orderNo||''),orderType:String(report.orderType||''),orderLabel:String(report.orderLabel||''),
    status:report.status||'new',messages,unread,
    createdAt:report.createdAt,updatedAt:report.updatedAt||null,closedByCustomer:Boolean(report.closedByCustomer)
  };
}

app.get('/api/support/reports',auth,(req,res)=>{
  const reports=(Array.isArray(req.db.supportReports)?req.db.supportReports:[])
    .filter(r=>r.userId===req.user.id)
    .map(r=>supportForUser(r))
    .sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt));
  res.json({ok:true,reports});
});

app.post('/api/support/report',auth,async(req,res)=>{
  const type=String(req.body?.type||'Inne').trim().slice(0,80);
  const description=String(req.body?.description||'').trim().slice(0,1500);
  const page=String(req.body?.page||'/').trim().slice(0,300);
  const orderId=String(req.body?.orderId||'').trim().slice(0,120);
  if(description.length<5)return res.status(400).json({error:'Opisz problem trochę dokładniej.'});
  const orderRequired=['Zamówienie','Płatność'].includes(type);
  let selectedOrder=null;
  if(orderId){
    ensureStore(req.db);
    selectedOrder=(req.db.orders||[]).find(o=>o.id===orderId&&o.userId===req.user.id)||null;
    if(!selectedOrder)return res.status(400).json({error:'Wybrane zamówienie nie istnieje lub nie należy do tego konta.'});
  }else if(orderRequired){
    return res.status(400).json({error:'Wybierz zamówienie, którego dotyczy zgłoszenie.'});
  }
  const selectedPublic=selectedOrder?orderForUser(selectedOrder,req.db):null;
  const selectedLabel=selectedPublic?(selectedPublic.items||[]).map(x=>x?.name).filter(Boolean).slice(0,2).join(' + '):'';

  if(!Array.isArray(req.db.supportReports))req.db.supportReports=[];
  const maxTicket=req.db.supportReports.reduce((m,r)=>{
    const n=Number(String(r.ticketNo||'').replace(/\D/g,''));
    return Number.isFinite(n)?Math.max(m,n):m;
  },1000);
  const report={
    id:crypto.randomUUID(),
    ticketNo:`SX-${maxTicket+1}`,
    userId:req.user.id,
    email:req.user.email,
    type,
    orderId:selectedPublic?.id||'',
    orderNo:selectedPublic?.orderNo||'',
    orderType:selectedPublic?.orderType||'',
    orderLabel:selectedLabel||'',
    description,
    page,
    createdAt:new Date().toISOString(),
    status:'new',
    messages:[{id:crypto.randomUUID(),author:'customer',text:description,createdAt:new Date().toISOString()}],
    customerReadAt:new Date().toISOString(),
    supportReadAt:null,
    closedByCustomer:false
  };
  req.db.supportReports.unshift(report);
  req.db.supportReports=req.db.supportReports.slice(0,1000);
  save(req.db);

  const key=String(process.env.RESEND_API_KEY||'').trim();
  if(key){
    try{
      const resend=new Resend(key);
      await resend.emails.send({
        from:process.env.SUPPORT_FROM||'STARXV Support <kontakt@starxv.pl>',
        to:'kontakt@starxv.pl',
        replyTo:req.user.email,
        subject:`STARXV — zgłoszenie problemu: ${type}${report.orderNo?' · #'+report.orderNo:''}`,
        text:`Nowe zgłoszenie STARXV\n\nTyp: ${type}\nKonto: ${req.user.email}${report.orderNo?`\nZamówienie: #${report.orderNo} · CYFROWE${report.orderLabel?' · '+report.orderLabel:''}`:''}\nStrona: ${page}\nData: ${report.createdAt}\n\nOpis:\n${description}`
      });
    }catch(err){console.error('Support report email error:',err?.message||err)}
  }
  res.json({ok:true,id:report.id,ticketNo:report.ticketNo});
});

app.put('/api/account/preferences',auth,(req,res)=>{
  const i=req.db.users.findIndex(x=>x.id===req.user.id);
  if(i<0)return res.status(401).json({error:'Sesja wygasła.'});
  const current=req.db.users[i];
  const body=req.body||{};
  if(Object.prototype.hasOwnProperty.call(body,'marketingEmails')) current.marketingEmails=body.marketingEmails===true;
  save(req.db);
  res.json({ok:true,preferences:accountPreferences(current)});
});


// --- STARXV Digital store --------------------------------------------------------
function ensureStore(db){
  // Remove obsolete physical-store state from the persistent account/store model.
  if(Object.prototype.hasOwnProperty.call(db,'catalog'))delete db.catalog;
  for(const u of (db.users||[])){
    delete u.favorites;
    delete u.addresses;
    delete u.defaultAddressId;
    delete u.cart;
  }

  if(!db.digitalProducts||typeof db.digitalProducts!=='object'){
    db.digitalProducts={
      'zero-to-first-sale':{id:'zero-to-first-sale',position:1,categoryId:'praktyczne',name:'ZERO TO FIRST SALE',subtitle:'Od pomysłu do pierwszej sprzedaży',description:'Praktyczny przewodnik od pomysłu do pierwszej sprzedaży.',meta:'STARXV DIGITAL / E-BOOK',points:['Produkt cyfrowy PDF','Dostęp po potwierdzeniu płatności','Przypisany do konta STARXV','Pobieranie z biblioteki zamówień'],price:Math.max(0,Number(process.env.ZERO_TO_FIRST_SALE_PRICE||39.99)),image:'/assets/placeholder.png',gallery:['/assets/placeholder.png'],fileName:'ZERO_TO_FIRST_SALE_FINAL_v1.0.pdf',downloadName:'ZERO_TO_FIRST_SALE_FINAL_v1.0.pdf',active:true}
    };
  }
  if(!Array.isArray(db.digitalCategories)||!db.digitalCategories.length){
    db.digitalCategories=[
      {id:'praktyczne',name:'E-BOOKI PRAKTYCZNE',description:'Poradniki, wiedza i materiały do wykorzystania w realnym życiu.',position:1,visible:true},
      {id:'fikcyjne-historie',name:'FIKCYJNE HISTORIE',description:'Fabularne e-booki i historie STARXV.',position:2,visible:true}
    ];
  }
  for(const p of Object.values(db.digitalProducts||{})){
    if(!String(p.categoryId||'').trim())p.categoryId='praktyczne';
  }
  // Replace obsolete ZERO TO FIRST SALE local artwork with the generic image-error placeholder.
  // This only touches the two legacy asset paths; real images configured later stay unchanged.
  const legacyDigitalImages=new Set(['/assets/zero-to-first-sale-3d.png','/assets/zero-to-first-sale-cover.png']);
  const zeroProduct=db.digitalProducts?.['zero-to-first-sale'];
  if(zeroProduct){
    if(!zeroProduct.image||legacyDigitalImages.has(String(zeroProduct.image)))zeroProduct.image='/assets/placeholder.png';
    if(Array.isArray(zeroProduct.gallery)){
      zeroProduct.gallery=[...new Set(zeroProduct.gallery.map(x=>legacyDigitalImages.has(String(x))?'/assets/placeholder.png':String(x||'').trim()).filter(Boolean))];
      if(!zeroProduct.gallery.length)zeroProduct.gallery=['/assets/placeholder.png'];
    }else{
      zeroProduct.gallery=['/assets/placeholder.png'];
    }
  }

  if(!db.siteSettings||typeof db.siteSettings!=='object')db.siteSettings={};
  if(!String(db.siteSettings.releaseVersion||'').trim())db.siteSettings.releaseVersion='PRE-LAUNCH 1.0v';
  if(!Array.isArray(db.siteSettings.comingLater))db.siteSettings.comingLater=[];
  if(!Array.isArray(db.faq)){
    const now=Date.now();
    db.faq=[
      {id:crypto.randomUUID(),question:'Gdzie znajdę kupionego eBooka?',answer:'Wejdź w Profil → Moje zamówienia → Produkty cyfrowe. Przy opłaconym zamówieniu znajdziesz przycisk pobrania zakupionego pliku.',position:1,visible:true,createdAt:now,updatedAt:now},
      {id:crypto.randomUUID(),question:'Kiedy otrzymam dostęp do produktu cyfrowego?',answer:'Dostęp pojawia się po potwierdzeniu płatności. Jeśli status nie zmieni się od razu, odśwież po chwili sekcję Moje zamówienia.',position:2,visible:true,createdAt:now,updatedAt:now},
      {id:crypto.randomUUID(),question:'Co zrobić, jeśli płatność się nie powiedzie?',answer:'Nie musisz tworzyć nowego zamówienia. W Profil → Moje zamówienia przy zamówieniu oczekującym na płatność użyj przycisku „ZAPŁAĆ →”, aby ponowić płatność.',position:3,visible:true,createdAt:now,updatedAt:now},
      {id:crypto.randomUUID(),question:'Jak użyć kodu rabatowego?',answer:'Kod rabatowy wpisz podczas finalizacji zakupu w polu przeznaczonym na kod promocyjny. Po zatwierdzeniu system pokaże naliczony rabat, jeśli kod jest aktywny i spełnia jego warunki.',position:4,visible:true,createdAt:now,updatedAt:now},
      {id:crypto.randomUUID(),question:'Jak zmienić dane konta?',answer:'W Profilu otwórz „Edytuj dane”. Możesz tam zmienić dane profilu oraz ustawienia logowania dostępne dla Twojej metody logowania.',position:5,visible:true,createdAt:now,updatedAt:now},
      {id:crypto.randomUUID(),question:'Jak zresetować hasło?',answer:'Na ekranie logowania wybierz „Nie pamiętasz hasła?”. Na adres e-mail konta otrzymasz kod, którym potwierdzisz ustawienie nowego hasła.',position:6,visible:true,createdAt:now,updatedAt:now},
      {id:crypto.randomUUID(),question:'Kiedy mogę wystawić opinię?',answer:'Opinię o produkcie cyfrowym możesz dodać po opłaceniu zamówienia i otrzymaniu dostępu do produktu.',position:7,visible:true,createdAt:now,updatedAt:now},
      {id:crypto.randomUUID(),question:'Jak zgłosić problem?',answer:'W Profilu wybierz „Zgłoś problem”, opisz sytuację i wyślij zgłoszenie. Odpowiedź supportu pojawi się w historii zgłoszenia.',position:8,visible:true,createdAt:now,updatedAt:now},
      {id:crypto.randomUUID(),question:'Jak usunąć konto STARXV?',answer:'W Profilu użyj przycisku „Usuń konto” i potwierdź operację. Usunięcie konta jest trwałe, dlatego przed potwierdzeniem upewnij się, że naprawdę chcesz je usunąć.',position:9,visible:true,createdAt:now,updatedAt:now}
    ];
  }

  if(!Array.isArray(db.orders))db.orders=[];
  if(!Array.isArray(db.reviews))db.reviews=[];
  if(!Array.isArray(db.marketingCampaigns))db.marketingCampaigns=[];
  return db;
}

function cleanReleaseVersion(v){
  return String(v||'').trim().replace(/\s+/g,' ').slice(0,60);
}

app.get('/api/site/settings',(req,res)=>{
  const db=load();
  const hadSettings=Boolean(db.siteSettings&&String(db.siteSettings.releaseVersion||'').trim());
  ensureStore(db);
  if(!hadSettings)save(db);
  res.setHeader('Cache-Control','no-store');
  res.json({ok:true,releaseVersion:db.siteSettings.releaseVersion,comingLater:Array.isArray(db.siteSettings.comingLater)?db.siteSettings.comingLater:[]});
});

const STARXV_PRICE_WINDOW_MS=30*24*60*60*1000;
function money2(v){return Math.round((Number(v)||0)*100)/100}
function effectiveCatalogPrice(p){
  const base=Math.max(0,Number(p?.price||0));
  const discount=Math.min(99,Math.max(0,Number(p?.discountPercent||0)));
  return money2(discount>0?base*(1-discount/100):base);
}
function ensureProductPriceTracking(p,now=Date.now()){
  if(!p||typeof p!=='object')return p;
  if(!Number.isFinite(Number(p.offeredAt))||Number(p.offeredAt)<=0)p.offeredAt=now;
  if(!Array.isArray(p.priceHistory))p.priceHistory=[];
  p.priceHistory=p.priceHistory.map(x=>({at:Number(x?.at||0),price:money2(x?.price)})).filter(x=>x.at>0&&Number.isFinite(x.price)&&x.price>=0).sort((a,b)=>a.at-b.at);
  if(!p.priceHistory.length)p.priceHistory.push({at:Number(p.offeredAt),price:effectiveCatalogPrice(p)});
  return p;
}
function recordProductPrice(p,price,at=Date.now()){
  ensureProductPriceTracking(p,at);
  const v=money2(price),last=p.priceHistory[p.priceHistory.length-1];
  if(last&&money2(last.price)===v){last.at=Math.max(Number(last.at||0),Number(at||Date.now()));return}
  p.priceHistory.push({at:Number(at||Date.now()),price:v});
  if(p.priceHistory.length>500)p.priceHistory=p.priceHistory.slice(-500);
}
function setOmnibusReferenceForPromotion(p,now=Date.now()){
  ensureProductPriceTracking(p,now);
  const offeredAt=Number(p.offeredAt||now);
  const from=Math.max(offeredAt,now-STARXV_PRICE_WINDOW_MS);
  const previous=p.priceHistory.filter(x=>Number(x.at)>=from&&Number(x.at)<now).map(x=>Number(x.price)).filter(Number.isFinite);
  p.promotionStartedAt=now;
  p.omnibusReferencePrice=previous.length?money2(Math.min(...previous)):null;
  p.omnibusReferenceType=(now-offeredAt)<STARXV_PRICE_WINDOW_MS?'since-offer':'30-days';
}
function clearOmnibusPromotion(p){p.promotionStartedAt=null;p.omnibusReferencePrice=null;p.omnibusReferenceType=null}
function orderEvent(order,key,title,note='',at=Date.now()){
  if(!Array.isArray(order.timeline))order.timeline=[];
  const last=order.timeline[order.timeline.length-1];
  if(last&&last.key===key&&String(last.note||'')===String(note||''))return;
  order.timeline.push({id:crypto.randomUUID(),key:String(key||''),title:String(title||''),note:String(note||''),at:Number(at||Date.now())});
  if(order.timeline.length>100)order.timeline=order.timeline.slice(-100);
}
function ensureOrderTimeline(order){
  if(!Array.isArray(order.timeline))order.timeline=[];
  if(!order.timeline.length){
    orderEvent(order,'created','Zamówienie utworzone','Oczekujemy na potwierdzenie płatności.',order.createdAt||Date.now());
    if(order.paymentStatus==='paid')orderEvent(order,'paid','Płatność potwierdzona','Zamówienie zostało opłacone.',order.updatedAt||order.createdAt||Date.now());
    if(order.paymentStatus==='cancelled')orderEvent(order,'cancelled','Zamówienie anulowane','Zamówienie nie będzie dalej realizowane.',order.cancelledAt||order.updatedAt||Date.now());
    if(order.paymentStatus==='failed')orderEvent(order,'payment_failed','Płatność nieudana','Płatność nie została potwierdzona.',order.updatedAt||Date.now());
    if(order.paymentStatus==='expired')orderEvent(order,'expired','Zamówienie wygasło','Płatność nie została potwierdzona w ciągu 24 godzin.',order.expiredAt||order.updatedAt||Date.now());
  }
  return order.timeline.slice().sort((a,b)=>Number(a.at||0)-Number(b.at||0));
}
const ORDER_PAYMENT_TTL_MS=24*60*60*1000;
function orderPaymentExpiresAt(order){return Number(order?.paymentExpiresAt||0)||Number(order?.createdAt||0)+ORDER_PAYMENT_TTL_MS}
function expirePendingOrders(db,userId=''){
  ensureStore(db);
  const now=Date.now(),uid=String(userId||'');let changed=false;
  for(const order of (db.orders||[])){
    if(uid&&String(order.userId)!==uid)continue;
    if(!['pending','failed'].includes(String(order.paymentStatus||'')))continue;
    const expiresAt=orderPaymentExpiresAt(order);
    if(!expiresAt||expiresAt>now)continue;
    order.paymentExpiresAt=expiresAt;
    order.paymentStatus='expired';
    order.expiredAt=now;
    order.updatedAt=now;
    orderEvent(order,'expired','Zamówienie wygasło','Płatność nie została potwierdzona w ciągu 24 godzin. Zamówienie zostało automatycznie wygaszone.',now);
    changed=true;
  }
  if(changed)save(db);
  return changed;
}
function orderForUser(o,db){
  let items=Array.isArray(o.items)?o.items.map(x=>({...x})):[];
  const current=db?.digitalProducts?.[String(o.digitalProductId||items[0]?.id||'')];
  if(current)items=items.map((x,i)=>i===0?{...x,name:current.name||x.name,image:String(current.image||x.image||'')}:x);
  return {
    id:o.id,orderNo:o.orderNo,orderType:'digital',createdAt:o.createdAt,updatedAt:o.updatedAt||o.createdAt,
    paymentExpiresAt:orderPaymentExpiresAt(o),items,address:o.address,paymentPreference:o.paymentPreference||'simpay',
    paymentStatus:o.paymentStatus||'pending',subtotal:Number(o.subtotal||0),discount:Number(o.promo?.discount||0),
    shippingCost:0,total:Number(o.total||0),digitalProductId:String(o.digitalProductId||''),
    digitalAccess:o.paymentStatus==='paid',timeline:ensureOrderTimeline(o)
  };
}


// --- Product reviews: shared backend storage ---------------------------------
function reviewProductId(v,db){const id=String(v||'').trim();return db?.digitalProducts?.[id]?id:''}
function cleanReviewText(v){return String(v||'').trim().replace(/\r\n?/g,'\n').slice(0,500)}
function reviewAuthor(db,userId){const u=(db.users||[]).find(x=>x.id===userId);return u?cleanName(u.firstName||'Klient').slice(0,30)||'Klient':'Klient'}
function reviewAuthorTitle(db,userId){const u=(db.users||[]).find(x=>x.id===userId);return accountTitleData(u)}
function deliveredOrderForUser(db,userId,orderId,productId){
  return (db.orders||[]).find(o=>String(o.id)===String(orderId)&&o.userId===userId&&o.paymentStatus==='paid'&&o.orderType==='digital'&&String(o.digitalProductId||'')===String(productId||''));
}
function reviewPurchaseItem(order,productId,color,size){return (order?.items||[]).find(i=>String(i.id)===String(productId)&&String(i.color||'')===String(color||'')&&String(i.size||'').toUpperCase()===String(size||'').toUpperCase())}
function reviewKey(r){return [String(r.orderId||''),String(r.productId||''),String(r.color||''),String(r.size||'').toUpperCase()].join('|')}
function reviewIsVerified(db,r){
  const order=(db.orders||[]).find(o=>String(o.id)===String(r.orderId||'')&&o.userId===r.userId&&o.paymentStatus==='paid'&&o.orderType==='digital'&&String(o.digitalProductId||'')===String(r.productId||''));
  return Boolean(order&&reviewPurchaseItem(order,r.productId,r.color,r.size));
}
function publicReview(db,r){return {id:r.id,productId:r.productId,productType:'digital',orderId:r.orderId||'',name:reviewAuthor(db,r.userId),title:reviewAuthorTitle(db,r.userId),rating:Math.max(1,Math.min(5,Number(r.rating)||5)),text:String(r.text||''),color:String(r.color||''),colorLabel:String(r.colorLabel||r.color||''),size:String(r.size||''),createdAt:Number(r.createdAt||Date.now()),updatedAt:Number(r.updatedAt||r.createdAt||Date.now()),verifiedPurchase:reviewIsVerified(db,r)}}
function orderReviewsForUser(db,order){return (db.reviews||[]).filter(r=>r.userId===order.userId&&String(r.orderId||'')===String(order.id)).map(r=>publicReview(db,r))}

app.get('/api/reviews/:productId',(req,res)=>{
  const db=load();ensureStore(db);const productId=reviewProductId(req.params.productId,db);if(!productId)return res.status(404).json({error:'Nie znaleziono produktu.'});
  const reviews=db.reviews.filter(r=>r.productId===productId&&r.visible!==false).sort((a,b)=>Number(b.updatedAt||b.createdAt)-Number(a.updatedAt||a.createdAt)).map(r=>publicReview(db,r));
  const average=reviews.length?reviews.reduce((sum,r)=>sum+r.rating,0)/reviews.length:0;
  res.setHeader('Cache-Control','no-store');res.json({ok:true,reviews,average:Math.round(average*10)/10,count:reviews.length});
});
app.get('/api/reviews/:productId/mine',auth,(req,res)=>{
  ensureStore(req.db);const productId=reviewProductId(req.params.productId,req.db);if(!productId)return res.status(404).json({error:'Nie znaleziono produktu.'});
  const reviews=req.db.reviews.filter(x=>x.productId===productId&&x.userId===req.user.id).map(r=>publicReview(req.db,r));res.json({ok:true,reviews,review:reviews[0]||null});
});
app.post('/api/reviews/:productId',rateLimit('review-write',15,15*60*1000),auth,(req,res)=>{
  ensureStore(req.db);const productId=reviewProductId(req.params.productId,req.db);if(!productId)return res.status(404).json({error:'Nie znaleziono produktu.'});
  const text=cleanReviewText(req.body?.text),rating=Number(req.body?.rating),orderId=String(req.body?.orderId||''),color=String(req.body?.color||''),size=String(req.body?.size||'').toUpperCase();
  if(text.length<3)return res.status(400).json({error:'Opinia musi mieć co najmniej 3 znaki.'});
  if(!Number.isInteger(rating)||rating<1||rating>5)return res.status(400).json({error:'Wybierz ocenę od 1 do 5.'});
  const order=deliveredOrderForUser(req.db,req.user.id,orderId,productId);if(!order)return res.status(403).json({error:'Opinię o produkcie cyfrowym możesz dodać po opłaceniu zamówienia i otrzymaniu dostępu.'});
  const item=reviewPurchaseItem(order,productId,color,size);if(!item)return res.status(400).json({error:'Nie znaleziono tego wariantu produktu w zamówieniu.'});
  const now=Date.now();let r=req.db.reviews.find(x=>x.userId===req.user.id&&String(x.orderId||'')===orderId&&x.productId===productId&&String(x.color||'')===String(item.color||'')&&String(x.size||'').toUpperCase()===String(item.size||'').toUpperCase());
  if(r){r.text=text;r.rating=rating;r.updatedAt=now;r.visible=true;r.color=String(item.color||'');r.colorLabel=String(item.colorLabel||item.color||'');r.size=String(item.size||'').toUpperCase()}
  else{r={id:crypto.randomUUID(),orderId:order.id,productId,userId:req.user.id,color:String(item.color||''),colorLabel:String(item.colorLabel||item.color||''),size:String(item.size||'').toUpperCase(),rating,text,visible:true,createdAt:now,updatedAt:now};req.db.reviews.push(r)}
  save(req.db);res.json({ok:true,review:publicReview(req.db,r),message:'Opinia została zapisana.'});
});
app.delete('/api/reviews/by-id/:id',auth,(req,res)=>{
  ensureStore(req.db);const r=req.db.reviews.find(x=>x.id===req.params.id&&x.userId===req.user.id);if(!r)return res.status(404).json({error:'Nie znaleziono Twojej opinii.'});
  req.db.reviews=req.db.reviews.filter(x=>x.id!==r.id);save(req.db);res.json({ok:true});
});
app.delete('/api/reviews/:productId',auth,(req,res)=>{
  ensureStore(req.db);const productId=reviewProductId(req.params.productId,req.db);if(!productId)return res.status(404).json({error:'Nie znaleziono produktu.'});
  const orderId=String(req.query?.orderId||''),color=String(req.query?.color||''),size=String(req.query?.size||'').toUpperCase();
  const before=req.db.reviews.length;req.db.reviews=req.db.reviews.filter(r=>!(r.productId===productId&&r.userId===req.user.id&&(!orderId||String(r.orderId||'')===orderId)&&(!color||String(r.color||'')===color)&&(!size||String(r.size||'').toUpperCase()===size)));
  if(req.db.reviews.length===before)return res.status(404).json({error:'Nie masz opinii dla tego produktu.'});save(req.db);res.json({ok:true});
});
app.get('/api/orders',auth,(req,res)=>{ensureStore(req.db);expirePendingOrders(req.db,req.user.id);res.json({ok:true,orders:req.db.orders.filter(o=>o.userId===req.user.id&&o.orderType==='digital'&&o.paymentStatus!=='expired').map(o=>({...orderForUser(o,req.db),reviews:orderReviewsForUser(req.db,o)})).sort((a,b)=>b.createdAt-a.createdAt)})});


function ensurePromoCodes(db){
  if(!Array.isArray(db.promoCodes))db.promoCodes=[];
  if(!db.promoCodes.some(p=>String(p.code||'').toUpperCase()==='STARXV10')){
    db.promoCodes.push({id:crypto.randomUUID(),code:'STARXV10',type:'percent',value:10,minSubtotal:0,usageLimit:null,usedCount:0,usedByUserIds:[],assignedUserId:null,active:true,startsAt:null,endsAt:null,createdAt:Date.now(),updatedAt:Date.now()});
  }
  for(const p of db.promoCodes){
    if(!Array.isArray(p.usedByUserIds))p.usedByUserIds=[];
    if(!Object.prototype.hasOwnProperty.call(p,'assignedUserId'))p.assignedUserId=null;
    if(!Object.prototype.hasOwnProperty.call(p,'productId'))p.productId=null;
  }
  return db.promoCodes;
}
function promoPublic(p){return {id:p.id,code:p.code,type:p.type,value:Number(p.value||0),minSubtotal:Number(p.minSubtotal||0),usageLimit:p.usageLimit==null?null:Number(p.usageLimit),usedCount:Number(p.usedCount||0),usedByCount:Array.isArray(p.usedByUserIds)?p.usedByUserIds.length:0,assignedUserId:p.assignedUserId||null,productId:p.productId||null,active:Boolean(p.active),startsAt:p.startsAt||null,endsAt:p.endsAt||null,createdAt:p.createdAt,updatedAt:p.updatedAt}}
function validatePromo(db,rawCode,subtotal,userId='',productId=''){
  ensurePromoCodes(db);
  const code=String(rawCode||'').trim().toUpperCase(),base=Math.max(0,Number(subtotal||0)),uid=String(userId||''),pid=String(productId||'').trim();
  if(!code)return {ok:false,error:'Wpisz kod rabatowy.'};
  const p=db.promoCodes.find(x=>String(x.code||'').toUpperCase()===code);
  if(!p||!p.active)return {ok:false,error:'Ten kod jest nieprawidłowy lub nieaktywny.'};
  if(p.productId&&String(p.productId)!==pid)return {ok:false,error:'Ten kod rabatowy nie obowiązuje dla tego produktu.'};
  if(p.assignedUserId&&String(p.assignedUserId)!==uid)return {ok:false,error:'Ten kod rabatowy jest przypisany do innego konta.'};
  if(uid&&Array.isArray(p.usedByUserIds)&&p.usedByUserIds.some(id=>String(id)===uid))return {ok:false,error:'Ten kod rabatowy został już wykorzystany na tym koncie.',errorCode:'PROMO_ALREADY_USED'};
  const now=Date.now(),start=p.startsAt?new Date(p.startsAt).getTime():0,end=p.endsAt?new Date(p.endsAt).getTime():0;
  if(start&&now<start)return {ok:false,error:'Ten kod nie jest jeszcze aktywny.'};
  if(end&&now>end)return {ok:false,error:'Ten kod wygasł.'};
  if(p.usageLimit!=null&&Number(p.usedCount||0)>=Number(p.usageLimit))return {ok:false,error:'Limit użyć tego kodu został wyczerpany.'};
  if(base<Number(p.minSubtotal||0))return {ok:false,error:`Ten rabat można użyć od ${Number(p.minSubtotal||0).toFixed(2)} PLN wartości zamówienia.`,errorCode:'PROMO_MIN_SUBTOTAL',minSubtotal:Number(p.minSubtotal||0)};
  let discount=p.type==='fixed'?Number(p.value||0):base*(Number(p.value||0)/100);
  discount=Math.max(0,Math.min(base,Math.round(discount*100)/100));
  return {ok:true,promo:promoPublic(p),discount,total:Math.max(0,Math.round((base-discount)*100)/100)};
}
app.get('/api/promos/validate',auth,(req,res)=>{
  ensurePromoCodes(req.db);const result=validatePromo(req.db,req.query?.code,req.query?.subtotal,req.user.id,req.query?.productId);save(req.db);
  if(!result.ok)return res.status(400).json(result);res.json(result);
});

function ensureReturnRequests(db){if(!Array.isArray(db.returnRequests))db.returnRequests=[];return db.returnRequests}
function nextReturnNo(db){const nums=ensureReturnRequests(db).map(x=>Number(String(x.returnNo||'').replace(/\D/g,''))||0);return `RT-${Math.max(1000,...nums)+1}`}
function returnForUser(r){return {id:r.id,returnNo:r.returnNo,orderId:r.orderId,orderNo:r.orderNo,type:r.type,reason:r.reason,details:r.details||'',items:r.items||[],status:r.status||'new',adminReply:r.adminReply||'',createdAt:r.createdAt,updatedAt:r.updatedAt||r.createdAt}}
app.get('/api/returns',auth,(req,res)=>{ensureReturnRequests(req.db);res.json({ok:true,returns:req.db.returnRequests.filter(r=>r.userId===req.user.id).map(returnForUser).sort((a,b)=>b.createdAt-a.createdAt)})});
app.post('/api/orders/:id/cancel',auth,(req,res)=>{
  ensureStore(req.db);
  const order=req.db.orders.find(o=>o.id===req.params.id&&o.userId===req.user.id);
  if(!order)return res.status(404).json({error:'Nie znaleziono zamówienia.'});
  expirePendingOrders(req.db,req.user.id);
  if(order.paymentStatus==='expired')return res.status(410).json({error:'To zamówienie wygasło po 24 godzinach bez potwierdzenia płatności.'});
  if(order.paymentStatus==='cancelled')return res.json({ok:true,order:orderForUser(order)});
  if(order.paymentStatus==='paid')return res.status(409).json({error:'Opłaconego zamówienia nie można anulować automatycznie. Skontaktuj się z obsługą STARXV.'});
  order.paymentStatus='cancelled';
  order.cancelledAt=Date.now();
  order.updatedAt=Date.now();
  orderEvent(order,'cancelled','Zamówienie anulowane','Zamówienie zostało anulowane przed potwierdzeniem płatności.',order.cancelledAt);
  save(req.db);sendOrderUpdateEmail(req.db,order,'cancelled',{dedupeKey:'cancelled'});
  res.json({ok:true,order:orderForUser(order)});
});
// This function is intentionally server-only. A future payment webhook should call it only after the payment provider confirms payment.
function markOrderPaid(db,order){
  if(order.paymentStatus==='paid')return;
  order.paymentStatus='paid';order.updatedAt=Date.now();
  if(order.promo?.code&&!order.promoCounted){ensurePromoCodes(db);const pc=db.promoCodes.find(p=>String(p.code||'').toUpperCase()===String(order.promo.code||'').toUpperCase());if(pc){pc.usedCount=Number(pc.usedCount||0)+1;if(!Array.isArray(pc.usedByUserIds))pc.usedByUserIds=[];if(order.userId&&!pc.usedByUserIds.some(id=>String(id)===String(order.userId)))pc.usedByUserIds.push(order.userId);pc.updatedAt=Date.now()}order.promoCounted=true;}
  orderEvent(order,'paid','Płatność potwierdzona','Płatność została zaakceptowana. Produkt cyfrowy jest dostępny na koncie STARXV.',order.updatedAt);
}


function paymentBaseUrl(req){
  const configured=String(process.env.PUBLIC_URL||'').trim().replace(/\/$/,'');
  return configured||`${req.protocol}://${req.get('host')}`;
}
async function sendPaidOrderEmail(db,order){
  try{
    const key=String(process.env.RESEND_API_KEY||'').trim();
    if(!key)return;
    const u=(db.users||[]).find(x=>x.id===order.userId);
    const to=cleanEmail(order.address?.email||u?.email);
    if(!to)return;
    const resend=new Resend(key);
    if(order.orderType==='digital'){
      const dbForDigital=load();ensureStore(dbForDigital);const product=getDigitalProduct(dbForDigital,order.digitalProductId);
      const base=String(process.env.PUBLIC_URL||'https://starxv.pl').replace(/\/$/,'');
      const access=base+'/?section=digital&order='+encodeURIComponent(order.id);
      const total=Number(order.total||0).toLocaleString('pl-PL',{minimumFractionDigits:2,maximumFractionDigits:2});
      const productName=String(product?.name||order.items?.[0]?.name||'E-book STARXV');
      const safe=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
      const consentAt=order.digitalConsentAt?new Date(order.digitalConsentAt).toLocaleString('pl-PL'):'złożona przy zakupie';
      const orderDate=new Date(order.createdAt||Date.now()).toLocaleString('pl-PL');
      const seller='Mikołaj Asman — STARXV, działalność nierejestrowana';
      const sellerAddress='ul. Osiedle 165/2, 42-460 Mierzęcice';
      const legalVersion=String(order.legalVersion||LEGAL_VERSION);
      const consentText=String(order.digitalConsentText||DIGITAL_CONSENT_TEXT);
      const legalLinks=`Regulamin: ${base}/terms.html\nPolityka prywatności: ${base}/privacy.html\nZwroty i reklamacje: ${base}/returns.html`;
      const mailText=`STARXV — POTWIERDZENIE ZAWARCIA UMOWY NA ODLEGŁOŚĆ\n\nZamówienie #${order.orderNo}\nData złożenia: ${orderDate}\nSprzedawca: ${seller}\nAdres: ${sellerAddress}\nKontakt: kontakt@starxv.pl, +48 574 424 450\n\nProdukt: ${productName}\nRodzaj: treść cyfrowa / e-book\nFormat: PDF\nSposób dostarczenia: elektronicznie na konto STARXV po potwierdzeniu płatności\nOperator płatności: SimPay\nŁączna cena: ${total} PLN\n\nPłatność została potwierdzona. Produkt jest przypisany do konta STARXV i można go pobrać tutaj:\n${access}\n\nOŚWIADCZENIE DOTYCZĄCE NATYCHMIASTOWEGO DOSTĘPU\n${consentText}\nZapis oświadczenia: ${consentAt}\n\nW odniesieniu do odpłatnej treści cyfrowej niedostarczanej na nośniku materialnym prawo do odstąpienia może zostać utracone po rozpoczęciu dostarczania, jeżeli spełnione zostały wymagane prawem warunki. Niezależnie od tego zachowujesz prawa z tytułu niezgodności treści cyfrowej z umową i możliwość złożenia reklamacji.\n\nWersja informacji prawnych zaakceptowana przy zakupie: ${legalVersion}.\n${legalLinks}\n\nReklamacje i kontakt: kontakt@starxv.pl`;
      const {error}=await resend.emails.send({
        from:process.env.MAIL_FROM||'STARXV <no-reply@starxv.pl>',to,
        subject:`STARXV — potwierdzenie umowy #${order.orderNo} / ${productName}`,
        text:mailText,
        html:`<div style="background:#090909;color:#f3f0e8;font-family:Arial,sans-serif;padding:36px 18px"><div style="max-width:620px;margin:auto"><div style="font-size:22px;font-weight:900;letter-spacing:4px">STARXV / DIGITAL</div><div style="margin:28px 0 8px;color:#c9a83d;font-size:10px;font-weight:900;letter-spacing:1.5px">POTWIERDZENIE ZAWARCIA UMOWY NA ODLEGŁOŚĆ</div><h1 style="font-size:27px;margin:0 0 20px">${safe(productName)} jest gotowy.</h1><div style="padding:18px;border:1px solid #292929;background:#0d0d0d;line-height:1.65;font-size:13px"><b>Zamówienie #${safe(order.orderNo)}</b><br>Data: ${safe(orderDate)}<br>Produkt: ${safe(productName)}<br>Format: PDF<br>Operator płatności: SimPay<br><b>Razem: ${safe(total)} PLN</b></div><p style="color:#aaa;line-height:1.7">Płatność została potwierdzona. Produkt jest przypisany do Twojego konta STARXV.</p><a href="${safe(access)}" style="display:inline-block;margin:8px 0 26px;background:#f1e7cf;color:#111;text-decoration:none;padding:14px 20px;font-size:12px;font-weight:900">OTWÓRZ I POBIERZ →</a><h2 style="font-size:15px;margin:20px 0 8px">Twoje oświadczenie</h2><p style="color:#bbb;line-height:1.7">${safe(consentText)}</p><p style="color:#777;font-size:11px">Zapis oświadczenia: ${safe(consentAt)} • wersja informacji prawnych: ${safe(legalVersion)}</p><h2 style="font-size:15px;margin:24px 0 8px">Sprzedawca</h2><p style="color:#bbb;line-height:1.65">${safe(seller)}<br>${safe(sellerAddress)}<br>kontakt@starxv.pl • +48 574 424 450</p><p style="color:#999;line-height:1.65;font-size:12px">Prawo do zwykłego odstąpienia od umowy dotyczącej treści cyfrowej może zostać utracone po rozpoczęciu jej dostarczania, jeżeli spełniono wymagane prawem warunki. Prawa dotyczące niezgodności treści cyfrowej z umową i reklamacji pozostają bez zmian.</p><div style="border-top:1px solid #242424;margin-top:24px;padding-top:18px;font-size:11px;line-height:1.8"><a style="color:#d8bf70" href="${base}/terms.html">Regulamin</a> • <a style="color:#d8bf70" href="${base}/privacy.html">Polityka prywatności</a> • <a style="color:#d8bf70" href="${base}/returns.html#digital">Zwroty i reklamacje</a></div></div></div>`
      });
      if(error)console.error('Resend digital confirmation error:',error);
      return;
    }
  }catch(e){console.error('Order confirmation email error:',e.message)}
}

async function sendOrderUpdateEmail(db,order,eventKey,opts={}){
  try{
    const key=String(process.env.RESEND_API_KEY||'').trim();
    if(!key)return false;
    if(!order.mailEvents||typeof order.mailEvents!=='object')order.mailEvents={};
    const dedupe=String(opts.dedupeKey||eventKey);
    if(order.mailEvents[dedupe])return false;
    const u=(db.users||[]).find(x=>x.id===order.userId);
    const to=cleanEmail(order.address?.email||u?.email);
    if(!to)return false;
    const t={
      created:['Zamówienie zostało utworzone','Otrzymaliśmy Twoje zamówienie cyfrowe. Oczekujemy na potwierdzenie płatności.'],
      paid:['Płatność potwierdzona','Płatność została zaakceptowana. Produkt cyfrowy jest dostępny na Twoim koncie.'],
      cancelled:['Zamówienie anulowane','Zamówienie zostało anulowane i nie będzie dalej realizowane.']
    };
    const [title,body]=t[eventKey]||['Aktualizacja zamówienia','Status Twojego zamówienia cyfrowego został zaktualizowany.'];
    const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const base=String(process.env.PUBLIC_URL||'https://starxv.pl').replace(/\/+$/,'');
    const resend=new Resend(key);
    const {error}=await resend.emails.send({from:process.env.MAIL_FROM||'STARXV <no-reply@starxv.pl>',to,subject:`STARXV — ${title} #${order.orderNo}`,text:`STARXV\n\n${title}\nZamówienie #${order.orderNo}\n\n${body}\n\nStatus zamówienia: ${base}`,html:`<div style="background:#090909;color:#fff;font-family:Arial,sans-serif;padding:36px 20px"><div style="max-width:560px;margin:auto"><div style="font-size:25px;font-weight:900;letter-spacing:5px;margin-bottom:30px">STARXV</div><div style="font-size:10px;color:#777;letter-spacing:2px">ZAMÓWIENIE #${esc(order.orderNo)}</div><h1 style="font-size:22px;margin:10px 0 14px">${esc(title)}</h1><p style="font-size:14px;line-height:1.7;color:#bbb">${esc(body)}</p><a href="${esc(base)}" style="display:inline-block;background:#fff;color:#000;text-decoration:none;padding:12px 18px;font-size:11px;font-weight:900;margin-top:12px">SPRAWDŹ ZAMÓWIENIE →</a><div style="font-size:10px;color:#555;margin-top:30px">STARXV • kontakt@starxv.pl</div></div></div>`});
    if(error){console.error('Resend order update error:',error);return false}
    order.mailEvents[dedupe]=Date.now();save(db);return true;
  }catch(e){console.error('Order update email error:',e.message);return false}
}

function simpayConfig(){
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


// --- STARXV DIGITAL ------------------------------------------------------------
// Metadata is managed from Admin and persisted in the same database as the physical catalog.
// PDF files stay outside /public, so they cannot be downloaded by guessing a URL.
function digitalFilePath(p){
  const fileName=path.basename(String(p?.fileName||''));
  return fileName?path.join(__dirname,'digital',fileName):'';
}
function getDigitalProduct(db,id){ensureStore(db);return db.digitalProducts?.[String(id||'')];}
function publicDigitalProduct(p,db){
  const file=digitalFilePath(p);
  ensureProductPriceTracking(p);
  const basePrice=money2(p.price||0),effectivePrice=effectiveCatalogPrice(p),ref=Number(p.omnibusReferencePrice);
  const promoActive=Number(p.discountPercent||0)>0&&Number.isFinite(ref)&&ref>effectivePrice;
  const shownDiscount=promoActive?Math.max(1,Math.round((1-effectivePrice/ref)*100)):0;
  const purchaseCount=db?new Set((db.orders||[]).filter(o=>o.orderType==='digital'&&String(o.digitalProductId||'')===String(p.id||'')&&o.paymentStatus==='paid'&&o.userId).map(o=>String(o.userId))).size:0;
  return {
    id:p.id,position:Number.isFinite(Number(p.position))?Number(p.position):999,categoryId:String(p.categoryId||'praktyczne'),name:p.name,subtitle:p.subtitle||'',description:p.description||'',meta:p.meta||'STARXV DIGITAL / E-BOOK',
    points:Array.isArray(p.points)?p.points.slice(0,4):['Produkt cyfrowy PDF','Dostęp po potwierdzeniu płatności','Przypisany do konta STARXV','Pobieranie z biblioteki zamówień'],
    price:basePrice,effectivePrice,discountPercent:Number(p.discountPercent||0),
    promotion:{active:promoActive,referencePrice:promoActive?money2(ref):null,referenceType:promoActive?(p.omnibusReferenceType||'30-days'):null,discountPercent:shownDiscount,promotionStartedAt:Number(p.promotionStartedAt||0)||null},
    image:p.image||'',gallery:Array.isArray(p.gallery)?p.gallery.slice(0,10):[],active:p.active!==false,
    available:p.active!==false&&effectivePrice>0&&Boolean(file)&&fs.existsSync(file),purchaseCount
  };
}
app.get('/api/digital/products',(req,res)=>{
  const db=load();ensureStore(db);res.setHeader('Cache-Control','no-store');
  const categories=(db.digitalCategories||[]).filter(c=>c.visible!==false).map(c=>({
    id:String(c.id||''),name:String(c.name||''),description:String(c.description||''),
    position:Number.isFinite(Number(c.position))?Number(c.position):999,visible:c.visible!==false
  })).sort((a,b)=>(a.position-b.position)||a.name.localeCompare(b.name,'pl'));
  const products=Object.values(db.digitalProducts||{}).filter(p=>p.active!==false).map(p=>publicDigitalProduct(p,db)).sort((a,b)=>(Number(a.position||999)-Number(b.position||999))||String(a.name||'').localeCompare(String(b.name||''),'pl'));
  res.json({ok:true,categories,products});
});
app.post('/api/digital/orders/prepare',auth,rateLimit('digital-prepare',20,10*60*1000),(req,res)=>{
  try{
    ensureStore(req.db);
    const product=getDigitalProduct(req.db,req.body?.productId);
    if(!product||product.active===false||!fs.existsSync(digitalFilePath(product)))return res.status(404).json({error:'Produkt cyfrowy nie jest jeszcze dostępny.'});
    const productPrice=effectiveCatalogPrice(product);
    if(!(Number(productPrice)>0))return res.status(409).json({error:'Cena produktu cyfrowego nie została jeszcze ustawiona.'});
    if(req.body?.termsAccepted!==true)return res.status(400).json({error:'Przed zakupem zaakceptuj Regulamin STARXV.'});
    if(req.body?.digitalConsent!==true)return res.status(400).json({error:'Aby otrzymać e-book od razu po płatności, wyraź zgodę na rozpoczęcie dostarczania treści cyfrowej przed upływem terminu do odstąpienia i potwierdź przyjęcie do wiadomości skutku tej zgody.'});
    const existing=(req.db.orders||[]).find(o=>o.userId===req.user.id&&o.orderType==='digital'&&o.digitalProductId===product.id&&o.paymentStatus==='paid');
    if(existing)return res.json({ok:true,alreadyOwned:true,order:orderForUser(existing)});
    const promoCode=String(req.body?.promoCode||'').trim().toUpperCase();
    let codeDiscount=0,promoRecord=null;
    if(promoCode){
      const check=validatePromo(req.db,promoCode,productPrice,req.user.id,product.id);
      if(!check.ok)return res.status(400).json(check);
      codeDiscount=Number(check.discount||0);promoRecord=check.promo;
    }
    const finalTotal=money2(Math.max(0,productPrice-codeDiscount));
    if(finalTotal<=0)return res.status(400).json({error:'Końcowa kwota zamówienia musi być większa od 0 PLN.'});
    const now=Date.now();
    const order={id:crypto.randomUUID(),orderNo:String(now).slice(-8),orderType:'digital',digitalProductId:product.id,userId:req.user.id,createdAt:now,updatedAt:now,items:[{id:product.id,name:product.name,fit:'STARXV DIGITAL',color:'digital',colorLabel:'Produkt cyfrowy',size:'PDF',qty:1,price:productPrice,basePrice:money2(product.price),discountPercent:Number(product.discountPercent||0),image:String(product.image||'/assets/placeholder.png')}],address:{email:cleanEmail(req.user.email),firstName:req.user.firstName,lastName:req.user.lastName},delivery:{type:'digital'},paymentPreference:'simpay',promo:promoCode?{code:promoCode,discount:codeDiscount,type:promoRecord?.type||null,value:promoRecord?.value||0,productId:promoRecord?.productId||null}:null,subtotal:productPrice,shippingCost:0,total:finalTotal,paymentStatus:'pending',paymentExpiresAt:now+ORDER_PAYMENT_TTL_MS,shippingStage:0,stockCommitted:true,legalVersion:LEGAL_VERSION,termsAcceptedAt:now,privacyAcknowledgedAt:req.body?.privacyAcknowledged===true?now:null,digitalConsentAt:now,digitalConsentText:DIGITAL_CONSENT_TEXT,timeline:[]};
    orderEvent(order,'created','Zamówienie cyfrowe utworzone','Po potwierdzeniu płatności e-book będzie dostępny natychmiast.',now);
    req.db.orders.push(order);save(req.db);
    res.json({ok:true,order:orderForUser(order)});
  }catch(e){console.error('Digital prepare error:',e);res.status(400).json({error:e.message||'Nie udało się przygotować zamówienia cyfrowego.'})}
});
app.get('/api/digital/download/:productId',auth,rateLimit('digital-download',40,10*60*1000),(req,res)=>{
  ensureStore(req.db);
  const product=getDigitalProduct(req.db,req.params.productId);

  if(!product||product.active===false||!fs.existsSync(digitalFilePath(product))){
    res.setHeader('Cache-Control','no-store');
    res.setHeader('Content-Type','text/html; charset=utf-8');
    return res.status(404).send(`<!doctype html>
<html lang="pl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="theme-color" content="#f5f3ef">
  <title>STARXV — plik chwilowo niedostępny</title>
  <style>
    *{box-sizing:border-box}
    html,body{margin:0;min-height:100%;font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f5f3ef;color:#111}
    body{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
    .wrap{width:min(100%,760px)}
    .brand{font-size:16px;font-weight:800;letter-spacing:.26em;text-transform:uppercase;margin:0 0 18px 2px}
    .card{background:rgba(255,255,255,.9);border:1px solid rgba(17,17,17,.08);border-radius:30px;padding:clamp(28px,5vw,54px);box-shadow:0 20px 70px rgba(17,17,17,.08)}
    .icon{width:58px;height:58px;border-radius:18px;background:#111;color:#fff;display:flex;align-items:center;justify-content:center;font-size:28px;font-weight:700;margin-bottom:28px}
    .eyebrow{font-size:12px;font-weight:800;letter-spacing:.18em;text-transform:uppercase;color:#777;margin-bottom:12px}
    h1{font-size:clamp(30px,6vw,54px);line-height:1.02;letter-spacing:-.045em;margin:0 0 18px;max-width:620px}
    p{font-size:16px;line-height:1.7;color:#626262;margin:0;max-width:590px}
    .actions{display:flex;flex-wrap:wrap;gap:12px;margin-top:32px}
    a,button{appearance:none;border:0;border-radius:999px;padding:14px 20px;font:inherit;font-weight:700;text-decoration:none;cursor:pointer}
    .primary{background:#111;color:#fff}
    .secondary{background:#ece9e3;color:#111}
    .code{margin-top:26px;padding-top:22px;border-top:1px solid rgba(17,17,17,.08);font-size:12px;color:#999;letter-spacing:.04em}
    @media(max-width:560px){body{padding:14px}.card{border-radius:24px}.actions{flex-direction:column}.actions a,.actions button{width:100%;text-align:center}}
  </style>
</head>
<body>
  <main class="wrap">
    <div class="brand">STARXV</div>
    <section class="card">
      <div class="icon">!</div>
      <div class="eyebrow">STARXV DIGITAL</div>
      <h1>Plik jest chwilowo niedostępny.</h1>
      <p>
        Nie możemy teraz pobrać tego e-booka, ponieważ jego plik nie jest obecnie dostępny na serwerze.
        Spróbuj ponownie później. Jeśli problem będzie się powtarzał, skontaktuj się z obsługą STARXV.
      </p>
      <div class="actions">
        <button class="primary" type="button" onclick="location.reload()">Spróbuj ponownie</button>
        <a class="secondary" href="/?section=digital&home=1">Wróć do STARXV Digital</a>
      </div>
      <div class="code">Błąd 404 · DIGITAL_FILE_UNAVAILABLE</div>
    </section>
  </main>
</body>
</html>`);
  }

  const owned=(req.db.orders||[]).some(o=>o.userId===req.user.id&&o.orderType==='digital'&&o.digitalProductId===product.id&&o.paymentStatus==='paid');
  if(!owned)return res.status(403).send('Ten plik jest dostępny tylko dla konta, które kupiło produkt.');

  res.setHeader('Cache-Control','private, no-store');
  res.setHeader('X-Content-Type-Options','nosniff');
  res.download(digitalFilePath(product),product.downloadName||product.fileName||'STARXV_DIGITAL.pdf');
});

app.get('/api/payments/config',(req,res)=>res.json({ok:true,provider:'simpay',configured:simpayConfigured(),currency:'PLN',methods:['simpay']}));

app.post('/api/create-checkout-session',auth,async(req,res)=>{
  try{
    if(!simpayConfigured())return res.status(503).json({error:'SimPay nie jest jeszcze skonfigurowany na serwerze.'});
    ensureStore(req.db);
    expirePendingOrders(req.db,req.user.id);
    const orderId=String(req.body?.orderId||'');
    const order=req.db.orders.find(o=>o.id===orderId&&o.userId===req.user.id);
    if(!order)return res.status(404).json({error:'Nie znaleziono zamówienia.'});
    if(order.paymentStatus==='paid')return res.status(409).json({error:'To zamówienie jest już opłacone.'});
    if(order.paymentStatus==='cancelled')return res.status(409).json({error:'To zamówienie zostało anulowane.'});
    if(order.paymentStatus==='expired')return res.status(410).json({error:'To zamówienie wygasło po 24 godzinach bez potwierdzenia płatności. Utwórz nowe zamówienie.'});
    const amount=Math.round(Number(order.total)*100)/100;
    if(!Number.isFinite(amount)||amount<=0)return res.status(400).json({error:'Nieprawidłowa kwota zamówienia.'});
    if(order.paymentStatus==='failed')order.paymentStatus='pending';
    const c=simpayConfig(),base=paymentBaseUrl(req);
    const payload={
      amount,
      currency:'PLN',
      control:order.id,
      description:('STARXV zamówienie '+order.orderNo).slice(0,128),
      returns:{
        success:base+'/?'+(order.orderType==='digital'?'section=digital&':'')+'payment=return&order='+encodeURIComponent(order.id),
        failure:base+'/?'+(order.orderType==='digital'?'section=digital&':'')+'payment=failed&order='+encodeURIComponent(order.id)
      }
    };
    let data;
    try{data=await simpayRequest('/payment/'+encodeURIComponent(c.serviceId)+'/transactions',{method:'POST',body:JSON.stringify(payload)})}
    catch(e){save(req.db);throw e}
    const transactionId=String(data?.data?.transactionId||'');
    const redirectUrl=String(data?.data?.redirectUrl||'');
    if(!transactionId||!/^https:\/\//i.test(redirectUrl)){save(req.db);throw new Error('SimPay nie zwrócił poprawnego linku płatności.')}
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
});


app.get('/api/orders/:id/payment-status',auth,(req,res)=>{ensureStore(req.db);expirePendingOrders(req.db,req.user.id);const order=req.db.orders.find(o=>o.id===req.params.id&&o.userId===req.user.id);if(!order||order.paymentStatus==='expired')return res.status(404).json({error:'Nie znaleziono aktywnego zamówienia.'});res.json({ok:true,order:orderForUser(order,req.db),confirmed:order.paymentStatus==='paid'})});


// --- STARXV marketing/news campaigns -----------------------------------------
const CAMPAIGN_TYPES=new Set(['newsletter','site_update','new_product','new_variant','restock','other']);
function campaignType(v){const x=String(v||'').trim();return CAMPAIGN_TYPES.has(x)?x:'other'}
function campaignTypeLabel(v){return ({newsletter:'NEWSLETTER',site_update:'ZMIANY NA STRONIE',new_product:'NOWY PRODUKT',new_variant:'NOWY WARIANT',restock:'POWRÓT DO MAGAZYNU',other:'NOWOŚĆ STARXV'})[campaignType(v)]||'NOWOŚĆ STARXV'}
function cleanCampaignText(v,max=3000){return String(v||'').trim().replace(/\r\n?/g,'\n').slice(0,max)}
function emailEscape(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function cleanCampaignUrl(v){
  const raw=String(v||'').trim();if(!raw)return 'https://starxv.pl/';
  try{const u=new URL(raw);if(u.protocol!=='https:'||!['starxv.pl','www.starxv.pl'].includes(u.hostname.toLowerCase()))throw new Error();return u.toString().slice(0,1000)}catch{throw new Error('Link przycisku musi prowadzić do https://starxv.pl.')}
}
function marketingSender(){return String(process.env.NEWSLETTER_FROM||'STARXV Nowości <kontakt@starxv.pl>').trim()}
function marketingSubscribers(db){return (db.users||[]).filter(u=>u.marketingEmails===true&&validEmail(cleanEmail(u.email)))}
function marketingCampaignImage(body){
  const dataUrl=String(body?.imageDataUrl||'').trim();if(!dataUrl)return null;
  const m=dataUrl.match(/^data:(image\/(?:png|jpeg|gif));base64,([A-Za-z0-9+/=]+)$/i);if(!m)throw new Error('Zdjęcie musi być plikiem JPG, PNG albo GIF.');
  const mime=m[1].toLowerCase(),base64=m[2],bytes=Buffer.from(base64,'base64');
  if(!bytes.length||bytes.length>2.5*1024*1024)throw new Error('Zdjęcie może mieć maksymalnie 2,5 MB.');
  const ext=mime==='image/jpeg'?'jpg':mime.split('/')[1],rawName=cleanCampaignText(body?.imageName,100).replace(/[^a-zA-Z0-9._-]/g,'_');
  return {mime,base64,filename:rawName||`starxv-news.${ext}`,contentId:'starxv-campaign-image'};
}
function marketingCampaignInput(body){
  const type=campaignType(body?.type),subject=cleanCampaignText(body?.subject,120),title=cleanCampaignText(body?.title,120),message=cleanCampaignText(body?.message,3000);
  const product=cleanCampaignText(body?.product,120),variant=cleanCampaignText(body?.variant,120),ctaLabel=cleanCampaignText(body?.ctaLabel,50)||'ZOBACZ STARXV',ctaUrl=cleanCampaignUrl(body?.ctaUrl),image=marketingCampaignImage(body);
  if(subject.length<3)throw new Error('Podaj temat wiadomości.');if(title.length<2)throw new Error('Podaj tytuł wiadomości.');if(message.length<5)throw new Error('Treść wiadomości jest za krótka.');
  return {type,subject,title,message,product,variant,ctaLabel,ctaUrl,image};
}
function campaignEmailContent(c){
  const tag=campaignTypeLabel(c.type),extra=[c.product,c.variant].filter(Boolean).join(' · ');
  const messageHtml=emailEscape(c.message).replace(/\n/g,'<br>');
  const imageHtml=c.image?`<div style="margin:0 0 24px"><img src="cid:${emailEscape(c.image.contentId)}" alt="STARXV" style="display:block;width:100%;max-width:560px;height:auto;border:0"></div>`:'';
  const brandHeader=`<div style="background:#050505;padding:18px 22px;text-align:center"><img src="cid:starxv-newsletter-logo" alt="STARXV Nowości" width="520" style="display:block;width:100%;max-width:520px;height:auto;margin:0 auto;border:0"><div style="margin-top:8px;font-size:10px;letter-spacing:2px;color:#aaa">${emailEscape(tag)}</div></div>`;
  const html=`<!doctype html><html><body style="margin:0;background:#f4f4f4;color:#111;font-family:Arial,sans-serif"><div style="max-width:620px;margin:0 auto;padding:28px 14px">${brandHeader}<div style="background:#fff;padding:34px 30px">${imageHtml}<div style="font-size:11px;font-weight:800;letter-spacing:1.5px;color:#777;margin-bottom:12px">${emailEscape(tag)}</div><h1 style="font-size:27px;line-height:1.1;margin:0 0 12px">${emailEscape(c.title)}</h1>${extra?`<div style="font-size:12px;color:#666;margin-bottom:22px">${emailEscape(extra)}</div>`:''}<div style="font-size:15px;line-height:1.7;color:#222">${messageHtml}</div><a href="${emailEscape(c.ctaUrl)}" style="display:inline-block;margin-top:28px;padding:13px 20px;background:#111;color:#fff;text-decoration:none;font-size:11px;font-weight:900;letter-spacing:1px">${emailEscape(c.ctaLabel)}</a><div style="margin-top:34px;padding-top:20px;border-top:1px solid #e8e8e8;font-size:10px;line-height:1.55;color:#888">Otrzymujesz tę wiadomość, ponieważ na koncie STARXV masz włączone powiadomienia marketingowe. Możesz je wyłączyć w dowolnym momencie w Profilu → Powiadomienia marketingowe.</div></div></div></body></html>`;
  const text=`STARXV — ${tag}\n\n${c.title}${extra?'\n'+extra:''}\n\n${c.message}\n\n${c.ctaLabel}: ${c.ctaUrl}\n\nOtrzymujesz tę wiadomość, ponieważ na koncie STARXV masz włączone powiadomienia marketingowe. Możesz je wyłączyć w Profilu.`;
  return {html,text};
}
async function sendMarketingCampaignEmail(to,c){
  const apiKey=String(process.env.RESEND_API_KEY||'').trim();if(!apiKey){if(process.env.NODE_ENV==='production')throw new Error('Brak RESEND_API_KEY.');console.log(`[STARXV DEV] Marketing → ${to}: ${c.subject}`);return {dev:true}}
  const resend=new Resend(apiKey),content=campaignEmailContent(c);
  const logoPath=path.join(__dirname,'public','assets','starxv-nowosci.png');
  const logoContent=fs.readFileSync(logoPath).toString('base64');
  const attachments=[{content:logoContent,filename:'starxv-nowosci.png',contentId:'starxv-newsletter-logo'}];
  if(c.image)attachments.push({content:c.image.base64,filename:c.image.filename,contentId:c.image.contentId});
  const {data,error}=await resend.emails.send({from:marketingSender(),to,subject:c.subject,text:content.text,html:content.html,attachments});
  if(error){console.error('Resend marketing error:',error);throw new Error(error.message||'Nie udało się wysłać e-maila.')}return {dev:false,id:data?.id||''};
}
async function sendCampaignToSubscribers(db,c){
  const recipients=marketingSubscribers(db),results=[];
  for(let i=0;i<recipients.length;i+=5){
    const chunk=recipients.slice(i,i+5);const part=await Promise.all(chunk.map(async u=>{try{await sendMarketingCampaignEmail(cleanEmail(u.email),c);return {ok:true}}catch(e){console.error(`Marketing send failed for user ${u.id}:`,e.message);return {ok:false,error:String(e.message||'Błąd wysyłki').slice(0,180)}}}));results.push(...part);
  }
  return {recipientCount:recipients.length,sentCount:results.filter(x=>x.ok).length,failedCount:results.filter(x=>!x.ok).length,errors:results.filter(x=>!x.ok).map(x=>x.error).slice(0,5)};
}


function cleanFaqText(v,max){
  return String(v||'').trim().replace(/\r\n?/g,'\n').slice(0,max);
}
function faqPublicItem(x){
  return {
    id:String(x.id||''),
    question:String(x.question||''),
    answer:String(x.answer||''),
    position:Number.isFinite(Number(x.position))?Number(x.position):999,
    visible:x.visible!==false,
    updatedAt:Number(x.updatedAt||x.createdAt||0)
  };
}
function sortedFaq(db,includeHidden=false){
  ensureStore(db);
  return db.faq
    .filter(x=>includeHidden||x.visible!==false)
    .slice()
    .sort((a,b)=>(Number(a.position||999)-Number(b.position||999))||(Number(a.createdAt||0)-Number(b.createdAt||0)))
    .map(faqPublicItem);
}
app.get('/api/faq',(req,res)=>{
  const db=load();
  const hadFaq=Array.isArray(db.faq);
  ensureStore(db);
  if(!hadFaq)save(db);
  res.setHeader('Cache-Control','no-store');
  res.json({ok:true,faq:sortedFaq(db,false)});
});

// --- STARXV admin panel ---
function adminEmails(){
  return String(process.env.ADMIN_EMAILS||'').split(',').map(cleanEmail).filter(Boolean);
}
function adminOnly(req,res,next){
  adminAuth(req,res,()=>{
    const allowed=adminEmails();
    if(!allowed.length)return res.status(503).json({error:'Panel administratora nie jest skonfigurowany. Dodaj ADMIN_EMAILS do pliku .env.'});
    if(!allowed.includes(cleanEmail(req.user.email)))return res.status(403).json({error:'To konto nie ma dostępu do panelu administratora.'});
    next();
  });
}
function clearAdminCookie(res){res.setHeader('Set-Cookie',`starxv_admin_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${process.env.NODE_ENV==='production'?'; Secure':''}`)}
app.post('/api/admin/login',rateLimit('admin-login',10,15*60*1000),(req,res)=>{
  const email=cleanEmail(req.body?.email),password=String(req.body?.password||'');
  const allowed=adminEmails();
  if(!allowed.length)return res.status(503).json({error:'Panel administratora nie jest skonfigurowany.'});
  if(!allowed.includes(email))return res.status(403).json({error:'To konto nie ma dostępu do panelu administratora.'});
  const db=load(),u=db.users.find(x=>cleanEmail(x.email)===email);
  if(!u||!authMethods(u).includes('email')||!checkPassword(password,u.passwordHash))return res.status(401).json({error:'Nieprawidłowy e-mail lub hasło.'});
  setAdminSession(res,u.id);
  res.json({ok:true,user:publicUser(u)});
});
app.post('/api/admin/google',rateLimit('admin-google',10,15*60*1000),async(req,res)=>{
  try{
    const clientId=googleClientId();
    if(!clientId)return res.status(503).json({error:'Logowanie Google nie jest skonfigurowane.'});
    const accessToken=String(req.body?.accessToken||'').trim();
    const info=await googleTokenInfo(accessToken);
    const audience=String(info.audience||info.issued_to||info.aud||info.azp||'');
    if(audience!==clientId||Number(info.expires_in||0)<=0)return res.status(401).json({error:'Nieprawidłowe lub wygasłe potwierdzenie Google.'});
    const profile=await googleUserInfo(accessToken);
    const email=cleanEmail(profile.email),verified=profile.email_verified===true||String(profile.email_verified)==='true';
    if(!verified||!validEmail(email))return res.status(401).json({error:'Google nie potwierdził adresu e-mail.'});
    const allowed=adminEmails();
    if(!allowed.includes(email))return res.status(403).json({error:'To konto nie ma dostępu do panelu administratora.'});
    const db=load(),u=db.users.find(x=>cleanEmail(x.email)===email);
    if(!u||!authMethods(u).includes('google'))return res.status(401).json({error:'To konto STARXV nie jest skonfigurowane do logowania przez Google.'});
    const storedSub=String(u.googleSub||''),incomingSub=String(profile.sub||'');
    if(storedSub&&incomingSub&&storedSub!==incomingSub)return res.status(401).json({error:'To konto Google nie pasuje do konta STARXV.'});
    if(!storedSub)u.googleSub=incomingSub;
    save(db);
    setAdminSession(res,u.id);
    res.json({ok:true,user:publicUser(u)});
  }catch(e){
    console.error('Admin Google login error:',e);
    res.status(401).json({error:e?.message||'Nie udało się zalogować do panelu przez Google.'});
  }
});
app.post('/api/admin/logout',(req,res)=>{
  const t=cookie(req,'starxv_admin_session');
  if(t)deleteSessionToken(t);
  clearAdminCookie(res);
  res.json({ok:true});
});


function adminTitleUserRow(u){
  return {
    id:u.id,
    email:u.email,
    firstName:u.firstName||'',
    lastName:u.lastName||'',
    title:accountTitleData(u)
  };
}
app.get('/api/admin/user-titles',adminOnly,(req,res)=>{
  const assignments=(req.db.users||[])
    .filter(u=>accountTitleData(u))
    .map(adminTitleUserRow)
    .sort((a,b)=>String(a.email).localeCompare(String(b.email),'pl'));
  res.json({
    ok:true,
    presets:Object.entries(ACCOUNT_TITLE_PRESETS).map(([key,v])=>({key,label:v.label,name:v.name})),
    assignments
  });
});
app.post('/api/admin/user-titles',adminOnly,(req,res)=>{
  const email=cleanEmail(req.body?.email);
  const key=String(req.body?.key||'').trim().toLowerCase();
  if(!validEmail(email))return res.status(400).json({error:'Podaj prawidłowy adres e-mail.'});
  if(!Object.prototype.hasOwnProperty.call(ACCOUNT_TITLE_PRESETS,key))return res.status(400).json({error:'Nieprawidłowy typ tytułu.'});
  const user=(req.db.users||[]).find(u=>cleanEmail(u.email)===email);
  if(!user)return res.status(404).json({error:'Nie znaleziono konta STARXV z takim adresem e-mail.'});
  const label=key==='custom'
    ?cleanAccountTitleLabel(req.body?.label)
    :ACCOUNT_TITLE_PRESETS[key].label;
  if(label.length<2)return res.status(400).json({error:'Wpisz tytuł mający co najmniej 2 znaki.'});
  user.displayTitle={key,label,assignedAt:Date.now(),assignedBy:req.user.id};
  save(req.db);
  res.json({ok:true,user:adminTitleUserRow(user)});
});
app.delete('/api/admin/user-titles/:userId',adminOnly,(req,res)=>{
  const user=(req.db.users||[]).find(u=>String(u.id)===String(req.params.userId));
  if(!user)return res.status(404).json({error:'Nie znaleziono konta.'});
  delete user.displayTitle;
  save(req.db);
  res.json({ok:true});
});


app.get('/api/admin/faq',adminOnly,(req,res)=>{
  ensureStore(req.db);
  res.setHeader('Cache-Control','no-store');
  res.json({ok:true,faq:sortedFaq(req.db,true)});
});

app.post('/api/admin/faq',adminOnly,async(req,res)=>{
  try{
    ensureStore(req.db);
    const question=cleanFaqText(req.body?.question,180);
    const answer=cleanFaqText(req.body?.answer,1800);
    const position=Math.max(1,Math.min(9999,Math.trunc(Number(req.body?.position)||req.db.faq.length+1)));
    const visible=req.body?.visible!==false;
    if(question.length<3)return res.status(400).json({error:'Pytanie musi mieć co najmniej 3 znaki.'});
    if(answer.length<3)return res.status(400).json({error:'Odpowiedź musi mieć co najmniej 3 znaki.'});
    const now=Date.now(),item={id:crypto.randomUUID(),question,answer,position,visible,createdAt:now,updatedAt:now};
    req.db.faq.push(item);
    await Promise.resolve(save(req.db));
    res.json({ok:true,item:faqPublicItem(item),faq:sortedFaq(req.db,true)});
  }catch(err){
    console.error('FAQ create error:',err);
    res.status(500).json({error:'Nie udało się dodać pytania FAQ.'});
  }
});

app.put('/api/admin/faq/:id',adminOnly,async(req,res)=>{
  try{
    ensureStore(req.db);
    const item=req.db.faq.find(x=>String(x.id)===String(req.params.id));
    if(!item)return res.status(404).json({error:'Nie znaleziono pytania FAQ.'});
    const question=cleanFaqText(req.body?.question,180);
    const answer=cleanFaqText(req.body?.answer,1800);
    const position=Math.max(1,Math.min(9999,Math.trunc(Number(req.body?.position)||1)));
    if(question.length<3)return res.status(400).json({error:'Pytanie musi mieć co najmniej 3 znaki.'});
    if(answer.length<3)return res.status(400).json({error:'Odpowiedź musi mieć co najmniej 3 znaki.'});
    item.question=question;
    item.answer=answer;
    item.position=position;
    item.visible=req.body?.visible!==false;
    item.updatedAt=Date.now();
    await Promise.resolve(save(req.db));
    res.json({ok:true,item:faqPublicItem(item),faq:sortedFaq(req.db,true)});
  }catch(err){
    console.error('FAQ update error:',err);
    res.status(500).json({error:'Nie udało się zapisać pytania FAQ.'});
  }
});

app.delete('/api/admin/faq/:id',adminOnly,async(req,res)=>{
  try{
    ensureStore(req.db);
    const before=req.db.faq.length;
    req.db.faq=req.db.faq.filter(x=>String(x.id)!==String(req.params.id));
    if(req.db.faq.length===before)return res.status(404).json({error:'Nie znaleziono pytania FAQ.'});
    await Promise.resolve(save(req.db));
    res.json({ok:true,faq:sortedFaq(req.db,true)});
  }catch(err){
    console.error('FAQ delete error:',err);
    res.status(500).json({error:'Nie udało się usunąć pytania FAQ.'});
  }
});

app.get('/api/admin/site-settings',adminOnly,(req,res)=>{
  ensureStore(req.db);
  res.setHeader('Cache-Control','no-store');
  res.json({ok:true,releaseVersion:req.db.siteSettings.releaseVersion,comingLater:Array.isArray(req.db.siteSettings.comingLater)?req.db.siteSettings.comingLater:[]});
});

app.patch('/api/admin/site-settings',adminOnly,async(req,res)=>{
  try{
    ensureStore(req.db);
    const releaseVersion=cleanReleaseVersion(req.body?.releaseVersion);
    if(!releaseVersion)return res.status(400).json({error:'Wpisz wersję, która ma być wyświetlana w profilu.'});
    req.db.siteSettings.releaseVersion=releaseVersion;
    await Promise.resolve(save(req.db));
    res.setHeader('Cache-Control','no-store');
    res.json({ok:true,releaseVersion});
  }catch(err){
    console.error('Site settings save error:',err);
    res.status(500).json({error:'Nie udało się zapisać ustawień strony w bazie.'});
  }
});


const COMING_LATER_ICONS=new Set(['sparkles','book','app','ai','code','laptop','phone','rocket','star','update']);
function cleanComingLaterText(v,max=220){
  return String(v||'').trim().replace(/\s+/g,' ').slice(0,max);
}
function cleanComingLaterIcon(v){
  const key=String(v||'').trim().toLowerCase();
  return COMING_LATER_ICONS.has(key)?key:'sparkles';
}
app.post('/api/admin/coming-later',adminOnly,async(req,res)=>{
  try{
    ensureStore(req.db);
    const title=cleanComingLaterText(req.body?.title,80);
    const description=cleanComingLaterText(req.body?.description,220);
    const icon=cleanComingLaterIcon(req.body?.icon);
    if(title.length<2)return res.status(400).json({error:'Wpisz nazwę pozycji Coming Later.'});
    const item={id:crypto.randomUUID(),title,description,icon,createdAt:Date.now()};
    req.db.siteSettings.comingLater.push(item);

    // W PostgreSQL/Neon save() jest asynchroniczne. Czekamy na faktyczny zapis
    // zanim panel dostanie odpowiedź, żeby po odświeżeniu pozycja nie znikała.
    await Promise.resolve(save(req.db));

    res.setHeader('Cache-Control','no-store');
    res.json({ok:true,item,comingLater:req.db.siteSettings.comingLater});
  }catch(err){
    console.error('Coming Later save error:',err);
    res.status(500).json({error:'Nie udało się zapisać Coming Later w bazie.'});
  }
});
app.delete('/api/admin/coming-later/:id',adminOnly,async(req,res)=>{
  try{
    ensureStore(req.db);
    const before=req.db.siteSettings.comingLater.length;
    req.db.siteSettings.comingLater=req.db.siteSettings.comingLater.filter(x=>String(x?.id)!==String(req.params.id));
    if(req.db.siteSettings.comingLater.length===before)return res.status(404).json({error:'Nie znaleziono tej pozycji.'});

    await Promise.resolve(save(req.db));

    res.setHeader('Cache-Control','no-store');
    res.json({ok:true,comingLater:req.db.siteSettings.comingLater});
  }catch(err){
    console.error('Coming Later delete error:',err);
    res.status(500).json({error:'Nie udało się zapisać zmiany Coming Later w bazie.'});
  }
});


// --- STARXV owner deploy tools ---------------------------------------------------
// Visible only to the first account listed in ADMIN_EMAILS. This section only
// exposes the safe local Git commands used to publish changes. Render Auto-Deploy
// handles the deployment automatically after `git push`.
function deployOwnerEmail(){return cleanEmail(adminEmails()[0]||'')}
function deployOwnerOnly(req,res,next){
  auth(req,res,()=>{
    const owner=deployOwnerEmail();
    if(!owner)return res.status(503).json({error:'Właściciel narzędzi deploy nie jest skonfigurowany.'});
    if(cleanEmail(req.user.email)!==owner)return res.status(403).json({error:'Brak dostępu.'});
    next();
  });
}
app.get('/api/admin/deploy/info',deployOwnerOnly,(req,res)=>{
  res.setHeader('Cache-Control','no-store');
  res.json({
    ok:true,
    commands:[
      'git add .',
      'git commit -m "Update STARXV"',
      'git push'
    ],
    note:'Po git push GitHub otrzyma najnowsze pliki, a Render uruchomi Auto-Deploy automatycznie.'
  });
});

function adminOrder(db,o){
  const u=(db.users||[]).find(x=>x.id===o.userId);
  return {...orderForUser(o,db),customer:u?{firstName:u.firstName,lastName:u.lastName,email:u.email}:{firstName:'',lastName:'',email:''}};
}
app.get('/api/admin/me',adminOnly,(req,res)=>res.json({ok:true,user:publicUser(req.user)}));

app.get('/api/admin/marketing-campaigns',adminOnly,(req,res)=>{
  ensureStore(req.db);const campaigns=req.db.marketingCampaigns.slice().sort((a,b)=>Number(b.createdAt||0)-Number(a.createdAt||0)).slice(0,100);
  res.json({ok:true,subscriberCount:marketingSubscribers(req.db).length,sender:marketingSender(),campaigns});
});
app.post('/api/admin/marketing-campaigns/test',rateLimit('marketing-test',20,60*60*1000),adminOnly,async(req,res)=>{try{
  const campaign=marketingCampaignInput(req.body||{});await sendMarketingCampaignEmail(cleanEmail(req.user.email),campaign);res.json({ok:true,to:cleanEmail(req.user.email),sender:marketingSender()});
}catch(e){res.status(400).json({error:e.message||'Nie udało się wysłać wiadomości testowej.'})}});
app.post('/api/admin/marketing-campaigns',rateLimit('marketing-send',12,60*60*1000),adminOnly,async(req,res)=>{try{
  ensureStore(req.db);const campaign=marketingCampaignInput(req.body||{}),subscribers=marketingSubscribers(req.db);
  if(!subscribers.length)return res.status(400).json({error:'Brak użytkowników z włączonymi powiadomieniami marketingowymi.'});
  const createdAt=Date.now(),record={id:crypto.randomUUID(),...campaign,image:undefined,hasImage:Boolean(campaign.image),imageName:campaign.image?.filename||'',createdAt,createdBy:req.user.id,createdByEmail:cleanEmail(req.user.email),sender:marketingSender(),status:'sending',recipientCount:subscribers.length,sentCount:0,failedCount:0};
  req.db.marketingCampaigns.unshift(record);req.db.marketingCampaigns=req.db.marketingCampaigns.slice(0,200);save(req.db);
  const result=await sendCampaignToSubscribers(req.db,campaign);record.sentCount=result.sentCount;record.failedCount=result.failedCount;record.status=result.failedCount===0?'sent':result.sentCount>0?'partial':'failed';record.sentAt=Date.now();record.errors=result.errors;save(req.db);
  res.json({ok:true,campaign:record});
}catch(e){console.error('Marketing campaign error:',e);res.status(400).json({error:e.message||'Nie udało się wysłać kampanii.'})}});

app.get('/api/admin/reviews',adminOnly,(req,res)=>{ensureStore(req.db);const reviews=req.db.reviews.slice().sort((a,b)=>Number(b.updatedAt||b.createdAt)-Number(a.updatedAt||a.createdAt)).map(r=>({...publicReview(req.db,r),visible:r.visible!==false,email:(req.db.users||[]).find(u=>u.id===r.userId)?.email||''}));res.json({ok:true,reviews})});
app.patch('/api/admin/reviews/:id',adminOnly,(req,res)=>{ensureStore(req.db);const r=req.db.reviews.find(x=>x.id===req.params.id);if(!r)return res.status(404).json({error:'Nie znaleziono opinii.'});if(Object.prototype.hasOwnProperty.call(req.body||{},'visible'))r.visible=Boolean(req.body.visible);r.updatedAt=Date.now();save(req.db);res.json({ok:true,review:{...publicReview(req.db,r),visible:r.visible!==false}})});
app.delete('/api/admin/reviews/:id',adminOnly,(req,res)=>{ensureStore(req.db);const before=req.db.reviews.length;req.db.reviews=req.db.reviews.filter(x=>x.id!==req.params.id);if(req.db.reviews.length===before)return res.status(404).json({error:'Nie znaleziono opinii.'});save(req.db);res.json({ok:true})});

app.get('/api/admin/dashboard',adminOnly,(req,res)=>{
  ensureStore(req.db);expirePendingOrders(req.db);
  const orders=req.db.orders.filter(o=>o.orderType==='digital'&&o.paymentStatus!=='expired').map(o=>adminOrder(req.db,o)).sort((a,b)=>b.createdAt-a.createdAt);
  const paid=orders.filter(o=>o.paymentStatus==='paid');
  res.json({ok:true,digitalProducts:req.db.digitalProducts||{},digitalCategories:req.db.digitalCategories||[],orders,stats:{orders:orders.length,pending:orders.filter(o=>o.paymentStatus==='pending').length,paid:paid.length,revenue:Math.round(paid.reduce((sum,o)=>sum+Number(o.total||0),0)*100)/100}});
});

function cleanSlug(v,label='ID'){
  const s=String(v||'').trim().toLowerCase().replace(/\s+/g,'-');
  if(!/^[a-z0-9][a-z0-9-]{1,59}$/.test(s))throw new Error(`${label} może zawierać małe litery, cyfry i myślniki (2–60 znaków).`);
  return s;
}
function cleanSize(v){
  const s=String(v||'').trim().toUpperCase();
  if(!/^[A-Z0-9+\-]{1,20}$/.test(s))throw new Error('Rozmiar może zawierać litery, cyfry, + i -.');
  return s;
}

function cleanDigitalPayload(body={},existing=null){
  const id=cleanSlug(body.id??existing?.id,'ID produktu cyfrowego');
  const name=String(body.name??existing?.name??'').trim().slice(0,160);
  const subtitle=String(body.subtitle??existing?.subtitle??'').trim().slice(0,220);
  const description=String(body.description??existing?.description??'').trim().slice(0,2000);
  const meta=String(body.meta??existing?.meta??'STARXV DIGITAL / E-BOOK').trim().slice(0,120);
  const defaultPoints=['Produkt cyfrowy PDF','Dostęp po potwierdzeniu płatności','Przypisany do konta STARXV','Pobieranie z biblioteki zamówień'];
  const rawPoints=Array.isArray(body.points)?body.points:(Array.isArray(existing?.points)?existing.points:defaultPoints);
  const points=rawPoints.map(x=>String(x||'').trim().slice(0,160)).filter(Boolean).slice(0,4);
  while(points.length<4)points.push(defaultPoints[points.length]);
  const price=Number(body.price??existing?.price??0);
  const discountPercent=Math.min(99,Math.max(0,Number(body.discountPercent??existing?.discountPercent??0)||0));
  const image=String(body.image??existing?.image??'').trim().slice(0,200000);
  const gallery=(Array.isArray(body.gallery)?body.gallery:(existing?.gallery||[])).map(x=>String(x||'').trim().slice(0,200000)).filter(Boolean).slice(0,10);
  const fileName=path.basename(String(body.fileName??existing?.fileName??'').trim()).slice(0,180);
  const downloadName=path.basename(String(body.downloadName??existing?.downloadName??fileName).trim()).slice(0,180);
  const rawPosition=Number(body.position??existing?.position??999);
  const position=Number.isFinite(rawPosition)?Math.max(1,Math.min(999,Math.round(rawPosition))):999;
  const categoryId=String(body.categoryId??existing?.categoryId??'praktyczne').trim().toLowerCase().slice(0,60)||'praktyczne';
  const active=Object.prototype.hasOwnProperty.call(body,'active')?body.active!==false:existing?.active!==false;
  if(!name)throw new Error('Podaj nazwę produktu cyfrowego.');
  if(!Number.isFinite(price)||price<0||price>100000)throw new Error('Podaj prawidłową cenę.');
  if(fileName&&!/\.pdf$/i.test(fileName))throw new Error('Plik produktu cyfrowego musi być plikiem PDF.');
  return {id,position,categoryId,name,subtitle,description,meta:meta||'STARXV DIGITAL / E-BOOK',points,price:money2(price),discountPercent,image,gallery,fileName,downloadName:downloadName||fileName,active,
    offeredAt:Number(existing?.offeredAt||0)||null,priceHistory:Array.isArray(existing?.priceHistory)?existing.priceHistory:[],promotionStartedAt:existing?.promotionStartedAt||null,omnibusReferencePrice:existing?.omnibusReferencePrice??null,omnibusReferenceType:existing?.omnibusReferenceType||null};
}

function cleanDigitalCategoryPayload(body={},existing=null){
  const id=cleanSlug(body.id??existing?.id,'ID kategorii');
  const name=String(body.name??existing?.name??'').trim().replace(/\s+/g,' ').slice(0,80);
  const description=String(body.description??existing?.description??'').trim().slice(0,240);
  const rawPosition=Number(body.position??existing?.position??999);
  const position=Number.isFinite(rawPosition)?Math.max(1,Math.min(999,Math.round(rawPosition))):999;
  const visible=Object.prototype.hasOwnProperty.call(body,'visible')?body.visible!==false:existing?.visible!==false;
  if(!name)throw new Error('Podaj nazwę kategorii.');
  return {id,name,description,position,visible};
}
app.get('/api/admin/digital-categories',adminOnly,(req,res)=>{
  ensureStore(req.db);
  const categories=[...(req.db.digitalCategories||[])].sort((a,b)=>(Number(a.position||999)-Number(b.position||999))||String(a.name||'').localeCompare(String(b.name||''),'pl'));
  res.json({ok:true,categories});
});
app.post('/api/admin/digital-categories',adminOnly,(req,res)=>{try{
  ensureStore(req.db);const data=cleanDigitalCategoryPayload(req.body||{});
  if((req.db.digitalCategories||[]).some(c=>c.id===data.id))return res.status(409).json({error:'Kategoria o takim ID już istnieje.'});
  req.db.digitalCategories.push(data);save(req.db);res.status(201).json({ok:true,category:data});
}catch(e){res.status(400).json({error:e.message||'Nie udało się dodać kategorii.'})}});
app.put('/api/admin/digital-categories/:id',adminOnly,(req,res)=>{try{
  ensureStore(req.db);const id=String(req.params.id||''),category=(req.db.digitalCategories||[]).find(c=>c.id===id);
  if(!category)return res.status(404).json({error:'Nie znaleziono kategorii.'});
  const data=cleanDigitalCategoryPayload({...req.body,id},category);
  Object.assign(category,data);save(req.db);res.json({ok:true,category});
}catch(e){res.status(400).json({error:e.message||'Nie udało się zapisać kategorii.'})}});
app.delete('/api/admin/digital-categories/:id',adminOnly,(req,res)=>{
  ensureStore(req.db);const id=String(req.params.id||''),categories=req.db.digitalCategories||[];
  const current=categories.find(c=>c.id===id);if(!current)return res.status(404).json({error:'Nie znaleziono kategorii.'});
  const remaining=categories.filter(c=>c.id!==id);
  if(!remaining.length)return res.status(409).json({error:'Musi pozostać przynajmniej jedna kategoria e-booków.'});
  const fallback=[...remaining].sort((a,b)=>Number(a.position||999)-Number(b.position||999))[0];
  let reassigned=0;
  for(const p of Object.values(req.db.digitalProducts||{})){if(String(p.categoryId||'')===id){p.categoryId=fallback.id;reassigned++}}
  req.db.digitalCategories=remaining;save(req.db);res.json({ok:true,reassigned,fallbackCategoryId:fallback.id});
});

app.post('/api/admin/digital-products',adminOnly,(req,res)=>{try{
  ensureStore(req.db);const data=cleanDigitalPayload(req.body||{});if(req.db.digitalProducts[data.id])return res.status(409).json({error:'Produkt cyfrowy o takim ID już istnieje.'});
  if(!(req.db.digitalCategories||[]).some(c=>c.id===data.categoryId))return res.status(400).json({error:'Wybrana kategoria e-booka nie istnieje.'});
  const now=Date.now();data.offeredAt=now;data.priceHistory=[];data.promotionStartedAt=null;data.omnibusReferencePrice=null;data.omnibusReferenceType=null;
  // Dla nowego produktu historia zaczyna się od ceny bazowej. Jeśli od razu ustawiono rabat,
  // zapisujemy bazę jako punkt odniesienia i start promocji jako osobne zdarzenie.
  data.discountPercent=0;ensureProductPriceTracking(data,now);
  const requestedDiscount=Math.min(99,Math.max(0,Number(req.body?.discountPercent)||0));
  if(requestedDiscount>0){recordProductPrice(data,Number(data.price),now-1);data.discountPercent=requestedDiscount;setOmnibusReferenceForPromotion(data,now);recordProductPrice(data,effectiveCatalogPrice(data),now)}
  req.db.digitalProducts[data.id]=data;save(req.db);res.status(201).json({ok:true,product:publicDigitalProduct(data,req.db)})
}catch(e){res.status(400).json({error:e.message||'Nie udało się dodać produktu cyfrowego.'})}});
app.put('/api/admin/digital-products/:id',adminOnly,(req,res)=>{try{
  ensureStore(req.db);const id=String(req.params.id||''),current=req.db.digitalProducts[id];if(!current)return res.status(404).json({error:'Nie znaleziono produktu cyfrowego.'});
  const now=Date.now();ensureProductPriceTracking(current,now);
  const beforePrice=effectiveCatalogPrice(current),beforeDiscount=Number(current.discountPercent||0),beforeBase=Number(current.price||0);
  const data=cleanDigitalPayload({...req.body,id},current);
  if(!(req.db.digitalCategories||[]).some(c=>c.id===data.categoryId))return res.status(400).json({error:'Wybrana kategoria e-booka nie istnieje.'});
  const afterPrice=effectiveCatalogPrice(data),afterDiscount=Number(data.discountPercent||0),afterBase=Number(data.price||0);
  const pricingChanged=beforePrice!==afterPrice||beforeDiscount!==afterDiscount||beforeBase!==afterBase;
  if(pricingChanged){
    recordProductPrice(data,beforePrice,now-1);
    if(afterDiscount>0)setOmnibusReferenceForPromotion(data,now);else clearOmnibusPromotion(data);
    recordProductPrice(data,afterPrice,now);
  }
  req.db.digitalProducts[id]=data;save(req.db);res.json({ok:true,product:publicDigitalProduct(data,req.db)})
}catch(e){res.status(400).json({error:e.message||'Nie udało się zapisać produktu cyfrowego.'})}});
app.delete('/api/admin/digital-products/:id',adminOnly,(req,res)=>{ensureStore(req.db);expirePendingOrders(req.db);const id=String(req.params.id||'');if(!req.db.digitalProducts[id])return res.status(404).json({error:'Nie znaleziono produktu cyfrowego.'});const blocking=(req.db.orders||[]).some(o=>o.orderType==='digital'&&o.digitalProductId===id&&o.paymentStatus==='pending');if(blocking)return res.status(409).json({error:'Nie można usunąć produktu z oczekującym zamówieniem.'});delete req.db.digitalProducts[id];save(req.db);res.json({ok:true})});

app.delete('/api/admin/orders/:id',adminOnly,async(req,res)=>{
  try{
    ensureStore(req.db);
    const idx=req.db.orders.findIndex(o=>String(o.id)===String(req.params.id));
    if(idx<0)return res.status(404).json({error:'Nie znaleziono zamówienia.'});
    const order=req.db.orders[idx];

    if(Array.isArray(req.db.returnRequests)){
      req.db.returnRequests=req.db.returnRequests.filter(r=>String(r.orderId)!==String(order.id));
    }

    req.db.orders.splice(idx,1);

    // PostgreSQL zapisuje stan asynchronicznie — czekamy na zapis zanim panel ponownie pobierze dane.
    await Promise.resolve(save(req.db));

    res.json({ok:true,id:order.id,orderNo:order.orderNo});
  }catch(e){
    res.status(400).json({error:e.message||'Nie udało się usunąć zamówienia.'});
  }
});

app.post('/api/admin/orders/bulk-delete',adminOnly,async(req,res)=>{
  try{
    ensureStore(req.db);
    const raw=Array.isArray(req.body?.ids)?req.body.ids:[];
    const ids=[...new Set(raw.map(x=>String(x||'').trim()).filter(Boolean))];
    if(!ids.length)return res.status(400).json({error:'Nie wybrano żadnych zamówień.'});
    if(ids.length>250)return res.status(400).json({error:'Możesz usunąć maksymalnie 250 zamówień jednocześnie.'});

    const wanted=new Set(ids);
    const deleting=req.db.orders.filter(o=>wanted.has(String(o.id)));
    if(!deleting.length)return res.status(404).json({error:'Nie znaleziono wybranych zamówień.'});

    const deletedIds=new Set(deleting.map(o=>String(o.id)));
    req.db.orders=req.db.orders.filter(o=>!deletedIds.has(String(o.id)));

    if(Array.isArray(req.db.returnRequests)){
      req.db.returnRequests=req.db.returnRequests.filter(r=>!deletedIds.has(String(r.orderId)));
    }

    await Promise.resolve(save(req.db));

    res.json({
      ok:true,
      deleted:deleting.length,
      ids:[...deletedIds]
    });
  }catch(e){
    res.status(400).json({error:e.message||'Nie udało się usunąć zaznaczonych zamówień.'});
  }
});

app.put('/api/admin/orders/:id',adminOnly,(req,res)=>{
  try{
    ensureStore(req.db);
    const order=req.db.orders.find(o=>o.id===req.params.id&&o.orderType==='digital');
    if(!order)return res.status(404).json({error:'Nie znaleziono zamówienia cyfrowego.'});
    const beforePayment=String(order.paymentStatus||'pending');
    const requestedStatus=String(req.body?.paymentStatus||'');
    if(requestedStatus){
      if(!['pending','paid','cancelled'].includes(requestedStatus))return res.status(400).json({error:'Nieprawidłowy status płatności.'});
      if(order.paymentStatus==='paid'&&requestedStatus!=='paid')return res.status(400).json({error:'Opłaconego zamówienia nie można cofnąć w tym panelu.'});
      if(order.paymentStatus==='cancelled'&&requestedStatus!=='cancelled')return res.status(400).json({error:'Anulowanego zamówienia nie można ponownie aktywować w tym panelu.'});
      if(requestedStatus==='paid')markOrderPaid(req.db,order);else order.paymentStatus=requestedStatus;
    }
    order.updatedAt=Date.now();
    if(beforePayment!==order.paymentStatus&&order.paymentStatus==='cancelled'){
      orderEvent(order,'cancelled','Zamówienie anulowane','Zamówienie zostało anulowane przez obsługę sklepu.',order.updatedAt);
      sendOrderUpdateEmail(req.db,order,'cancelled',{dedupeKey:'cancelled'});
    }
    save(req.db);res.json({ok:true,order:adminOrder(req.db,order)});
  }catch(e){res.status(400).json({error:e.message||'Nie udało się zaktualizować zamówienia.'})}
});

app.put('/api/account/avatar',auth,(req,res)=>{const avatarData=String(req.body?.avatarData||'');if(avatarData&&!/^data:image\/(jpeg|png|webp);base64,/.test(avatarData))return res.status(400).json({error:'Nieprawidłowy format zdjęcia.'});if(avatarData.length>5_500_000)return res.status(413).json({error:'Zdjęcie jest za duże.'});const i=req.db.users.findIndex(x=>x.id===req.user.id);req.db.users[i].avatarData=avatarData;save(req.db);res.json({ok:true,user:publicUser(req.db.users[i])})});

// STARXV admin — zgłoszenia problemów


app.get('/api/admin/promo-users',adminOnly,(req,res)=>{const users=(req.db.users||[]).map(u=>({id:u.id,firstName:u.firstName||'',lastName:u.lastName||'',email:u.email||''})).sort((a,b)=>String(a.email).localeCompare(String(b.email)));res.json({ok:true,users})});
app.get('/api/admin/promos',adminOnly,(req,res)=>{ensurePromoCodes(req.db);save(req.db);res.json({ok:true,promos:req.db.promoCodes.map(promoPublic).sort((a,b)=>(b.createdAt||0)-(a.createdAt||0))})});
app.post('/api/admin/promos',adminOnly,(req,res)=>{
  ensurePromoCodes(req.db);
  const code=String(req.body?.code||'').trim().toUpperCase().replace(/\s+/g,'');
  const type=String(req.body?.type||'percent'),value=Number(req.body?.value),minSubtotal=Math.max(0,Number(req.body?.minSubtotal||0));
  const productId=String(req.body?.productId||'').trim()||null;
  const usageRaw=req.body?.usageLimit,usageLimit=(usageRaw===null||usageRaw===''||usageRaw===undefined)?null:Math.max(1,Math.floor(Number(usageRaw)));
  if(!/^[A-Z0-9_-]{3,24}$/.test(code))return res.status(400).json({error:'Kod może mieć 3–24 znaki: litery, cyfry, _ lub -.'});
  if(req.db.promoCodes.some(p=>String(p.code||'').toUpperCase()===code))return res.status(409).json({error:'Taki kod już istnieje.'});
  if(!['percent','fixed'].includes(type)||!Number.isFinite(value)||value<=0||(type==='percent'&&value>100))return res.status(400).json({error:'Nieprawidłowa wartość rabatu.'});
  const assignedUserId=String(req.body?.assignedUserId||'').trim()||null;if(assignedUserId&&!req.db.users.some(u=>String(u.id)===assignedUserId))return res.status(400).json({error:'Nie znaleziono wybranego konta klienta.'});
  if(productId&&!req.db.digitalProducts?.[productId])return res.status(400).json({error:'Nie znaleziono wybranego produktu Digital.'});
  const p={id:crypto.randomUUID(),code,type,value:Math.round(value*100)/100,minSubtotal:Math.round(minSubtotal*100)/100,usageLimit,usedCount:0,usedByUserIds:[],assignedUserId,productId,active:req.body?.active!==false,startsAt:req.body?.startsAt||null,endsAt:req.body?.endsAt||null,createdAt:Date.now(),updatedAt:Date.now()};
  req.db.promoCodes.push(p);save(req.db);res.json({ok:true,promo:promoPublic(p)});
});
app.patch('/api/admin/promos/:id',adminOnly,(req,res)=>{
  ensurePromoCodes(req.db);const p=req.db.promoCodes.find(x=>x.id===req.params.id);if(!p)return res.status(404).json({error:'Nie znaleziono kodu.'});
  if(req.body?.active!==undefined)p.active=Boolean(req.body.active);
  if(req.body?.productId!==undefined){const productId=String(req.body.productId||'').trim()||null;if(productId&&!req.db.digitalProducts?.[productId])return res.status(400).json({error:'Nie znaleziono wybranego produktu Digital.'});p.productId=productId}
  if(req.body?.usageLimit!==undefined)p.usageLimit=(req.body.usageLimit===null||req.body.usageLimit==='')?null:Math.max(1,Math.floor(Number(req.body.usageLimit)));
  if(req.body?.minSubtotal!==undefined)p.minSubtotal=Math.max(0,Math.round(Number(req.body.minSubtotal||0)*100)/100);
  if(req.body?.startsAt!==undefined)p.startsAt=req.body.startsAt||null;
  if(req.body?.endsAt!==undefined)p.endsAt=req.body.endsAt||null;
  p.updatedAt=Date.now();save(req.db);res.json({ok:true,promo:promoPublic(p)});
});
app.delete('/api/admin/promos/:id',adminOnly,(req,res)=>{ensurePromoCodes(req.db);const n=req.db.promoCodes.length;req.db.promoCodes=req.db.promoCodes.filter(x=>x.id!==req.params.id);if(req.db.promoCodes.length===n)return res.status(404).json({error:'Nie znaleziono kodu.'});save(req.db);res.json({ok:true})});

app.get('/api/admin/returns',adminOnly,(req,res)=>{ensureReturnRequests(req.db);res.json({ok:true,returns:req.db.returnRequests.slice().sort((a,b)=>b.createdAt-a.createdAt)})});
app.patch('/api/admin/returns/:id',adminOnly,async(req,res)=>{
  ensureReturnRequests(req.db);const rr=req.db.returnRequests.find(x=>x.id===req.params.id);
  if(!rr)return res.status(404).json({error:'Nie znaleziono zgłoszenia.'});
  const status=String(req.body?.status||rr.status),reply=String(req.body?.reply??rr.adminReply??'').trim().slice(0,2000);
  if(!['new','review','accepted','rejected','completed'].includes(status))return res.status(400).json({error:'Nieprawidłowy status.'});
  const changed=status!==rr.status;rr.status=status;rr.adminReply=reply;rr.updatedAt=Date.now();save(req.db);
  if(changed||reply){
    try{
      const key=String(process.env.RESEND_API_KEY||'').trim(),to=cleanEmail(rr.email);
      if(key&&to){const names={new:'Nowe',review:'W trakcie weryfikacji',accepted:'Zaakceptowane',rejected:'Odrzucone',completed:'Zakończone'};const resend=new Resend(key);await resend.emails.send({from:process.env.MAIL_FROM||'STARXV <no-reply@starxv.pl>',to,subject:`STARXV — ${rr.returnNo} • ${names[status]||status}`,text:`Status zgłoszenia ${rr.returnNo}: ${names[status]||status}.${reply?`\n\nOdpowiedź STARXV:\n${reply}`:''}\n\nSzczegóły znajdziesz na swoim koncie STARXV.`})}
    }catch(e){console.error('Return status email error:',e.message)}
  }
  res.json({ok:true,request:rr});
});
app.delete('/api/admin/returns/:id',adminOnly,(req,res)=>{ensureReturnRequests(req.db);const n=req.db.returnRequests.length;req.db.returnRequests=req.db.returnRequests.filter(x=>x.id!==req.params.id);if(req.db.returnRequests.length===n)return res.status(404).json({error:'Nie znaleziono zgłoszenia.'});save(req.db);res.json({ok:true})});

app.get('/api/admin/support-reports',adminOnly,(req,res)=>{
  const reports=(Array.isArray(req.db.supportReports)?req.db.supportReports:[]).map(r=>{
    const messages=supportMessages(r);
    const lastCustomer=[...messages].reverse().find(m=>m.author==='customer');
    const adminUnread=Boolean(lastCustomer && (!r.supportReadAt || new Date(r.supportReadAt)<new Date(lastCustomer.createdAt||0)));
    return {...r,messages,adminUnread};
  });
  res.json({ok:true,reports});
});

app.post('/api/admin/support-reports/:id/read',adminOnly,(req,res)=>{
  const report=(Array.isArray(req.db.supportReports)?req.db.supportReports:[]).find(r=>r.id===req.params.id);
  if(!report)return res.status(404).json({error:'Nie znaleziono zgłoszenia.'});
  report.supportReadAt=new Date().toISOString();save(req.db);res.json({ok:true});
});

app.patch('/api/admin/support-reports/:id',adminOnly,(req,res)=>{
  const reports=Array.isArray(req.db.supportReports)?req.db.supportReports:[];
  const report=reports.find(x=>x.id===req.params.id);
  if(!report)return res.status(404).json({error:'Nie znaleziono zgłoszenia.'});
  const status=String(req.body?.status||'');
  if(!['new','progress','resolved'].includes(status))return res.status(400).json({error:'Nieprawidłowy status.'});
  report.status=status;if(status!=='resolved')report.closedByCustomer=false;report.updatedAt=new Date().toISOString();save(req.db);
  res.json({ok:true,report});
});

app.post('/api/admin/support-reports/:id/reply',adminOnly,async(req,res)=>{
  const reports=Array.isArray(req.db.supportReports)?req.db.supportReports:[];
  const report=reports.find(x=>x.id===req.params.id);
  if(!report)return res.status(404).json({error:'Nie znaleziono zgłoszenia.'});
  const reply=String(req.body?.reply||'').trim().slice(0,2000);
  if(reply.length<2)return res.status(400).json({error:'Wpisz odpowiedź dla klienta.'});
  const repliedAt=new Date().toISOString();
  supportMessages(report).push({id:crypto.randomUUID(),author:'support',authorUserId:req.user.id,authorTitle:accountTitleData(req.user),text:reply,createdAt:repliedAt});
  report.customerReadAt=null;
  report.supportReadAt=repliedAt;
  report.closedByCustomer=false;
  report.updatedAt=repliedAt;
  if((report.status||'new')==='new')report.status='progress';
  save(req.db);

  const key=String(process.env.RESEND_API_KEY||'').trim();
  if(key&&report.email){
    try{
      const resend=new Resend(key);
      await resend.emails.send({
        from:process.env.SUPPORT_FROM||'STARXV Support <kontakt@starxv.pl>',
        to:report.email,
        replyTo:'kontakt@starxv.pl',
        subject:`STARXV Support — odpowiedź ${report.ticketNo||''}`,
        text:`Cześć,\n\nSTARXV Support odpowiedział na Twoje zgłoszenie ${report.ticketNo||''}.\n\n${reply}\n\nStatus: ${report.status==='resolved'?'Rozwiązane':'W trakcie'}\n\nOdpowiedź zobaczysz również po zalogowaniu w Profil → Zgłoś problem.`
      });
    }catch(err){console.error('Support reply email error:',err?.message||err)}
  }
  res.json({ok:true,report});
});

app.delete('/api/admin/support-reports/:id',adminOnly,(req,res)=>{
  if(!Array.isArray(req.db.supportReports))req.db.supportReports=[];
  const n=req.db.supportReports.length;
  req.db.supportReports=req.db.supportReports.filter(x=>x.id!==req.params.id);
  if(req.db.supportReports.length===n)return res.status(404).json({error:'Nie znaleziono zgłoszenia.'});
  save(req.db);res.json({ok:true});
});

// Explicit SEO endpoints: return crawler-friendly 200 responses and MIME types.
app.get('/robots.txt',(req,res)=>{
  res.status(200).type('text/plain; charset=utf-8').set('Cache-Control','public, max-age=300').sendFile(path.join(__dirname,'public','robots.txt'));
});
app.get('/sitemap.xml',(req,res)=>{
  res.status(200).type('application/xml; charset=utf-8').set('Cache-Control','public, max-age=300').sendFile(path.join(__dirname,'public','sitemap.xml'));
});

app.get(['/privacy','/privacy/','/privacy.html'],(req,res)=>res.sendFile(path.join(__dirname,'public','privacy.html')));
app.get(['/admin','/admin/'],(req,res)=>res.sendFile(path.join(__dirname,'public','admin.html')));
app.use('/assets',express.static(path.join(__dirname,'public','assets'),{maxAge:'1y',immutable:true}));
app.use(express.static(path.join(__dirname,'public'),{extensions:['html']}));

app.get('/{*splat}', (req,res) => {
  res.sendFile(path.join(__dirname,'public','index.html'));
});
initPersistence()
  .then(()=>{
    cleanupExpiredSessions();
    app.listen(PORT,()=>console.log(`STARXV działa na http://localhost:${PORT} [${persistenceMode}]`));
  })
  .catch(err=>{
    console.error('STARXV nie uruchomił się:',err);
    process.exit(1);
  });
