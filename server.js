'use strict';

require('dotenv').config();
const { Resend } = require('resend');

const express=require('express');const fs=require('fs');const path=require('path');const crypto=require('crypto');const nodemailer=require('nodemailer');
const app=express(),PORT=Number(process.env.PORT||3000);
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
  res.setHeader('Cross-Origin-Opener-Policy','same-origin');
  res.setHeader('Cross-Origin-Resource-Policy','same-origin');
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

async function initPostgres(){
  const {Pool}=require('pg');
  pgPool=new Pool({
    connectionString:String(process.env.DATABASE_URL||'').trim(),
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

let stripeClient=null;
function getStripe(){
  const key=String(process.env.STRIPE_SECRET_KEY||'').trim();
  if(!key)return null;
  if(!stripeClient){
    try{stripeClient=require('stripe')(key)}catch(e){
      console.error('Stripe package error:',e.message);
      return null;
    }
  }
  return stripeClient;
}

// Stripe requires the untouched/raw request body for webhook signature verification.
// Keep this route BEFORE express.json().
app.post('/api/stripe/webhook',express.raw({type:'application/json'}),handleStripeWebhook);
app.use(express.json({limit:'5mb'}));

// Browser CSRF protection: unsafe API calls must come from this site. Requests
// without Origin (server-to-server tools) are still allowed; Stripe has its own
// signed webhook route above this middleware.
app.use('/api',(req,res,next)=>{
  if(!['POST','PUT','PATCH','DELETE'].includes(req.method))return next();
  const origin=String(req.headers.origin||'').trim();
  if(!origin)return next();
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
app.use('/api/orders/prepare',rateLimit('prepare-order',40,10*60*1000));
app.use('/api/create-checkout-session',rateLimit('checkout',25,10*60*1000));
function cleanEmail(v){return String(v||'').trim().toLowerCase()}function publicUser(u){return {id:u.id,firstName:u.firstName,lastName:u.lastName,email:u.email,createdAt:u.createdAt,avatarData:u.avatarData||''}}
function hashPassword(password,salt=crypto.randomBytes(16).toString('hex')){const hash=crypto.scryptSync(password,salt,64).toString('hex');return `${salt}:${hash}`}
function checkPassword(password,stored){try{const [salt,hex]=stored.split(':');const a=Buffer.from(hex,'hex'),b=crypto.scryptSync(password,salt,64);return a.length===b.length&&crypto.timingSafeEqual(a,b)}catch{return false}}
function codeHash(email,code){return crypto.createHash('sha256').update(email+'|'+code).digest('hex')}
function cookie(req,name){const m=String(req.headers.cookie||'').split(';').map(x=>x.trim().split('='));const p=m.find(x=>x[0]===name);return p?decodeURIComponent(p.slice(1).join('=')):''}
function sessionKey(token){return crypto.createHash('sha256').update(String(token||'')).digest('hex')}
function deleteSessionToken(token){if(!token)return;sqliteDeleteSession.run(sessionKey(token));sqliteDeleteSession.run(token)}
function setSession(res,userId){const token=crypto.randomBytes(32).toString('hex'),now=Date.now(),expires=now+1000*60*60*24*14;sqliteInsertSession.run(sessionKey(token),userId,expires,now);res.setHeader('Cache-Control','no-store');res.setHeader('Set-Cookie',`starxv_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=1209600${process.env.NODE_ENV==='production'?'; Secure':''}`)}
function auth(req,res,next){const t=cookie(req,'starxv_session');if(!t)return res.status(401).json({error:'Musisz się zalogować.'});const key=sessionKey(t);let s=sqliteGetSession.get(key);if(!s){const legacy=sqliteGetSession.get(t);if(legacy){sqliteDeleteSession.run(t);sqliteInsertSession.run(key,legacy.userId,legacy.expires,Date.now());s=sqliteGetSession.get(key)}}if(!s||s.expires<Date.now()){deleteSessionToken(t);return res.status(401).json({error:'Musisz się zalogować.'})}const db=load(),u=db.users.find(x=>x.id===s.userId);if(!u){deleteSessionToken(t);return res.status(401).json({error:'Sesja wygasła.'})}res.setHeader('Cache-Control','no-store');req.user=u;req.db=db;req.sessionToken=t;req.sessionKey=key;next()}
function validEmail(v){return v.length<=320&&/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)}
function validPassword(v){return v.length>=8&&v.length<=256}
function cleanName(v){return String(v||'').trim().replace(/\s+/g,' ').slice(0,80)}
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
  const user=db.users.find(u=>u.email===email);
  if(!user){save(db);return res.json(generic)}
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
  const reset=db.passwordResets.find(x=>x.email===email),user=db.users.find(u=>u.email===email);
  if(!reset||!user||reset.userId!==user.id)return res.status(400).json({error:'Kod jest nieprawidłowy lub wygasł. Wyślij nowy kod.'});
  if(reset.attempts>=5){db.passwordResets=db.passwordResets.filter(x=>x.email!==email);save(db);return res.status(429).json({error:'Za dużo błędnych prób. Wyślij nowy kod.'})}
  if(reset.codeHash!==codeHash(email,code)){reset.attempts++;save(db);return res.status(400).json({error:'Nieprawidłowy kod.'})}
  user.passwordHash=hashPassword(password);db.passwordResets=db.passwordResets.filter(x=>x.email!==email);save(db);invalidateUserSessions(user.id);
  res.setHeader('Set-Cookie',`starxv_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${process.env.NODE_ENV==='production'?'; Secure':''}`);res.json({ok:true});
});
app.post('/api/auth/register',async(req,res)=>{try{let {firstName,lastName,email,password}=req.body||{};firstName=cleanName(firstName);lastName=cleanName(lastName);email=cleanEmail(email);password=String(password||'');if(!firstName||!lastName||!validEmail(email)||!validPassword(password))return res.status(400).json({error:'Sprawdź dane. Hasło musi mieć 8–256 znaków.'});const db=load();if(db.users.some(u=>u.email===email))return res.status(409).json({error:'Konto z tym adresem e-mail już istnieje.'});const now=Date.now();db.pending=(db.pending||[]).filter(p=>p.expiresAt>now&&p.email!==email);const code=String(crypto.randomInt(100000,1000000));db.pending.push({email,firstName,lastName,passwordHash:hashPassword(password),codeHash:codeHash(email,code),expiresAt:now+10*60*1000,attempts:0,createdAt:now});save(db);const sent=await sendCode(email,code);res.json({ok:true,expiresIn:600,developmentCode:sent.dev?code:undefined})}catch(e){console.error(e);res.status(500).json({error:'Nie udało się wysłać kodu. Spróbuj ponownie.'})}});
app.post('/api/auth/verify',(req,res)=>{const email=cleanEmail(req.body?.email),code=String(req.body?.code||'').replace(/\D/g,'');const db=load(),now=Date.now(),p=db.pending.find(x=>x.email===email);if(!p||p.expiresAt<now)return res.status(400).json({error:'Kod wygasł. Wróć do rejestracji i wyślij nowy.'});if(p.attempts>=5)return res.status(429).json({error:'Za dużo błędnych prób. Wyślij nowy kod.'});if(p.codeHash!==codeHash(email,code)){p.attempts++;save(db);return res.status(400).json({error:'Nieprawidłowy kod.'})}if(db.users.some(u=>u.email===email))return res.status(409).json({error:'To konto już istnieje.'});const u={id:crypto.randomUUID(),firstName:p.firstName,lastName:p.lastName,email,passwordHash:p.passwordHash,createdAt:now,avatarData:'',favorites:[],addresses:[],defaultAddressId:'',cart:[]};db.users.push(u);db.pending=db.pending.filter(x=>x.email!==email);save(db);setSession(res,u.id);res.json({ok:true,user:publicUser(u)})});
app.post('/api/auth/login',(req,res)=>{const email=cleanEmail(req.body?.email),password=String(req.body?.password||'');if(!validEmail(email)||password.length>256)return res.status(401).json({error:'Nieprawidłowy e-mail lub hasło.'});const db=load(),u=db.users.find(x=>x.email===email);if(!u||!checkPassword(password,u.passwordHash))return res.status(401).json({error:'Nieprawidłowy e-mail lub hasło.'});setSession(res,u.id);res.json({ok:true,user:publicUser(u)})});
app.post('/api/auth/logout',(req,res)=>{const t=cookie(req,'starxv_session');if(t)deleteSessionToken(t);res.setHeader('Set-Cookie',`starxv_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${process.env.NODE_ENV==='production'?'; Secure':''}`);res.json({ok:true})});
app.get('/api/auth/me',auth,(req,res)=>res.json({user:publicUser(req.user)}));


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

// Permanently delete the currently logged-in STARXV account.
// Existing paid/order records are kept as standalone store records, but the account itself
// (profile, saved addresses, favorites, avatar and password hash) is removed.
app.delete('/api/account',auth,(req,res)=>{
  const password=String(req.body?.password||'');
  if(!password)return res.status(400).json({error:'Wpisz hasło, aby usunąć konto.'});
  if(!checkPassword(password,req.user.passwordHash))return res.status(401).json({error:'Nieprawidłowe hasło.'});

  const userId=req.user.id;
  const email=req.user.email;
  ensureStore(req.db);

  // Unpaid draft orders can be discarded; completed/paid records stay in the shop records.
  req.db.orders=(req.db.orders||[]).filter(o=>!(o.userId===userId && String(o.paymentStatus||'pending')!=='paid'));
  req.db.users=(req.db.users||[]).filter(u=>u.id!==userId);
  req.db.pending=(req.db.pending||[]).filter(p=>cleanEmail(p.email)!==cleanEmail(email));
  save(req.db);

  invalidateUserSessions(userId);
  res.setHeader('Set-Cookie',`starxv_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${process.env.NODE_ENV==='production'?'; Secure':''}`);
  res.json({ok:true});
});

// Account preferences stored on the backend (favorites + saved addresses).
function accountPreferences(u){
  return {
    favorites:Array.isArray(u.favorites)?u.favorites:[],
    addresses:Array.isArray(u.addresses)?u.addresses:[],
    defaultAddressId:String(u.defaultAddressId||''),
    cart:Array.isArray(u.cart)?u.cart:[]
  };
}
function cleanFavorites(value){
  if(!Array.isArray(value)) return [];
  return [...new Set(value.map(x=>String(x||'').trim()).filter(Boolean))].slice(0,200);
}
function cleanCart(value){
  if(!Array.isArray(value)) return [];
  return value.slice(0,50).map(x=>({
    id:String(x?.id||'').trim().slice(0,120),
    name:String(x?.name||'').trim().slice(0,180),
    fit:String(x?.fit||'').trim().slice(0,80),
    price:Math.max(0,Math.min(100000,Number(x?.price)||0)),
    color:String(x?.color||'').trim().slice(0,80),
    colorLabel:String(x?.colorLabel||'').trim().slice(0,100),
    size:String(x?.size||'').trim().toUpperCase().slice(0,20),
    qty:Math.max(1,Math.min(20,Number(x?.qty||1)|0)),
    selected:x?.selected!==false,
    stockLimit:Math.max(0,Math.min(100000,Number(x?.stockLimit)||0)),
    image:String(x?.image||'').trim().slice(0,2048)
  })).filter(x=>x.id&&x.color&&x.size);
}
function cleanAddresses(value){
  if(!Array.isArray(value)) return [];
  return value.slice(0,20).map(a=>({
    id:String(a?.id||crypto.randomUUID()).slice(0,120),
    firstName:String(a?.firstName||'').trim().slice(0,80),
    lastName:String(a?.lastName||'').trim().slice(0,80),
    email:cleanEmail(a?.email).slice(0,160),
    phone:String(a?.phone||'').trim().slice(0,40),
    street:String(a?.street||'').trim().slice(0,160),
    postal:String(a?.postal||'').trim().slice(0,20),
    city:String(a?.city||'').trim().slice(0,100)
  }));
}
app.get('/api/account/preferences',auth,(req,res)=>{
  res.json({ok:true,preferences:accountPreferences(req.user)});
});

// Dedicated cart endpoints: cart persistence should not depend on the broader
// preferences synchronization used by favorites and addresses.
app.get('/api/account/cart',auth,(req,res)=>{
  res.json({ok:true,cart:Array.isArray(req.user.cart)?req.user.cart:[]});
});
app.put('/api/account/cart',auth,(req,res)=>{
  const i=req.db.users.findIndex(x=>x.id===req.user.id);
  if(i<0)return res.status(401).json({error:'Sesja wygasła.'});
  req.db.users[i].cart=cleanCart(req.body?.cart);
  save(req.db);
  res.json({ok:true,cart:req.db.users[i].cart});
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
  if(report.supportReply && !report.messages.some(m=>m.legacySupportReply)){
    report.messages.push({
      id:crypto.randomUUID(),
      author:'support',
      text:String(report.supportReply),
      createdAt:report.supportRepliedAt||report.updatedAt||report.createdAt||new Date().toISOString(),
      legacySupportReply:true
    });
  }
  return report.messages;
}
function supportForUser(report){
  const messages=supportMessages(report).map(m=>({
    id:m.id,author:m.author==='support'?'support':'customer',
    text:String(m.text||''),createdAt:m.createdAt||report.createdAt
  }));
  const lastSupport=[...messages].reverse().find(m=>m.author==='support');
  const unread=Boolean(lastSupport && (!report.customerReadAt || new Date(report.customerReadAt)<new Date(lastSupport.createdAt||0)));
  return {
    id:report.id,ticketNo:report.ticketNo||'',type:report.type,description:report.description,
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
  if(description.length<5)return res.status(400).json({error:'Opisz problem trochę dokładniej.'});

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
        from:process.env.MAIL_FROM||'STARXV <no-reply@starxv.pl>',
        to:'kontakt@starxv.pl',
        replyTo:req.user.email,
        subject:`STARXV — zgłoszenie problemu: ${type}`,
        text:`Nowe zgłoszenie STARXV\n\nTyp: ${type}\nKonto: ${req.user.email}\nStrona: ${page}\nData: ${report.createdAt}\n\nOpis:\n${description}`
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
  if(Object.prototype.hasOwnProperty.call(body,'favorites')) current.favorites=cleanFavorites(body.favorites);
  if(Object.prototype.hasOwnProperty.call(body,'addresses')) current.addresses=cleanAddresses(body.addresses);
  if(Object.prototype.hasOwnProperty.call(body,'defaultAddressId')) current.defaultAddressId=String(body.defaultAddressId||'').slice(0,120);
  if(Object.prototype.hasOwnProperty.call(body,'cart')) current.cart=cleanCart(body.cart);
  const ids=new Set((current.addresses||[]).map(a=>a.id));
  if(current.defaultAddressId&&!ids.has(current.defaultAddressId)) current.defaultAddressId='';
  save(req.db);
  res.json({ok:true,preferences:accountPreferences(current)});
});


// --- STARXV backend catalog, inventory and orders ---
const DEFAULT_CATALOG={
  'black-hoodie-graffiti':{name:'Hoodie x Graffiti - Fantastic Style',price:129,fit:'RELAXED FIT',category:'hoodies',image:'',colors:{black:{label:'Czarny',sizes:{S:8,M:12,L:6,XL:4}},pink:{label:'Różowy',sizes:{S:5,M:7,L:3,XL:2}},blue:{label:'Jasny niebieski',sizes:{S:4,M:6,L:5,XL:3}}}},
  'oversized-white-shirt':{name:'T-Shirt Different Reality.',price:99,fit:'OVERSIZED FIT',category:'tshirts',image:'',colors:{white:{label:'Biały',sizes:{S:8,M:12,L:8,XL:5}},blue:{label:'Jasny niebieski',sizes:{S:6,M:8,L:6,XL:4}},purple:{label:'Fioletowy',sizes:{S:5,M:7,L:5,XL:3}}}}
};
function ensureStore(db){
  // Seed the starter catalog only once. Do not recreate products that an admin deliberately deleted.
  if(!db.catalog||typeof db.catalog!=='object')db.catalog=JSON.parse(JSON.stringify(DEFAULT_CATALOG));
  if(!Array.isArray(db.orders))db.orders=[];
  return db;
}
function publicCatalog(db){ensureStore(db);return db.catalog}
function safeOrderAddress(a){return {id:String(a?.id||'').slice(0,120),firstName:String(a?.firstName||'').trim().slice(0,80),lastName:String(a?.lastName||'').trim().slice(0,80),email:cleanEmail(a?.email).slice(0,160),phone:String(a?.phone||'').trim().slice(0,40),street:String(a?.street||'').trim().slice(0,160),postal:String(a?.postal||'').trim().slice(0,20),city:String(a?.city||'').trim().slice(0,100)} }
function normalizeOrderItems(db,items){
  ensureStore(db);if(!Array.isArray(items)||!items.length)throw new Error('Koszyk jest pusty.');if(items.length>30)throw new Error('Za dużo pozycji w koszyku.');
  return items.map(raw=>{const id=String(raw?.id||''),color=String(raw?.color||''),size=String(raw?.size||'').toUpperCase(),qty=Math.max(1,Math.min(20,Number(raw?.qty||1)|0));const product=db.catalog[id],variant=product?.colors?.[color],stock=Number(variant?.sizes?.[size]);if(!product||!variant||!Number.isFinite(stock))throw new Error('Nieprawidłowy wariant produktu.');if(qty>stock)throw new Error(`Brak wystarczającego stanu: ${product.name} ${variant.label} / ${size}. Dostępne: ${stock} szt.`);return {id,name:product.name,fit:product.fit,color,colorLabel:variant.label,size,qty,price:Number(product.price),stockLimit:stock,image:String(raw?.image||'').slice(0,5_500_000)}})
}
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
    if(order.paymentStatus==='paid'&&Number(order.shippingStage||0)>0){
      const names=['Nowe','W przygotowaniu','Nadane','W drodze','Dostarczone'];
      const stage=Math.max(0,Math.min(4,Number(order.shippingStage||0)));
      orderEvent(order,`shipping_${stage}`,names[stage],'Aktualny etap realizacji zamówienia.',order.updatedAt||Date.now());
    }
  }
  return order.timeline.slice().sort((a,b)=>Number(a.at||0)-Number(b.at||0));
}
function orderForUser(o){return {id:o.id,orderNo:o.orderNo,createdAt:o.createdAt,updatedAt:o.updatedAt||o.createdAt,items:o.items,address:o.address,delivery:o.delivery,paymentPreference:o.paymentPreference||'',paymentStatus:o.paymentStatus||'pending',shippingStage:Number(o.shippingStage||0),total:Number(o.total||0),trackingNumber:String(o.trackingNumber||''),carrier:String(o.carrier||''),carrierStatus:String(o.carrierStatus||''),inpostShipmentId:o.inpostShipmentId||null,trackingUpdatedAt:Number(o.trackingUpdatedAt||0),timeline:ensureOrderTimeline(o)}}
function decrementStockForOrder(db,order){if(order.stockCommitted)return;for(const x of order.items){const slot=db.catalog?.[x.id]?.colors?.[x.color]?.sizes;if(!slot||Number(slot[x.size])<Number(x.qty))throw new Error('Stan magazynowy zmienił się przed potwierdzeniem płatności.');slot[x.size]-=Number(x.qty)}order.stockCommitted=true;order.stockCommittedAt=Date.now()}
function reserveStockForOrder(db,order){
  if(order.stockCommitted||order.stockReserved)return;
  for(const x of order.items){const slot=db.catalog?.[x.id]?.colors?.[x.color]?.sizes;if(!slot||Number(slot[x.size])<Number(x.qty))throw new Error(`Brak wystarczającego stanu: ${x.name} ${x.colorLabel||x.color} / ${x.size}.`)}
  for(const x of order.items){db.catalog[x.id].colors[x.color].sizes[x.size]-=Number(x.qty)}
  order.stockReserved=true;order.stockReservedAt=Date.now();
}
function releaseStockReservation(db,order){
  if(!order.stockReserved||order.stockCommitted)return;
  for(const x of order.items){const slot=db.catalog?.[x.id]?.colors?.[x.color]?.sizes;if(slot&&Object.prototype.hasOwnProperty.call(slot,x.size))slot[x.size]=Number(slot[x.size]||0)+Number(x.qty)}
  order.stockReserved=false;order.stockReservedReleasedAt=Date.now();
}
app.get('/api/store/catalog',(req,res)=>{const db=load();ensureStore(db);save(db);res.json({ok:true,catalog:publicCatalog(db)})});
app.get('/api/orders',auth,(req,res)=>{ensureStore(req.db);res.json({ok:true,orders:req.db.orders.filter(o=>o.userId===req.user.id).map(orderForUser).sort((a,b)=>b.createdAt-a.createdAt)})});


function ensurePromoCodes(db){
  if(!Array.isArray(db.promoCodes))db.promoCodes=[];
  if(!db.promoCodes.some(p=>String(p.code||'').toUpperCase()==='STARXV10')){
    db.promoCodes.push({id:crypto.randomUUID(),code:'STARXV10',type:'percent',value:10,minSubtotal:0,usageLimit:null,usedCount:0,active:true,startsAt:null,endsAt:null,createdAt:Date.now(),updatedAt:Date.now()});
  }
  return db.promoCodes;
}
function promoPublic(p){return {id:p.id,code:p.code,type:p.type,value:Number(p.value||0),minSubtotal:Number(p.minSubtotal||0),usageLimit:p.usageLimit==null?null:Number(p.usageLimit),usedCount:Number(p.usedCount||0),active:Boolean(p.active),startsAt:p.startsAt||null,endsAt:p.endsAt||null,createdAt:p.createdAt,updatedAt:p.updatedAt}}
function validatePromo(db,rawCode,subtotal){
  ensurePromoCodes(db);
  const code=String(rawCode||'').trim().toUpperCase(),base=Math.max(0,Number(subtotal||0));
  if(!code)return {ok:false,error:'Wpisz kod rabatowy.'};
  const p=db.promoCodes.find(x=>String(x.code||'').toUpperCase()===code);
  if(!p||!p.active)return {ok:false,error:'Ten kod jest nieprawidłowy lub nieaktywny.'};
  const now=Date.now(),start=p.startsAt?new Date(p.startsAt).getTime():0,end=p.endsAt?new Date(p.endsAt).getTime():0;
  if(start&&now<start)return {ok:false,error:'Ten kod nie jest jeszcze aktywny.'};
  if(end&&now>end)return {ok:false,error:'Ten kod wygasł.'};
  if(p.usageLimit!=null&&Number(p.usedCount||0)>=Number(p.usageLimit))return {ok:false,error:'Limit użyć tego kodu został wyczerpany.'};
  if(base<Number(p.minSubtotal||0))return {ok:false,error:`Minimalna wartość koszyka dla tego kodu to ${Number(p.minSubtotal||0).toFixed(2)} PLN.`};
  let discount=p.type==='fixed'?Number(p.value||0):base*(Number(p.value||0)/100);
  discount=Math.max(0,Math.min(base,Math.round(discount*100)/100));
  return {ok:true,promo:promoPublic(p),discount,total:Math.max(0,Math.round((base-discount)*100)/100)};
}
app.get('/api/promos/validate',(req,res)=>{
  const db=load();ensurePromoCodes(db);const result=validatePromo(db,req.query?.code,req.query?.subtotal);save(db);
  if(!result.ok)return res.status(400).json(result);res.json(result);
});

function ensureReturnRequests(db){if(!Array.isArray(db.returnRequests))db.returnRequests=[];return db.returnRequests}
function nextReturnNo(db){const nums=ensureReturnRequests(db).map(x=>Number(String(x.returnNo||'').replace(/\D/g,''))||0);return `RT-${Math.max(1000,...nums)+1}`}
function returnForUser(r){return {id:r.id,returnNo:r.returnNo,orderId:r.orderId,orderNo:r.orderNo,type:r.type,reason:r.reason,details:r.details||'',items:r.items||[],status:r.status||'new',adminReply:r.adminReply||'',createdAt:r.createdAt,updatedAt:r.updatedAt||r.createdAt}}
app.get('/api/returns',auth,(req,res)=>{ensureReturnRequests(req.db);res.json({ok:true,returns:req.db.returnRequests.filter(r=>r.userId===req.user.id).map(returnForUser).sort((a,b)=>b.createdAt-a.createdAt)})});
app.post('/api/orders/:id/return-request',auth,(req,res)=>{
  try{
    ensureStore(req.db);ensureReturnRequests(req.db);
    const order=req.db.orders.find(o=>o.id===req.params.id&&o.userId===req.user.id);
    if(!order)return res.status(404).json({error:'Nie znaleziono zamówienia.'});
    if(order.paymentStatus!=='paid'||Number(order.shippingStage||0)<4)return res.status(409).json({error:'Zwrot lub reklamację można zgłosić po dostarczeniu opłaconego zamówienia.'});
    const type=String(req.body?.type||'return');if(!['return','complaint'].includes(type))return res.status(400).json({error:'Nieprawidłowy typ zgłoszenia.'});
    const reason=String(req.body?.reason||'').trim().slice(0,120),details=String(req.body?.details||'').trim().slice(0,1500);
    if(reason.length<2)return res.status(400).json({error:'Wybierz powód zgłoszenia.'});
    const requested=Array.isArray(req.body?.items)?req.body.items:[];
    const items=[];
    for(const q of requested){
      const oi=(order.items||[]).find(x=>String(x.id)===String(q.id)&&String(x.color)===String(q.color)&&String(x.size)===String(q.size));
      if(!oi)continue;const qty=Math.max(1,Math.min(Number(oi.qty||1),Math.floor(Number(q.qty||1))));
      items.push({id:oi.id,name:oi.name,color:oi.color,colorLabel:oi.colorLabel||oi.color,size:oi.size,qty,price:Number(oi.price||0)});
    }
    if(!items.length)return res.status(400).json({error:'Wybierz co najmniej jeden produkt.'});
    const active=req.db.returnRequests.find(r=>r.userId===req.user.id&&r.orderId===order.id&&!['rejected','completed'].includes(r.status||'new'));
    if(active)return res.status(409).json({error:`Dla tego zamówienia istnieje już aktywne zgłoszenie ${active.returnNo}.`});
    const now=Date.now(),rr={id:crypto.randomUUID(),returnNo:nextReturnNo(req.db),userId:req.user.id,email:cleanEmail(order.address?.email||req.user.email),orderId:order.id,orderNo:order.orderNo,type,reason,details,items,status:'new',adminReply:'',createdAt:now,updatedAt:now};
    req.db.returnRequests.push(rr);save(req.db);
    res.json({ok:true,request:returnForUser(rr)});
  }catch(e){res.status(400).json({error:e.message||'Nie udało się wysłać zgłoszenia.'})}
});

app.post('/api/orders/:id/cancel',auth,(req,res)=>{
  ensureStore(req.db);
  const order=req.db.orders.find(o=>o.id===req.params.id&&o.userId===req.user.id);
  if(!order)return res.status(404).json({error:'Nie znaleziono zamówienia.'});
  if(order.paymentStatus==='cancelled')return res.json({ok:true,order:orderForUser(order)});
  if(order.paymentStatus==='paid')return res.status(409).json({error:'Opłaconego zamówienia nie można anulować automatycznie. Skontaktuj się z obsługą STARXV.'});
  releaseStockReservation(req.db,order);
  order.paymentStatus='cancelled';
  order.cancelledAt=Date.now();
  order.updatedAt=Date.now();
  orderEvent(order,'cancelled','Zamówienie anulowane','Zamówienie zostało anulowane przed potwierdzeniem płatności.',order.cancelledAt);
  save(req.db);sendOrderUpdateEmail(req.db,order,'cancelled',{dedupeKey:'cancelled'});
  res.json({ok:true,order:orderForUser(order)});
});
app.post('/api/orders/prepare',auth,(req,res)=>{try{ensureStore(req.db);const items=normalizeOrderItems(req.db,req.body?.items);const address=safeOrderAddress(req.body?.address);if(!address.street||!address.postal||!address.city)throw new Error('Uzupełnij adres dostawy.');const subtotal=items.reduce((s,x)=>s+x.price*x.qty,0);const promoCode=String(req.body?.promo?.code||'').trim().toUpperCase();let discount=0,promoRecord=null;if(promoCode){const check=validatePromo(req.db,promoCode,subtotal);if(!check.ok)throw new Error(check.error);discount=check.discount;promoRecord=check.promo}const total=Math.max(0,Math.round((subtotal-discount)*100)/100);const now=Date.now(),order={id:crypto.randomUUID(),orderNo:String(now).slice(-8),userId:req.user.id,createdAt:now,updatedAt:now,items,address,delivery:req.body?.delivery||null,paymentPreference:String(req.body?.paymentPreference||''),promo:promoCode?{code:promoCode,discount,type:promoRecord?.type||null,value:promoRecord?.value||0}:null,total,paymentStatus:'pending',shippingStage:0,stockCommitted:false,timeline:[]};orderEvent(order,'created','Zamówienie utworzone','Oczekujemy na potwierdzenie płatności.',order.createdAt);req.db.orders.push(order);save(req.db);sendOrderUpdateEmail(req.db,order,'created',{dedupeKey:'created'});res.json({ok:true,order:orderForUser(order)})}catch(e){res.status(400).json({error:e.message||'Nie udało się przygotować zamówienia.'})}});
// This function is intentionally server-only. A future payment webhook should call it only after the payment provider confirms payment.
function markOrderPaid(db,order){
  if(order.paymentStatus==='paid')return;
  if(order.stockReserved){order.stockReserved=false;order.stockCommitted=true;order.stockCommittedAt=Date.now()}
  else decrementStockForOrder(db,order);
  order.paymentStatus='paid';order.shippingStage=0;order.updatedAt=Date.now();
  if(order.promo?.code&&!order.promoCounted){ensurePromoCodes(db);const pc=db.promoCodes.find(p=>String(p.code||'').toUpperCase()===String(order.promo.code||'').toUpperCase());if(pc){pc.usedCount=Number(pc.usedCount||0)+1;pc.updatedAt=Date.now()}order.promoCounted=true;}
  orderEvent(order,'paid','Płatność potwierdzona','Płatność została zaakceptowana. Zamówienie trafiło do realizacji.',order.updatedAt);
}


function stripeBaseUrl(req){
  const configured=String(process.env.PUBLIC_URL||'').trim().replace(/\/$/,'');
  return configured||`${req.protocol}://${req.get('host')}`;
}
function stripeMethods(preference){
  const p=String(preference||'auto');
  if(p==='blik')return ['blik'];
  if(p==='p24')return ['p24'];
  if(p==='card')return ['card'];
  if(p==='wallet')return ['card']; // Apple Pay / Google Pay are exposed through eligible card wallets.
  if(p==='link')return ['card','link'];
  return null;
}
async function sendPaidOrderEmail(db,order){
  try{
    const key=String(process.env.RESEND_API_KEY||'').trim();
    if(!key)return;
    const u=(db.users||[]).find(x=>x.id===order.userId);
    const to=cleanEmail(order.address?.email||u?.email);
    if(!to)return;
    const resend=new Resend(key);
    const itemLines=(order.items||[]).map(x=>`${x.name} — ${x.colorLabel||x.color} / ${x.size} × ${x.qty}`).join('\n');
    const total=Number(order.total||0).toLocaleString('pl-PL',{minimumFractionDigits:2,maximumFractionDigits:2});
    const {error}=await resend.emails.send({
      from:process.env.MAIL_FROM||'STARXV <no-reply@starxv.pl>',to,
      subject:`STARXV — potwierdzenie zamówienia #${order.orderNo}`,
      text:`Dziękujemy za zamówienie #${order.orderNo}.\n\nPłatność została potwierdzona.\n\n${itemLines}\n\nRazem: ${total} PLN\n\nStatus zamówienia możesz sprawdzić w profilu STARXV.`,
      html:`<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:32px"><h1 style="font-size:28px;margin:0 0 26px">STARXV</h1><p>Płatność za zamówienie <b>#${order.orderNo}</b> została potwierdzona.</p><div style="margin:24px 0;padding:18px;border:1px solid #ddd">${(order.items||[]).map(x=>`<div style="margin:8px 0"><b>${String(x.name||'STARXV').replace(/[<>&]/g,'')}</b><br><span style="color:#666">${String(x.colorLabel||x.color||'').replace(/[<>&]/g,'')} / ${String(x.size||'').replace(/[<>&]/g,'')} × ${Number(x.qty||1)}</span></div>`).join('')}<hr style="border:0;border-top:1px solid #ddd;margin:18px 0"><b>Razem: ${total} PLN</b></div><p style="color:#666">Aktualny status realizacji znajdziesz w sekcji „Moje zamówienia” na swoim koncie.</p></div>`
    });
    if(error)console.error('Resend order confirmation error:',error);
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
    const tracking=String(order.trackingNumber||'').trim();
    const t={
      created:['Zamówienie zostało utworzone','Otrzymaliśmy Twoje zamówienie. Oczekujemy na potwierdzenie płatności.'],
      paid:['Płatność potwierdzona','Płatność została zaakceptowana. Zamówienie trafiło do realizacji.'],
      preparing:['Przygotowujemy zamówienie','Twoje produkty są przygotowywane do wysyłki.'],
      shipped:['Paczka została nadana',tracking?`Przesyłka została nadana. Numer InPost: ${tracking}`:'Przesyłka została nadana przewoźnikowi.'],
      transit:['Paczka jest w drodze',tracking?`Przesyłka jest w drodze. Numer InPost: ${tracking}`:'Przesyłka jest w drodze.'],
      delivered:['Zamówienie dostarczone','Przesyłka została oznaczona jako dostarczona. Dziękujemy za zakupy w STARXV.'],
      tracking:['Numer przesyłki InPost',tracking?`Twój numer przesyłki InPost: ${tracking}`:'Do zamówienia został dodany numer przesyłki.'],
      cancelled:['Zamówienie anulowane','Zamówienie zostało anulowane i nie będzie dalej realizowane.']
    };
    const [title,body]=t[eventKey]||['Aktualizacja zamówienia','Status Twojego zamówienia został zaktualizowany.'];
    const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const base=String(process.env.PUBLIC_URL||'https://starxv.pl').replace(/\/+$/,'');
    const resend=new Resend(key);
    const {error}=await resend.emails.send({
      from:process.env.MAIL_FROM||'STARXV <no-reply@starxv.pl>',to,
      subject:`STARXV — ${title} #${order.orderNo}`,
      text:`STARXV\n\n${title}\nZamówienie #${order.orderNo}\n\n${body}${tracking?`\n\nInPost: ${tracking}`:''}\n\nStatus zamówienia: ${base}`,
      html:`<div style="background:#090909;color:#fff;font-family:Arial,sans-serif;padding:36px 20px"><div style="max-width:560px;margin:auto"><div style="font-size:25px;font-weight:900;letter-spacing:5px;margin-bottom:30px">STARXV</div><div style="font-size:10px;color:#777;letter-spacing:2px">ZAMÓWIENIE #${esc(order.orderNo)}</div><h1 style="font-size:22px;margin:10px 0 14px">${esc(title)}</h1><p style="font-size:14px;line-height:1.7;color:#bbb">${esc(body)}</p>${tracking?`<div style="border:1px solid #292929;padding:14px;margin:22px 0"><span style="font-size:10px;color:#777">INPOST</span><br><b>${esc(tracking)}</b></div>`:''}<a href="${esc(base)}" style="display:inline-block;background:#fff;color:#000;text-decoration:none;padding:12px 18px;font-size:11px;font-weight:900;margin-top:12px">SPRAWDŹ ZAMÓWIENIE →</a><div style="font-size:10px;color:#555;margin-top:30px">STARXV • kontakt@starxv.pl</div></div></div>`
    });
    if(error){console.error('Resend order update error:',error);return false}
    order.mailEvents[dedupe]=Date.now();save(db);return true;
  }catch(e){console.error('Order update email error:',e.message);return false}
}


app.get('/api/payments/config',(req,res)=>{
  res.json({ok:true,stripeConfigured:Boolean(process.env.STRIPE_SECRET_KEY&&process.env.STRIPE_WEBHOOK_SECRET),currency:'pln'});
});

app.post('/api/create-checkout-session',auth,async(req,res)=>{
  try{
    const stripe=getStripe();
    if(!stripe)return res.status(503).json({error:'Stripe nie jest jeszcze skonfigurowany na serwerze.'});
    ensureStore(req.db);
    const orderId=String(req.body?.orderId||'');
    const order=req.db.orders.find(o=>o.id===orderId&&o.userId===req.user.id);
    if(!order)return res.status(404).json({error:'Nie znaleziono zamówienia.'});
    if(order.paymentStatus==='paid')return res.status(409).json({error:'To zamówienie jest już opłacone.'});
    if(order.paymentStatus==='cancelled')return res.status(409).json({error:'To zamówienie zostało anulowane.'});
    if(!Number.isFinite(Number(order.total))||Number(order.total)<=0)return res.status(400).json({error:'Nieprawidłowa kwota zamówienia.'});

    // Reserve stock for this checkout so two customers cannot pay for the same last item.
    if(order.paymentStatus==='failed')order.paymentStatus='pending';
    reserveStockForOrder(req.db,order);
    save(req.db);

    const base=stripeBaseUrl(req);
    const methods=stripeMethods(order.paymentPreference);
    const params={
      mode:'payment',
      success_url:`${base}/?payment=success&order=${encodeURIComponent(order.id)}&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url:`${base}/?payment=cancelled&order=${encodeURIComponent(order.id)}`,
      customer_email:cleanEmail(order.address?.email||req.user.email)||undefined,
      line_items:[{
        quantity:1,
        price_data:{
          currency:'pln',
          unit_amount:Math.round(Number(order.total)*100),
          product_data:{name:`STARXV — zamówienie #${order.orderNo}`,description:`${(order.items||[]).length} ${(order.items||[]).length===1?'produkt':'produkty'} • płatność za całe zamówienie`}
        }
      }],
      metadata:{orderId:order.id,orderNo:String(order.orderNo),userId:String(order.userId),paymentPreference:String(order.paymentPreference||'auto')},
      payment_intent_data:{metadata:{orderId:order.id,orderNo:String(order.orderNo),userId:String(order.userId)}},
      locale:'pl',
      expires_at:Math.floor(Date.now()/1000)+30*60
    };
    if(methods)params.payment_method_types=methods;else params.automatic_payment_methods={enabled:true};
    let session;
    try{
      session=await stripe.checkout.sessions.create(params,{idempotencyKey:`starxv-${order.id}-${Math.floor(Date.now()/60000)}`});
    }catch(e){
      releaseStockReservation(req.db,order);save(req.db);throw e;
    }
    order.stripeSessionId=session.id;
    order.stripeSessionCreatedAt=Date.now();
    order.updatedAt=Date.now();
    save(req.db);
    res.json({ok:true,url:session.url,sessionId:session.id,orderId:order.id});
  }catch(e){
    console.error('Stripe Checkout error:',e);
    res.status(400).json({error:e?.message||'Nie udało się uruchomić płatności.'});
  }
});

app.get('/api/orders/:id/payment-status',auth,(req,res)=>{
  ensureStore(req.db);
  const order=req.db.orders.find(o=>o.id===req.params.id&&o.userId===req.user.id);
  if(!order)return res.status(404).json({error:'Nie znaleziono zamówienia.'});
  res.json({ok:true,order:orderForUser(order),confirmed:order.paymentStatus==='paid'});
});

async function handleStripeWebhook(req,res){
  const stripe=getStripe(),secret=String(process.env.STRIPE_WEBHOOK_SECRET||'').trim();
  if(!stripe||!secret)return res.status(503).send('Stripe webhook is not configured.');
  let event;
  try{event=stripe.webhooks.constructEvent(req.body,req.headers['stripe-signature'],secret)}
  catch(e){console.error('Stripe webhook signature error:',e.message);return res.status(400).send('Invalid signature.');}
  try{
    const session=event.data.object;
    const orderId=String(session?.metadata?.orderId||'');
    if(orderId){
      const db=load();ensureStore(db);const order=db.orders.find(o=>o.id===orderId);
      if(order){
        if(event.type==='checkout.session.completed'||event.type==='checkout.session.async_payment_succeeded'){
          if(session.payment_status==='paid'||event.type==='checkout.session.async_payment_succeeded'){
            const wasPaid=order.paymentStatus==='paid';
            markOrderPaid(db,order);
            order.stripeSessionId=session.id||order.stripeSessionId;
            order.stripePaymentIntentId=typeof session.payment_intent==='string'?session.payment_intent:'';
            order.updatedAt=Date.now();save(db);
            if(!wasPaid)await sendPaidOrderEmail(db,order);
          }
        }else if(event.type==='checkout.session.async_payment_failed'){
          if(order.paymentStatus!=='paid'){releaseStockReservation(db,order);order.paymentStatus='failed';order.updatedAt=Date.now();save(db)}
        }else if(event.type==='checkout.session.expired'){
          if(order.paymentStatus==='pending'){releaseStockReservation(db,order);order.paymentStatus='cancelled';order.updatedAt=Date.now();save(db)}
        }
      }
    }
    res.json({received:true});
  }catch(e){console.error('Stripe webhook processing error:',e);res.status(500).send('Webhook processing failed.');}
}


// --- STARXV admin panel ---
function adminEmails(){
  return String(process.env.ADMIN_EMAILS||'').split(',').map(cleanEmail).filter(Boolean);
}
function adminOnly(req,res,next){
  auth(req,res,()=>{
    const allowed=adminEmails();
    if(!allowed.length)return res.status(503).json({error:'Panel administratora nie jest skonfigurowany. Dodaj ADMIN_EMAILS do pliku .env.'});
    if(!allowed.includes(cleanEmail(req.user.email)))return res.status(403).json({error:'To konto nie ma dostępu do panelu administratora.'});
    next();
  });
}

// --- STARXV InPost / ShipX shipping -------------------------------------------
// Requires INPOST_TOKEN and INPOST_ORGANIZATION_ID in .env.
// The ShipX PL API is asynchronous: creation may initially return no tracking_number.
function inpostConfig(){
  return {
    token:String(process.env.INPOST_TOKEN||'').trim(),
    organizationId:String(process.env.INPOST_ORGANIZATION_ID||'').trim(),
    base:String(process.env.INPOST_API_BASE||'https://api-shipx-pl.easypack24.net/v1').trim().replace(/\/$/,''),
    parcelTemplate:['small','medium','large'].includes(String(process.env.INPOST_PARCEL_TEMPLATE||'small').trim())?String(process.env.INPOST_PARCEL_TEMPLATE||'small').trim():'small'
  };
}
function inpostConfigured(){const c=inpostConfig();return Boolean(c.token&&c.organizationId)}
async function inpostRequest(pathname,{method='GET',body,auth=true,accept='application/json'}={}){
  const c=inpostConfig();
  if(auth&&!inpostConfigured())throw Object.assign(new Error('InPost nie jest jeszcze skonfigurowany. Dodaj INPOST_TOKEN i INPOST_ORGANIZATION_ID do .env.'),{status:503});
  const headers={Accept:accept};
  if(auth)headers.Authorization=`Bearer ${c.token}`;
  if(body!==undefined)headers['Content-Type']='application/json';
  const response=await fetch(c.base+pathname,{method,headers,body:body===undefined?undefined:JSON.stringify(body)});
  const contentType=String(response.headers.get('content-type')||'');
  if(!response.ok){
    let detail='';
    try{const j=contentType.includes('json')?await response.json():null;detail=j?.description||j?.message||j?.error||''}catch{}
    const err=new Error(detail||`InPost zwrócił błąd HTTP ${response.status}.`);err.status=response.status;throw err;
  }
  if(accept!=='application/json')return response;
  return response.status===204?{}:response.json();
}
function receiverForInpost(order,withAddress){
  const a=order.address||{};
  const receiver={first_name:String(a.firstName||'').trim(),last_name:String(a.lastName||'').trim(),email:cleanEmail(a.email),phone:String(a.phone||'').replace(/\s+/g,'').trim()};
  if(!receiver.first_name||!receiver.last_name||!receiver.email||!receiver.phone)throw new Error('Do utworzenia przesyłki InPost potrzebne są imię, nazwisko, e-mail i numer telefonu odbiorcy.');
  if(withAddress){
    receiver.address={line1:String(a.street||'').trim(),city:String(a.city||'').trim(),post_code:String(a.postal||'').trim(),country_code:'PL'};
    if(!receiver.address.line1||!receiver.address.city||!receiver.address.post_code)throw new Error('Brakuje pełnego adresu odbiorcy.');
  }
  return receiver;
}
function makeInpostShipmentBody(order){
  const c=inpostConfig(),delivery=order.delivery||{},locker=delivery?.locker||{};
  const isLocker=delivery.type==='inpost';
  const body={
    receiver:receiverForInpost(order,!isLocker),
    parcels:{template:c.parcelTemplate},
    service:isLocker?'inpost_locker_standard':'inpost_courier_standard',
    reference:`STARXV-${String(order.orderNo||order.id).slice(0,40)}`
  };
  if(isLocker){
    const point=String(locker.id||locker.name||'').trim();
    if(!point)throw new Error('W zamówieniu nie zapisano kodu Paczkomatu.');
    body.custom_attributes={target_point:point};
  }
  return body;
}
function inpostStageFromStatus(status,current=0){
  const s=String(status||'');
  if(s==='delivered')return 4;
  if(['out_for_delivery','out_for_delivery_to_address','ready_to_pickup','pickup_reminder_sent','ready_to_pickup_from_branch','ready_to_pickup_from_pok'].includes(s))return 3;
  if(['dispatched_by_sender','dispatched_by_sender_to_pok','collected_from_sender','taken_by_courier','adopted_at_source_branch','sent_from_source_branch','adopted_at_sorting_center','sent_from_sorting_center','adopted_at_target_branch','taken_by_courier_from_pok'].includes(s))return 3;
  if(['confirmed','created','offers_prepared','offer_selected'].includes(s))return Math.max(2,Number(current||0));
  return Number(current||0);
}
function applyInpostState(order,data,db=null){
  const before=Number(order.shippingStage||0),beforeTracking=String(order.trackingNumber||'');
  if(data?.id)order.inpostShipmentId=data.id;
  if(data?.tracking_number)order.trackingNumber=String(data.tracking_number);
  if(data?.status)order.carrierStatus=String(data.status);
  order.carrier='InPost';order.trackingUpdatedAt=Date.now();
  order.shippingStage=inpostStageFromStatus(order.carrierStatus,order.shippingStage);order.updatedAt=Date.now();
  const after=Number(order.shippingStage||0);
  if(after!==before){
    const names=['Nowe','W przygotowaniu','Nadane','W drodze','Dostarczone'];
    const notes=['Zamówienie zostało przyjęte do realizacji.','Produkty są przygotowywane do wysyłki.','Przesyłka została nadana przewoźnikowi.','Przesyłka jest w drodze.','Przesyłka została dostarczona.'];
    orderEvent(order,`shipping_${after}`,names[after]||'Aktualizacja dostawy',notes[after]||'Status dostawy został zaktualizowany.',order.updatedAt);
    if(db){const k={1:'preparing',2:'shipped',3:'transit',4:'delivered'}[after];if(k)sendOrderUpdateEmail(db,order,k,{dedupeKey:`shipping_${after}`})}
  }
  if(db&&!beforeTracking&&order.trackingNumber)sendOrderUpdateEmail(db,order,'tracking',{dedupeKey:`tracking_${order.trackingNumber}`});
}
async function refreshInpostOrder(order,db=null){
  if(order.inpostShipmentId){
    const data=await inpostRequest(`/shipments/${encodeURIComponent(order.inpostShipmentId)}`);
    applyInpostState(order,data,db);
  }
  if(order.trackingNumber){
    try{
      const tracking=await inpostRequest(`/tracking/${encodeURIComponent(order.trackingNumber)}`,{auth:false});
      if(tracking?.status)order.carrierStatus=String(tracking.status);
      order.shippingStage=inpostStageFromStatus(order.carrierStatus,order.shippingStage);
      order.trackingUpdatedAt=Date.now();order.updatedAt=Date.now();
    }catch(e){console.warn('InPost tracking refresh:',e.message)}
  }
  return order;
}
app.get('/api/shipping/config',(req,res)=>res.json({ok:true,inpostConfigured:inpostConfigured(),carrier:'InPost'}));
app.post('/api/admin/orders/:id/shipment/create',adminOnly,async(req,res)=>{try{
  ensureStore(req.db);const order=req.db.orders.find(o=>o.id===req.params.id);
  if(!order)return res.status(404).json({error:'Nie znaleziono zamówienia.'});
  if(order.paymentStatus!=='paid')return res.status(409).json({error:'Przesyłkę można utworzyć dopiero dla opłaconego zamówienia.'});
  if(order.inpostShipmentId)return res.status(409).json({error:'Dla tego zamówienia istnieje już przesyłka InPost.'});
  const data=await inpostRequest(`/organizations/${encodeURIComponent(inpostConfig().organizationId)}/shipments`,{method:'POST',body:makeInpostShipmentBody(order)});
  applyInpostState(order,data,db);order.shippingStage=Math.max(1,Number(order.shippingStage||0));save(req.db);
  res.status(201).json({ok:true,order:adminOrder(req.db,order)});
}catch(e){console.error('InPost create shipment:',e);res.status(e.status&&e.status>=400&&e.status<600?e.status:400).json({error:e.message||'Nie udało się utworzyć przesyłki InPost.'})}});
app.post('/api/admin/orders/:id/shipment/sync',adminOnly,async(req,res)=>{try{
  ensureStore(req.db);const order=req.db.orders.find(o=>o.id===req.params.id);
  if(!order)return res.status(404).json({error:'Nie znaleziono zamówienia.'});
  if(!order.inpostShipmentId&&!order.trackingNumber)return res.status(409).json({error:'To zamówienie nie ma jeszcze przesyłki InPost.'});
  await refreshInpostOrder(order,req.db);save(req.db);res.json({ok:true,order:adminOrder(req.db,order)});
}catch(e){console.error('InPost sync:',e);res.status(e.status&&e.status>=400&&e.status<600?e.status:400).json({error:e.message||'Nie udało się odświeżyć trackingu InPost.'})}});
app.get('/api/admin/orders/:id/shipment/label',adminOnly,async(req,res)=>{try{
  ensureStore(req.db);const order=req.db.orders.find(o=>o.id===req.params.id);
  if(!order)return res.status(404).json({error:'Nie znaleziono zamówienia.'});
  if(!order.inpostShipmentId)return res.status(409).json({error:'To zamówienie nie ma jeszcze przesyłki InPost.'});
  const r=await inpostRequest(`/shipments/${encodeURIComponent(order.inpostShipmentId)}/label?format=pdf`,{accept:'application/pdf'});
  const buf=Buffer.from(await r.arrayBuffer());res.setHeader('Content-Type','application/pdf');res.setHeader('Content-Disposition',`inline; filename=STARXV-${String(order.orderNo||'shipment')}-InPost.pdf`);res.send(buf);
}catch(e){console.error('InPost label:',e);res.status(e.status&&e.status>=400&&e.status<600?e.status:400).json({error:e.message||'Nie udało się pobrać etykiety InPost.'})}});
app.post('/api/admin/orders/:id/shipment/manual',adminOnly,(req,res)=>{try{
  ensureStore(req.db);const order=req.db.orders.find(o=>o.id===req.params.id);
  if(!order)return res.status(404).json({error:'Nie znaleziono zamówienia.'});
  const tracking=String(req.body?.trackingNumber||'').trim().replace(/\s+/g,'');
  if(!/^[A-Za-z0-9-]{8,40}$/.test(tracking))return res.status(400).json({error:'Wpisz poprawny numer przesyłki.'});
  const beforeStage=Number(order.shippingStage||0),beforeTracking=String(order.trackingNumber||'');order.trackingNumber=tracking;order.carrier='InPost';order.carrierStatus='manual';order.shippingStage=Math.max(2,beforeStage);order.trackingUpdatedAt=Date.now();order.updatedAt=Date.now();if(order.shippingStage!==beforeStage)orderEvent(order,'shipping_2','Nadane',`Numer przesyłki InPost: ${tracking}`,order.updatedAt);save(req.db);if(beforeTracking!==tracking)sendOrderUpdateEmail(req.db,order,'tracking',{dedupeKey:`tracking_${tracking}`});if(order.shippingStage!==beforeStage)sendOrderUpdateEmail(req.db,order,'shipped',{dedupeKey:'shipping_2'});
  res.json({ok:true,order:adminOrder(req.db,order)});
}catch(e){res.status(400).json({error:e.message||'Nie udało się zapisać numeru przesyłki.'})}});

function adminOrder(db,o){
  const u=(db.users||[]).find(x=>x.id===o.userId);
  return {
    ...orderForUser(o),
    customer:u?{firstName:u.firstName,lastName:u.lastName,email:u.email}:{firstName:'',lastName:'',email:''},
    stockCommitted:Boolean(o.stockCommitted)
  };
}
app.get('/api/admin/me',adminOnly,(req,res)=>res.json({ok:true,user:publicUser(req.user)}));
app.get('/api/admin/dashboard',adminOnly,(req,res)=>{
  ensureStore(req.db);
  const orders=req.db.orders.map(o=>adminOrder(req.db,o)).sort((a,b)=>b.createdAt-a.createdAt);
  const variants=[];
  for(const [productId,p] of Object.entries(req.db.catalog))for(const [color,c] of Object.entries(p.colors||{}))for(const [size,stock] of Object.entries(c.sizes||{}))variants.push({productId,productName:p.name,color,colorLabel:c.label,size,stock:Number(stock||0)});
  const paid=orders.filter(o=>o.paymentStatus==='paid');
  res.json({ok:true,catalog:req.db.catalog,orders,stats:{orders:orders.length,pending:orders.filter(o=>o.paymentStatus==='pending').length,paid:paid.length,revenue:Math.round(paid.reduce((sum,o)=>sum+Number(o.total||0),0)*100)/100,stock:variants.reduce((sum,v)=>sum+v.stock,0)}});
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
app.post('/api/admin/products',adminOnly,(req,res)=>{
  try{
    ensureStore(req.db);
    const id=cleanSlug(req.body?.id,'ID produktu');
    if(req.db.catalog[id])return res.status(409).json({error:'Produkt o takim ID już istnieje.'});
    const name=String(req.body?.name||'').trim().slice(0,160);
    const fit=String(req.body?.fit||'').trim().slice(0,80);
    const category=['hoodies','tshirts','other'].includes(String(req.body?.category||''))?String(req.body.category):'other';
    const image=String(req.body?.image||'').trim().slice(0,200000);
    const price=Number(req.body?.price);
    if(!name)return res.status(400).json({error:'Podaj nazwę produktu.'});
    if(!Number.isFinite(price)||price<0||price>100000)return res.status(400).json({error:'Podaj prawidłową cenę.'});
    req.db.catalog[id]={name,price:Math.round(price*100)/100,fit,category,image,colors:{}};
    save(req.db);res.status(201).json({ok:true,id,product:req.db.catalog[id]});
  }catch(e){res.status(400).json({error:e.message||'Nie udało się dodać produktu.'})}
});
app.put('/api/admin/products/:id',adminOnly,(req,res)=>{
  try{
    ensureStore(req.db);const id=String(req.params.id||'');const p=req.db.catalog[id];
    if(!p)return res.status(404).json({error:'Nie znaleziono produktu.'});
    if(Object.prototype.hasOwnProperty.call(req.body||{},'name')){const name=String(req.body.name||'').trim().slice(0,160);if(!name)return res.status(400).json({error:'Nazwa nie może być pusta.'});p.name=name}
    if(Object.prototype.hasOwnProperty.call(req.body||{},'fit'))p.fit=String(req.body.fit||'').trim().slice(0,80);
    if(Object.prototype.hasOwnProperty.call(req.body||{},'category')){const category=String(req.body.category||'');if(!['hoodies','tshirts','other'].includes(category))return res.status(400).json({error:'Nieprawidłowa kategoria.'});p.category=category}
    if(Object.prototype.hasOwnProperty.call(req.body||{},'image'))p.image=String(req.body.image||'').trim().slice(0,200000);
    if(Object.prototype.hasOwnProperty.call(req.body||{},'price')){const price=Number(req.body.price);if(!Number.isFinite(price)||price<0||price>100000)return res.status(400).json({error:'Podaj prawidłową cenę.'});p.price=Math.round(price*100)/100}
    save(req.db);res.json({ok:true,product:p});
  }catch(e){res.status(400).json({error:e.message||'Nie udało się zapisać produktu.'})}
});
app.delete('/api/admin/products/:id',adminOnly,(req,res)=>{
  try{
    ensureStore(req.db);
    const id=String(req.params.id||'');
    const product=req.db.catalog[id];
    if(!product)return res.status(404).json({error:'Nie znaleziono produktu.'});

    // A pending order may still need this product when payment is confirmed.
    // Keep the catalog entry until that order is paid or cancelled.
    const blockingOrder=(req.db.orders||[]).find(o=>
      !o.stockCommitted && String(o.paymentStatus||'pending')==='pending' &&
      Array.isArray(o.items) && o.items.some(x=>String(x.id||'')===id)
    );
    if(blockingOrder){
      return res.status(409).json({error:`Nie można usunąć produktu, bo znajduje się w oczekującym zamówieniu #${blockingOrder.orderNo||''}. Najpierw oznacz zamówienie jako opłacone albo anulowane.`});
    }

    delete req.db.catalog[id];
    save(req.db);
    res.json({ok:true,id});
  }catch(e){
    res.status(400).json({error:e.message||'Nie udało się usunąć produktu.'});
  }
});

app.post('/api/admin/products/:id/colors',adminOnly,(req,res)=>{
  try{
    ensureStore(req.db);const id=String(req.params.id||'');const p=req.db.catalog[id];
    if(!p)return res.status(404).json({error:'Nie znaleziono produktu.'});
    const color=cleanSlug(req.body?.color,'ID koloru');
    if(p.colors?.[color])return res.status(409).json({error:'Ten kolor już istnieje.'});
    const label=String(req.body?.label||'').trim().slice(0,80);if(!label)return res.status(400).json({error:'Podaj nazwę koloru.'});
    if(!p.colors||typeof p.colors!=='object')p.colors={};p.colors[color]={label,sizes:{}};
    save(req.db);res.status(201).json({ok:true,color,variant:p.colors[color]});
  }catch(e){res.status(400).json({error:e.message||'Nie udało się dodać koloru.'})}
});
app.post('/api/admin/products/:id/colors/:color/sizes',adminOnly,(req,res)=>{
  try{
    ensureStore(req.db);const id=String(req.params.id||''),color=String(req.params.color||'');const c=req.db.catalog?.[id]?.colors?.[color];
    if(!c)return res.status(404).json({error:'Nie znaleziono produktu lub koloru.'});
    const size=cleanSize(req.body?.size);if(Object.prototype.hasOwnProperty.call(c.sizes||{},size))return res.status(409).json({error:'Ten rozmiar już istnieje.'});
    const stock=Number(req.body?.stock??0);if(!Number.isInteger(stock)||stock<0||stock>9999)return res.status(400).json({error:'Stan musi być liczbą całkowitą od 0 do 9999.'});
    if(!c.sizes||typeof c.sizes!=='object')c.sizes={};c.sizes[size]=stock;save(req.db);res.status(201).json({ok:true,size,stock});
  }catch(e){res.status(400).json({error:e.message||'Nie udało się dodać rozmiaru.'})}
});

app.put('/api/admin/stock',adminOnly,(req,res)=>{
  ensureStore(req.db);
  const productId=String(req.body?.productId||''),color=String(req.body?.color||''),size=String(req.body?.size||'').toUpperCase();
  const stock=Number(req.body?.stock);
  const slot=req.db.catalog?.[productId]?.colors?.[color]?.sizes;
  if(!slot||!Object.prototype.hasOwnProperty.call(slot,size))return res.status(404).json({error:'Nie znaleziono tego wariantu produktu.'});
  if(!Number.isInteger(stock)||stock<0||stock>9999)return res.status(400).json({error:'Stan musi być liczbą całkowitą od 0 do 9999.'});
  slot[size]=stock;save(req.db);res.json({ok:true,stock});
});
app.put('/api/admin/orders/:id',adminOnly,(req,res)=>{
  try{
    ensureStore(req.db);
    const order=req.db.orders.find(o=>o.id===req.params.id);
    if(!order)return res.status(404).json({error:'Nie znaleziono zamówienia.'});
    const beforePayment=String(order.paymentStatus||'pending');
    const beforeStage=Number(order.shippingStage||0);
    const requestedStatus=String(req.body?.paymentStatus||'');
    if(requestedStatus){
      if(!['pending','paid','cancelled'].includes(requestedStatus))return res.status(400).json({error:'Nieprawidłowy status płatności.'});
      if(order.paymentStatus==='paid'&&requestedStatus!=='paid')return res.status(400).json({error:'Opłaconego zamówienia nie można cofnąć w tym panelu.'});
      if(order.paymentStatus==='cancelled'&&requestedStatus!=='cancelled')return res.status(400).json({error:'Anulowanego zamówienia nie można ponownie aktywować w tym panelu.'});
      if(requestedStatus==='paid')markOrderPaid(req.db,order);else{if(requestedStatus==='cancelled')releaseStockReservation(req.db,order);order.paymentStatus=requestedStatus;}
    }
    if(Object.prototype.hasOwnProperty.call(req.body||{},'shippingStage')){
      const stage=Number(req.body.shippingStage);
      if(!Number.isInteger(stage)||stage<0||stage>4)return res.status(400).json({error:'Etap wysyłki musi być od 0 do 4.'});
      order.shippingStage=stage;
    }
    order.updatedAt=Date.now();
    if(beforePayment!==order.paymentStatus&&order.paymentStatus==='cancelled')orderEvent(order,'cancelled','Zamówienie anulowane','Zamówienie zostało anulowane przez obsługę sklepu.',order.updatedAt);
    if(beforeStage!==Number(order.shippingStage||0)&&order.paymentStatus==='paid'){
      const names=['Nowe','W przygotowaniu','Nadane','W drodze','Dostarczone'];
      const notes=['Zamówienie zostało przyjęte do realizacji.','Produkty są przygotowywane do wysyłki.','Przesyłka została nadana.','Przesyłka jest w drodze.','Przesyłka została dostarczona.'];
      const st=Number(order.shippingStage||0);
      orderEvent(order,`shipping_${st}`,names[st]||'Aktualizacja realizacji',notes[st]||'Status zamówienia został zaktualizowany.',order.updatedAt);
      const mailKey={1:'preparing',2:'shipped',3:'transit',4:'delivered'}[st];
      if(mailKey)sendOrderUpdateEmail(req.db,order,mailKey,{dedupeKey:`shipping_${st}`});
    }
    if(beforePayment!==order.paymentStatus&&order.paymentStatus==='cancelled')sendOrderUpdateEmail(req.db,order,'cancelled',{dedupeKey:'cancelled'});
    save(req.db);res.json({ok:true,order:adminOrder(req.db,order)});
  }catch(e){res.status(400).json({error:e.message||'Nie udało się zaktualizować zamówienia.'})}
});

app.put('/api/account/avatar',auth,(req,res)=>{const avatarData=String(req.body?.avatarData||'');if(avatarData&&!/^data:image\/(jpeg|png|webp);base64,/.test(avatarData))return res.status(400).json({error:'Nieprawidłowy format zdjęcia.'});if(avatarData.length>5_500_000)return res.status(413).json({error:'Zdjęcie jest za duże.'});const i=req.db.users.findIndex(x=>x.id===req.user.id);req.db.users[i].avatarData=avatarData;save(req.db);res.json({ok:true,user:publicUser(req.db.users[i])})});

// STARXV admin — zgłoszenia problemów


app.get('/api/admin/promos',adminOnly,(req,res)=>{ensurePromoCodes(req.db);save(req.db);res.json({ok:true,promos:req.db.promoCodes.map(promoPublic).sort((a,b)=>(b.createdAt||0)-(a.createdAt||0))})});
app.post('/api/admin/promos',adminOnly,(req,res)=>{
  ensurePromoCodes(req.db);
  const code=String(req.body?.code||'').trim().toUpperCase().replace(/\s+/g,'');
  const type=String(req.body?.type||'percent'),value=Number(req.body?.value),minSubtotal=Math.max(0,Number(req.body?.minSubtotal||0));
  const usageRaw=req.body?.usageLimit,usageLimit=(usageRaw===null||usageRaw===''||usageRaw===undefined)?null:Math.max(1,Math.floor(Number(usageRaw)));
  if(!/^[A-Z0-9_-]{3,24}$/.test(code))return res.status(400).json({error:'Kod może mieć 3–24 znaki: litery, cyfry, _ lub -.'});
  if(req.db.promoCodes.some(p=>String(p.code||'').toUpperCase()===code))return res.status(409).json({error:'Taki kod już istnieje.'});
  if(!['percent','fixed'].includes(type)||!Number.isFinite(value)||value<=0||(type==='percent'&&value>100))return res.status(400).json({error:'Nieprawidłowa wartość rabatu.'});
  const p={id:crypto.randomUUID(),code,type,value:Math.round(value*100)/100,minSubtotal:Math.round(minSubtotal*100)/100,usageLimit,usedCount:0,active:req.body?.active!==false,startsAt:req.body?.startsAt||null,endsAt:req.body?.endsAt||null,createdAt:Date.now(),updatedAt:Date.now()};
  req.db.promoCodes.push(p);save(req.db);res.json({ok:true,promo:promoPublic(p)});
});
app.patch('/api/admin/promos/:id',adminOnly,(req,res)=>{
  ensurePromoCodes(req.db);const p=req.db.promoCodes.find(x=>x.id===req.params.id);if(!p)return res.status(404).json({error:'Nie znaleziono kodu.'});
  if(req.body?.active!==undefined)p.active=Boolean(req.body.active);
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
  supportMessages(report).push({id:crypto.randomUUID(),author:'support',text:reply,createdAt:repliedAt});
  report.supportReply=reply;
  report.supportRepliedAt=repliedAt;
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
        from:process.env.MAIL_FROM||'STARXV <no-reply@starxv.pl>',
        to:report.email,
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
