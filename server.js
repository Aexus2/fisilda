// Fısılda — anonim mesaj sitesi. Bağımlılık yok: Node 22.13+ (node:sqlite) yeterli.
const http = require('node:http');
const crypto = require('node:crypto');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT) || 3000;
const TRUST_PROXY = process.env.TRUST_PROXY === '1'; // ters proxy arkasındaysan 1 yap
const SECURE_COOKIE = process.env.SECURE_COOKIE === '1'; // HTTPS'te 1 yap
const MAX_LEN = 500;
const SESSION_DAYS = 30;

const db = new DatabaseSync(process.env.DB_PATH || path.join(__dirname, 'data.db'));
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pass TEXT NOT NULL, created_at INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS sessions(
    token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS messages(
    id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, body TEXT NOT NULL,
    sender TEXT NOT NULL, read INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
  CREATE INDEX IF NOT EXISTS messages_user ON messages(user_id, id DESC);
  CREATE TABLE IF NOT EXISTS blocks(
    user_id INTEGER NOT NULL, sender TEXT NOT NULL, PRIMARY KEY(user_id, sender));
  CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
`);

// Gönderen IP'leri düz saklanmaz; bu anahtarla HMAC'lenir (sadece engelleme için kullanılır).
let secret = db.prepare('SELECT v FROM meta WHERE k = ?').get('secret')?.v;
if (!secret) {
  secret = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO meta(k, v) VALUES(?, ?)').run('secret', secret);
}

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const senderId = (ip) => crypto.createHmac('sha256', secret).update(ip).digest('hex').slice(0, 32);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  return salt.toString('hex') + ':' + crypto.scryptSync(pw, salt, 64).toString('hex');
}
function checkPassword(pw, stored) {
  const [salt, hash] = stored.split(':');
  const a = Buffer.from(hash, 'hex');
  const b = crypto.scryptSync(pw, Buffer.from(salt, 'hex'), 64);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// Basit bellek içi hız sınırı
const buckets = new Map();
function limited(key, max, windowMs) {
  const now = Date.now();
  const hits = (buckets.get(key) || []).filter((t) => now - t < windowMs);
  if (hits.length >= max) { buckets.set(key, hits); return true; }
  hits.push(now);
  buckets.set(key, hits);
  return false;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of buckets) if (!v.some((t) => now - t < 3600e3)) buckets.delete(k);
  db.prepare('DELETE FROM sessions WHERE expires < ?').run(now);
}, 600e3).unref();

function clientIp(req) {
  if (TRUST_PROXY && req.headers['x-forwarded-for']) return req.headers['x-forwarded-for'].split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}
function cookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}
function currentUser(req) {
  const token = cookies(req).sid;
  if (!token) return null;
  return db.prepare(`SELECT u.id, u.username FROM sessions s JOIN users u ON u.id = s.user_id
                     WHERE s.token = ? AND s.expires > ?`).get(sha(token), Date.now()) || null;
}
function startSession(res, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions(token, user_id, expires) VALUES(?, ?, ?)')
    .run(sha(token), userId, Date.now() + SESSION_DAYS * 864e5);
  res.setHeader('Set-Cookie',
    `sid=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}${SECURE_COOKIE ? '; Secure' : ''}`);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (data.length > 20000) { reject(new Error('too large')); req.destroy(); }
    });
    req.on('end', () => resolve(Object.fromEntries(new URLSearchParams(data))));
    req.on('error', reject);
  });
}
function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true; // SameSite=Lax çerez zaten siteler arası POST'u engeller
  try { return new URL(origin).host === req.headers.host; } catch { return false; }
}

// ---------- Görünümler ----------
const CSS = `
:root{--bg1:#ff5f6d;--bg2:#7b2ff7;--card:#fff;--ink:#16131f;--mut:#6b6780;--line:#e8e5f0;--acc:#7b2ff7}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:var(--ink);
  background:linear-gradient(160deg,var(--bg1),var(--bg2)) fixed;display:flex;flex-direction:column;align-items:center;padding:24px 16px 48px}
a{color:inherit}
header{width:100%;max-width:460px;display:flex;justify-content:space-between;align-items:center;color:#fff;margin-bottom:20px}
.logo{font-weight:800;font-size:22px;letter-spacing:-.02em;text-decoration:none}
header form button,header a.link{background:rgba(255,255,255,.2);color:#fff;border:0;border-radius:999px;padding:7px 14px;font:inherit;font-size:14px;cursor:pointer;text-decoration:none}
main{width:100%;max-width:460px;display:grid;gap:16px}
.card{background:var(--card);border-radius:22px;padding:22px;box-shadow:0 12px 40px rgba(20,0,60,.25)}
h1{font-size:26px;line-height:1.2;margin:0 0 8px;letter-spacing:-.02em;text-wrap:balance}
h2{font-size:18px;margin:0 0 12px}
p{margin:0 0 12px;color:var(--mut)}
.hero{color:#fff;text-align:center;padding:8px 8px 4px}.hero p{color:rgba(255,255,255,.9)}
label{display:block;font-size:14px;font-weight:600;margin:12px 0 6px}
input,textarea{width:100%;font:inherit;padding:13px 14px;border:1.5px solid var(--line);border-radius:14px;background:#faf9fd;color:var(--ink)}
textarea{min-height:140px;resize:vertical}
input:focus,textarea:focus{outline:2px solid var(--acc);outline-offset:1px;border-color:transparent}
.btn{display:block;width:100%;margin-top:16px;padding:14px;border:0;border-radius:999px;background:var(--ink);color:#fff;font:inherit;font-weight:700;cursor:pointer;text-align:center;text-decoration:none}
.btn.alt{background:#f1eef9;color:var(--ink)}
.row{display:flex;gap:8px}.row>*{flex:1}
.err{background:#ffe9ea;color:#a3121f;border-radius:12px;padding:10px 14px;font-size:14px;margin-bottom:8px}
.ok{background:#e7f8ee;color:#12693a}
.who{display:flex;align-items:center;gap:12px;margin-bottom:14px}
.avatar{width:48px;height:48px;border-radius:50%;background:linear-gradient(135deg,var(--bg1),var(--bg2));color:#fff;display:grid;place-items:center;font-weight:800;font-size:20px;flex:none}
.who b{display:block}.who span{color:var(--mut);font-size:14px}
.meta{display:flex;justify-content:space-between;align-items:center;font-size:13px;color:var(--mut);margin-top:6px}
.dice{background:none;border:0;font-size:20px;cursor:pointer;padding:4px}
.linkbox{display:flex;gap:8px}.linkbox input{flex:1;min-width:0;font-size:14px}
.linkbox button{flex:none;border:0;border-radius:14px;padding:0 16px;background:var(--acc);color:#fff;font:inherit;font-weight:700;cursor:pointer}
.msg{position:relative}.msg.new{outline:3px solid #ffd84d}
.msg .body{font-size:18px;font-weight:600;white-space:pre-wrap;overflow-wrap:anywhere;margin-bottom:10px}
.msg .foot{display:flex;justify-content:space-between;align-items:center;gap:8px;font-size:13px;color:var(--mut)}
.msg .foot form{display:inline}
.msg .foot button{background:none;border:0;color:var(--mut);font:inherit;font-size:13px;cursor:pointer;text-decoration:underline;padding:4px}
.msg .foot .share{background:var(--acc);color:#fff;text-decoration:none;font-weight:700;border-radius:999px;padding:6px 14px}
[hidden]{display:none!important}
dialog{border:0;border-radius:22px;padding:18px;width:min(92vw,380px);max-height:94vh;overflow:auto;box-shadow:0 20px 60px rgba(0,0,0,.4)}
dialog::backdrop{background:rgba(10,0,30,.6)}
dialog img{display:block;height:min(40vh,420px);margin:0 auto 4px;border-radius:14px}
dialog .btn{margin-top:10px;padding:12px}
dialog small{display:block;color:var(--mut);margin-top:10px;text-align:center}
.empty{text-align:center;color:#fff;padding:24px 8px}
.nav{display:flex;gap:8px;align-items:center}
.stats{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.stats div{background:#f6f4fb;border-radius:14px;padding:12px 14px}
.stats b{display:block;font-size:26px;line-height:1.1;font-variant-numeric:tabular-nums}
.stats span{font-size:13px;color:var(--mut)}
.urow{border-top:1px solid var(--line);padding:12px 0;margin-top:12px}
.urow>div>span:not(.tag){display:block;font-size:13px;color:var(--mut)}
.urow .acts{display:flex;flex-wrap:wrap;gap:6px 14px;margin-top:6px;font-size:14px}
.urow .acts form{display:inline}
.urow .acts button{background:none;border:0;padding:0;font:inherit;text-decoration:underline;cursor:pointer;color:inherit}
.urow .acts .danger{color:#a3121f}
.tag{font-size:11px;font-weight:700;background:var(--acc);color:#fff;border-radius:999px;padding:2px 8px;vertical-align:middle}
footer{margin-top:28px;color:rgba(255,255,255,.75);font-size:13px;text-align:center}
`;

function page(res, { title, user, body, status = 200 }) {
  const nav = user
    ? `<span class="nav">${isAdmin(user) ? '<a class="link" href="/admin">Yönetim</a>' : ''}<form method="post" action="/logout"><button>Çıkış</button></form></span>`
    : '';
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Security-Policy': "default-src 'self'; img-src 'self' blob: data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'same-origin',
    'Cache-Control': 'no-store',
  });
  res.end(`<!doctype html><html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>${CSS}</style></head><body>
<header><a class="logo" href="/">fısılda 🤫</a>${nav}</header>
<main>${body}</main>
<footer>Mesajlar anonimdir. Lütfen nazik ol.</footer>
</body></html>`);
}
const redirect = (res, to) => { res.writeHead(303, { Location: to }); res.end(); };

function homeView(res, { error = '', mode = 'register', username = '' } = {}) {
  const isReg = mode === 'register';
  page(res, {
    title: 'Fısılda — anonim mesaj al',
    status: error ? 400 : 200,
    body: `
<div class="hero"><h1>Arkadaşların sana anonim olarak ne söylerdi?</h1>
<p>Linkini al, hikâyende paylaş, gelen mesajları oku.</p></div>
<div class="card">
  <h2>${isReg ? 'Linkini oluştur' : 'Giriş yap'}</h2>
  ${error ? `<div class="err">${esc(error)}</div>` : ''}
  <form method="post" action="/${isReg ? 'register' : 'login'}">
    <label for="u">Kullanıcı adı</label>
    <input id="u" name="username" value="${esc(username)}" autocomplete="username" autocapitalize="none" required minlength="3" maxlength="20" placeholder="ornek_ad">
    <label for="p">Şifre</label>
    <input id="p" name="password" type="password" autocomplete="${isReg ? 'new-password' : 'current-password'}" required minlength="6" maxlength="200">
    <button class="btn">${isReg ? 'Linkimi oluştur' : 'Giriş yap'}</button>
  </form>
  <a class="btn alt" href="/?mode=${isReg ? 'login' : 'register'}">${isReg ? 'Zaten hesabım var' : 'Yeni hesap oluştur'}</a>
</div>`,
  });
}

const PROMPTS = [
  'Benim hakkımda ilk izlenimin neydi?', 'Bana söylemeye çekindiğin bir şey var mı?',
  'Sence en iyi özelliğim ne?', 'Beni üç kelimeyle anlat.', 'Bana bir şarkı öner.',
  'Birlikte yapmak istediğin bir şey?', 'Bana bir tavsiye ver.', 'Benimle ilgili en sevdiğin anı?',
];

function profileView(res, target, { error = '', text = '', sent = false, status = 200 } = {}) {
  const body = sent
    ? `<div class="card" style="text-align:center"><h1>Gönderildi ✅</h1>
       <p>Mesajın @${esc(target.username)} adlı kişiye anonim olarak iletildi.</p>
       <a class="btn" href="/">Sen de kendi linkini al</a>
       <a class="btn alt" href="/u/${esc(target.username)}">Bir mesaj daha gönder</a></div>`
    : `<div class="card">
  <div class="who"><div class="avatar">${esc(target.username[0].toUpperCase())}</div>
    <div><b>@${esc(target.username)}</b><span>bana anonim bir mesaj gönder!</span></div></div>
  ${error ? `<div class="err">${esc(error)}</div>` : ''}
  <form method="post" action="/u/${esc(target.username)}">
    <textarea id="t" name="text" maxlength="${MAX_LEN}" required placeholder="Buraya yaz… kim olduğun görünmez.">${esc(text)}</textarea>
    <div class="meta"><span><span id="n">${text.length}</span>/${MAX_LEN}</span>
      <button type="button" class="dice" id="dice" title="Rastgele soru" aria-label="Rastgele soru">🎲</button></div>
    <input name="website" tabindex="-1" autocomplete="off" aria-hidden="true" style="position:absolute;left:-9999px;width:1px;height:1px">
    <button class="btn">Anonim gönder</button>
  </form>
</div>
<script>
const t=document.getElementById('t'),n=document.getElementById('n'),P=${JSON.stringify(PROMPTS)};
t.addEventListener('input',()=>n.textContent=t.value.length);
document.getElementById('dice').addEventListener('click',()=>{t.value=P[Math.floor(Math.random()*P.length)];n.textContent=t.value.length;t.focus()});
</script>`;
  page(res, { title: `@${target.username} — anonim mesaj gönder`, status, body });
}

const fmtDate = (ms) => new Date(ms).toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul', day: 'numeric', month: 'long', hour: '2-digit', minute: '2-digit' });

const SHARE_JS = String.raw`
(function(){
var dlg=document.getElementById('share'),img=document.getElementById('shimg'),blob=null,
    LINK=document.getElementById('link').value,F='system-ui,-apple-system,"Segoe UI",Roboto,sans-serif';
function rr(c,x,y,w,h,r){c.beginPath();c.moveTo(x+r,y);c.arcTo(x+w,y,x+w,y+h,r);c.arcTo(x+w,y+h,x,y+h,r);c.arcTo(x,y+h,x,y,r);c.arcTo(x,y,x+w,y,r);c.closePath()}
function wrap(c,text,maxW){var out=[];text.split(/\r?\n/).forEach(function(par){var line='';par.split(' ').forEach(function(word){
  var t=line?line+' '+word:word;
  if(c.measureText(t).width<=maxW){line=t;return}
  if(line)out.push(line);
  while(c.measureText(word).width>maxW){var i=word.length;while(i>1&&c.measureText(word.slice(0,i)).width>maxW)i--;out.push(word.slice(0,i));word=word.slice(i)}
  line=word});out.push(line)});return out}
// 1080x1920: Instagram/TikTok hikâye boyutu
function draw(text){
  var W=1080,H=1920,cv=document.createElement('canvas');cv.width=W;cv.height=H;var c=cv.getContext('2d');
  var g=c.createLinearGradient(0,0,W,H);g.addColorStop(0,'#ff5f6d');g.addColorStop(1,'#7b2ff7');c.fillStyle=g;c.fillRect(0,0,W,H);
  var cw=900,pad=64,headH=190,maxH=1000,size=68,lines,lh;
  for(;;){c.font='700 '+size+'px '+F;lines=wrap(c,text,cw-pad*2);lh=Math.round(size*1.3);if(lines.length*lh<=maxH||size<=30)break;size-=4}
  var maxLines=Math.floor(maxH/lh);
  if(lines.length>maxLines){lines=lines.slice(0,maxLines);lines[maxLines-1]=lines[maxLines-1].slice(0,-2)+'…'}
  var bodyH=Math.max(lines.length*lh,lh*2)+pad*2,ch=headH+bodyH,x=(W-cw)/2,y=(H-ch)/2-60;
  c.save();c.shadowColor='rgba(20,0,60,.35)';c.shadowBlur=60;c.shadowOffsetY=24;rr(c,x,y,cw,ch,56);c.fillStyle='#fff';c.fill();c.restore();
  c.save();rr(c,x,y,cw,ch,56);c.clip();c.fillStyle='#16131f';c.fillRect(x,y,cw,headH);c.restore();
  c.textAlign='center';c.textBaseline='middle';
  c.fillStyle='#fff';c.font='800 54px '+F;c.fillText('bana anonim mesaj gönder!',W/2,y+headH/2);
  c.fillStyle='#16131f';c.font='700 '+size+'px '+F;
  var ty=y+headH+pad+(bodyH-pad*2-lines.length*lh)/2+lh/2;
  lines.forEach(function(l,i){c.fillText(l,W/2,ty+i*lh)});
  c.fillStyle='#fff';c.font='800 60px '+F;c.fillText('fısılda 🤫',W/2,y+ch+130);
  c.globalAlpha=.9;c.font='500 38px '+F;c.fillText(LINK.replace(/^https?:\/\//,''),W/2,y+ch+205);
  return cv}
function file(){return new File([blob],'fisilda-mesaj.png',{type:'image/png'})}
var sys=document.getElementById('shsys'),hint=document.getElementById('shhint'),canFiles=false;
try{canFiles=!!(navigator.canShare&&navigator.canShare({files:[new File(['x'],'a.png',{type:'image/png'})]}))}catch(e){}
sys.hidden=!canFiles;
hint.textContent=canFiles?"Paylaş düğmesine basıp Instagram, X ya da istediğin uygulamayı seç."
  :'Bu tarayıcı doğrudan görsel paylaşamıyor: görseli indir, sonra Instagram ya da X gönderine ekle.';
document.addEventListener('click',function(e){var b=e.target.closest('[data-share]');if(!b)return;
  var text=b.closest('.msg').querySelector('.body').textContent;
  draw(text).toBlob(function(bl){blob=bl;if(img.src)URL.revokeObjectURL(img.src);img.src=URL.createObjectURL(bl);dlg.showModal()},'image/png')});
sys.onclick=function(){navigator.share({files:[file()]}).catch(function(){})};
document.getElementById('shdl').onclick=function(){var a=document.createElement('a');a.href=img.src;a.download='fisilda-mesaj.png';document.body.appendChild(a);a.click();a.remove()};
document.getElementById('shx').href='https://x.com/intent/post?text='+encodeURIComponent('Bana anonim mesaj gönder 🤫')+'&url='+encodeURIComponent(LINK);
document.getElementById('shclose').onclick=function(){dlg.close()};
dlg.addEventListener('click',function(e){if(e.target===dlg)dlg.close()});
})();
`;

function inboxView(req, res, user, notice = '') {
  const msgs = db.prepare('SELECT id, body, read, created_at FROM messages WHERE user_id = ? ORDER BY id DESC LIMIT 200').all(user.id);
  db.prepare('UPDATE messages SET read = 1 WHERE user_id = ? AND read = 0').run(user.id);
  const proto = TRUST_PROXY && req.headers['x-forwarded-proto'] ? req.headers['x-forwarded-proto'].split(',')[0] : 'http';
  const link = `${proto}://${req.headers.host}/u/${user.username}`;
  const list = msgs.length
    ? msgs.map((m) => `<div class="card msg${m.read ? '' : ' new'}">
        <div class="body">${esc(m.body)}</div>
        <div class="foot"><span>${m.read ? '' : 'Yeni · '}${fmtDate(m.created_at)}</span><span>
          <button type="button" class="share" data-share>Paylaş</button>
          <form method="post" action="/inbox/${m.id}/block" onsubmit="return confirm('Bu gönderen sana bir daha mesaj atamayacak. Emin misin?')"><button>Göndereni engelle</button></form>
          <form method="post" action="/inbox/${m.id}/delete" onsubmit="return confirm('Mesaj silinsin mi?')"><button>Sil</button></form>
        </span></div></div>`).join('')
    : `<div class="empty"><h2>Henüz mesaj yok</h2><p style="color:inherit">Linkini paylaş, mesajlar burada görünecek.</p></div>`;
  page(res, {
    title: 'Gelen kutusu — Fısılda', user,
    body: `
<div class="card">
  <h2>Merhaba @${esc(user.username)} 👋</h2>
  <p>Bu linki hikâyende ya da biyografinde paylaş:</p>
  ${notice ? `<div class="err ok">${esc(notice)}</div>` : ''}
  <div class="linkbox"><input id="link" readonly value="${esc(link)}"><button id="copy" type="button">Kopyala</button></div>
</div>
${list}
<dialog id="share" aria-label="Mesajı paylaş">
  <img id="shimg" alt="Paylaşılacak mesaj görseli">
  <button class="btn" id="shsys" type="button">Paylaş (Instagram, X, WhatsApp…)</button>
  <button class="btn alt" id="shdl" type="button">Görseli indir</button>
  <a class="btn alt" id="shx" target="_blank" rel="noopener">X'te gönderi aç</a>
  <button class="btn alt" id="shclose" type="button">Kapat</button>
  <small id="shhint"></small>
</dialog>
<script>${SHARE_JS}</script>
<script>
const b=document.getElementById('copy'),l=document.getElementById('link');
b.addEventListener('click',async()=>{
  if(navigator.share){try{await navigator.share({title:'Bana anonim mesaj gönder',url:l.value});return}catch(e){}}
  try{await navigator.clipboard.writeText(l.value)}catch(e){l.select();document.execCommand('copy')}
  b.textContent='Kopyalandı';setTimeout(()=>b.textContent='Kopyala',1500)});
</script>`,
  });
}

// ---------- Rotalar ----------
// ---------- Yönetim paneli ----------
// Yöneticiler ADMIN_USERS ortam değişkeniyle belirlenir (virgülle ayrılmış kullanıcı adları).
// Panel mesaj içeriklerini göstermez: yalnızca sayılar ve hesap işlemleri.
const ADMINS = new Set((process.env.ADMIN_USERS || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean));
const isAdmin = (user) => !!user && ADMINS.has(user.username);

function adminView(res, user, { q = '', notice = '', error = '' } = {}) {
  const day = Date.now() - 864e5;
  const n = (sql, ...a) => db.prepare(sql).get(...a).n;
  const stats = [
    ['Kullanıcı', n('SELECT COUNT(*) n FROM users')],
    ['Son 24 saatte yeni üye', n('SELECT COUNT(*) n FROM users WHERE created_at > ?', day)],
    ['Kayıtlı mesaj', n('SELECT COUNT(*) n FROM messages')],
    ['Son 24 saatte mesaj', n('SELECT COUNT(*) n FROM messages WHERE created_at > ?', day)],
  ];
  const like = '%' + q.replace(/[\\%_]/g, '\\$&') + '%';
  const users = db.prepare(`SELECT u.id, u.username, u.created_at,
      (SELECT COUNT(*) FROM messages m WHERE m.user_id = u.id) AS msgs,
      (SELECT MAX(m.created_at) FROM messages m WHERE m.user_id = u.id) AS last_msg
    FROM users u WHERE u.username LIKE ? ESCAPE '\\' ORDER BY u.id DESC LIMIT 100`).all(like);
  const rows = users.map((u) => `<div class="urow">
      <div><b>@${esc(u.username)}</b>${ADMINS.has(u.username) ? ' <span class="tag">yönetici</span>' : ''}
        <span>Kayıt: ${fmtDate(u.created_at)} · ${u.msgs} mesaj${u.last_msg ? ' · son: ' + fmtDate(u.last_msg) : ''}</span></div>
      <div class="acts">
        <a href="/u/${esc(u.username)}">Sayfası</a>
        <form method="post" action="/admin/users/${u.id}/reset" onsubmit="return confirm('@${esc(u.username)} için yeni şifre üretilsin mi? Açık oturumları kapanır.')"><button>Şifre sıfırla</button></form>
        ${u.id === user.id ? '' : `<form method="post" action="/admin/users/${u.id}/delete" onsubmit="return confirm('@${esc(u.username)} hesabı ve tüm mesajları kalıcı olarak silinsin mi?')"><button class="danger">Hesabı sil</button></form>`}
      </div></div>`).join('');
  page(res, {
    title: 'Yönetim — Fısılda', user, status: error ? 400 : 200,
    body: `
<div class="card">
  <h2>Yönetim paneli</h2>
  ${notice ? `<div class="err ok">${notice}</div>` : ''}
  ${error ? `<div class="err">${esc(error)}</div>` : ''}
  <div class="stats">${stats.map(([k, v]) => `<div><b>${v}</b><span>${k}</span></div>`).join('')}</div>
</div>
<div class="card">
  <h2>Kullanıcılar</h2>
  <form method="get" action="/admin" class="linkbox">
    <input name="q" value="${esc(q)}" placeholder="Kullanıcı adı ara" autocapitalize="none" maxlength="20">
    <button>Ara</button>
  </form>
  ${rows || '<p style="margin-top:14px">Eşleşen kullanıcı yok.</p>'}
  ${users.length === 100 ? '<p style="margin-top:14px">İlk 100 sonuç gösteriliyor; daraltmak için ara.</p>' : ''}
</div>
<a class="btn alt" href="/inbox">Gelen kutuma dön</a>`,
  });
}

async function adminRoutes(req, res, url, user) {
  const p = url.pathname;
  if (req.method === 'GET' && p === '/admin') {
    const notice = url.searchParams.get('n') === 'deleted' ? 'Hesap silindi.' : '';
    return adminView(res, user, { q: String(url.searchParams.get('q') || '').slice(0, 20), notice });
  }
  const m = p.match(/^\/admin\/users\/(\d+)\/(reset|delete)$/);
  if (!m || req.method !== 'POST') return false;
  const target = db.prepare('SELECT id, username FROM users WHERE id = ?').get(Number(m[1]));
  if (!target) return adminView(res, user, { error: 'Kullanıcı bulunamadı.' });

  if (m[2] === 'reset') {
    const pw = crypto.randomBytes(7).toString('base64url');
    db.prepare('UPDATE users SET pass = ? WHERE id = ?').run(hashPassword(pw), target.id);
    if (target.id !== user.id) db.prepare('DELETE FROM sessions WHERE user_id = ?').run(target.id);
    console.log(`[admin] ${user.username} -> şifre sıfırlama: ${target.username}`);
    // Şifre yalnızca bu yanıtta gösterilir; adrese ya da günlüğe yazılmaz.
    return adminView(res, user, { notice: `@${esc(target.username)} için yeni şifre: <b>${esc(pw)}</b> — bir daha gösterilmeyecek, şimdi not al.` });
  }
  if (target.id === user.id) return adminView(res, user, { error: 'Kendi hesabını buradan silemezsin.' });
  db.exec('BEGIN');
  try {
    for (const t of ['messages', 'blocks', 'sessions']) db.prepare(`DELETE FROM ${t} WHERE user_id = ?`).run(target.id);
    db.prepare('DELETE FROM users WHERE id = ?').run(target.id);
    db.exec('COMMIT');
  } catch (e) { db.exec('ROLLBACK'); throw e; }
  console.log(`[admin] ${user.username} -> hesap silme: ${target.username}`);
  return redirect(res, '/admin?n=deleted');
}

const USERNAME_RE = /^[a-z0-9_.]{3,20}$/;
const RESERVED = new Set(['admin', 'inbox', 'login', 'logout', 'register', 'root', 'destek', 'fisilda']);

async function handle(req, res) {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  const ip = clientIp(req);
  const user = currentUser(req);

  if (req.method !== 'GET' && req.method !== 'POST') { res.writeHead(405); return res.end(); }
  if (req.method === 'POST' && !sameOrigin(req)) { res.writeHead(403); return res.end('Forbidden'); }

  if (req.method === 'GET' && p === '/') {
    if (user) return redirect(res, '/inbox');
    return homeView(res, { mode: url.searchParams.get('mode') === 'login' ? 'login' : 'register' });
  }

  if (req.method === 'POST' && (p === '/register' || p === '/login')) {
    const mode = p.slice(1);
    const f = await readBody(req);
    const username = String(f.username || '').trim().toLowerCase();
    const password = String(f.password || '');
    const fail = (error) => homeView(res, { error, mode, username });
    if (limited(`auth:${ip}`, 10, 600e3)) return fail('Çok fazla deneme yaptın. Birkaç dakika sonra tekrar dene.');

    if (mode === 'register') {
      if (!USERNAME_RE.test(username) || RESERVED.has(username))
        return fail('Kullanıcı adı 3–20 karakter olmalı; yalnızca küçük harf, rakam, alt çizgi ve nokta kullan.');
      if (password.length < 6 || password.length > 200) return fail('Şifre en az 6 karakter olmalı.');
      if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(username)) return fail('Bu kullanıcı adı alınmış.');
      const r = db.prepare('INSERT INTO users(username, pass, created_at) VALUES(?, ?, ?)').run(username, hashPassword(password), Date.now());
      startSession(res, Number(r.lastInsertRowid));
      return redirect(res, '/inbox');
    }
    const row = db.prepare('SELECT id, pass FROM users WHERE username = ?').get(username);
    if (!row || !checkPassword(password, row.pass)) return fail('Kullanıcı adı veya şifre hatalı.');
    startSession(res, row.id);
    return redirect(res, '/inbox');
  }

  if (req.method === 'POST' && p === '/logout') {
    const token = cookies(req).sid;
    if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(sha(token));
    res.setHeader('Set-Cookie', 'sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
    return redirect(res, '/');
  }

  if (p === '/admin' || p.startsWith('/admin/')) {
    // Yönetici olmayanlara panelin varlığı belli edilmez.
    if (isAdmin(user) && (await adminRoutes(req, res, url, user)) !== false) return;
    return page(res, { title: 'Bulunamadı', status: 404, user, body: '<div class="card"><h1>Sayfa bulunamadı</h1><a class="btn" href="/">Ana sayfa</a></div>' });
  }

  if (p === '/inbox' && req.method === 'GET') {
    if (!user) return redirect(res, '/?mode=login');
    const notice = url.searchParams.get('n') === 'blocked' ? 'Gönderen engellendi.' : '';
    return inboxView(req, res, user, notice);
  }

  const act = p.match(/^\/inbox\/(\d+)\/(delete|block)$/);
  if (act && req.method === 'POST') {
    if (!user) return redirect(res, '/?mode=login');
    const msg = db.prepare('SELECT id, sender FROM messages WHERE id = ? AND user_id = ?').get(Number(act[1]), user.id);
    if (msg && act[2] === 'block') {
      db.prepare('INSERT OR IGNORE INTO blocks(user_id, sender) VALUES(?, ?)').run(user.id, msg.sender);
      db.prepare('DELETE FROM messages WHERE user_id = ? AND sender = ?').run(user.id, msg.sender);
      return redirect(res, '/inbox?n=blocked');
    }
    if (msg) db.prepare('DELETE FROM messages WHERE id = ?').run(msg.id);
    return redirect(res, '/inbox');
  }

  const prof = p.match(/^\/u\/([A-Za-z0-9_.]{3,20})$/);
  if (prof) {
    const target = db.prepare('SELECT id, username FROM users WHERE username = ?').get(prof[1].toLowerCase());
    if (!target) return page(res, { title: 'Bulunamadı', status: 404, body: `<div class="card"><h1>Böyle bir kullanıcı yok</h1><a class="btn" href="/">Ana sayfa</a></div>` });
    if (req.method === 'GET') return profileView(res, target, { sent: url.searchParams.has('sent') });

    const f = await readBody(req);
    const text = String(f.text || '').replace(/\r\n/g, '\n').trim();
    if (!text) return profileView(res, target, { error: 'Mesaj boş olamaz.', status: 400 });
    if ([...text].length > MAX_LEN) return profileView(res, target, { error: `Mesaj en fazla ${MAX_LEN} karakter olabilir.`, text: text.slice(0, MAX_LEN), status: 400 });
    if (limited(`msg:${ip}:${target.id}`, 5, 600e3) || limited(`msgall:${ip}`, 30, 3600e3))
      return profileView(res, target, { error: 'Çok hızlı gidiyorsun. Biraz sonra tekrar dene.', text, status: 429 });

    const sender = senderId(ip);
    const blocked = db.prepare('SELECT 1 FROM blocks WHERE user_id = ? AND sender = ?').get(target.id, sender);
    // Bot tuzağı doluysa ya da gönderen engelliyse sessizce yut: başarılı görünür ama kaydedilmez.
    if (!f.website && !blocked)
      db.prepare('INSERT INTO messages(user_id, body, sender, created_at) VALUES(?, ?, ?, ?)').run(target.id, text, sender, Date.now());
    return redirect(res, `/u/${target.username}?sent`);
  }

  page(res, { title: 'Bulunamadı', status: 404, user, body: `<div class="card"><h1>Sayfa bulunamadı</h1><a class="btn" href="/">Ana sayfa</a></div>` });
}

http.createServer((req, res) => {
  handle(req, res).catch((err) => {
    console.error(err);
    if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Bir şeyler ters gitti.');
  });
}).listen(PORT, () => console.log(`Fısılda http://localhost:${PORT} adresinde çalışıyor`));
