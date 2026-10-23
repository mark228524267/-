// deno-lint-ignore-file no-explicit-any
// PartPay: сервер + сайт в одном файле. База: Deno KV. Пароль админа: переменная ADMIN_PASSWORD.
const kv: any = await Deno.openKv();
const ADMIN_PW = Deno.env.get("ADMIN_PASSWORD") ?? "";
const enc = new TextEncoder();
const hex = (b: ArrayBuffer) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
async function hashPw(pw: string, salt: string) {
  const k = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  return hex(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: 100000 }, k, 256));
}
const normName = (s: string) => String(s || "").trim().replace(/\s+/g, " ").toLowerCase().replace(/ё/g, "е");
const json = (d: unknown, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { "content-type": "application/json" } });
class Err extends Error { s: number; constructor(m: string, s = 400) { super(m); this.s = s; } }
const token = (req: Request) => (req.headers.get("authorization") || "").replace("Bearer ", "");
const toCents = (x: unknown) => { const c = Math.round(Number(x) * 100); if (!Number.isFinite(c) || c <= 0 || c > 1e12) throw new Err("Введите сумму больше нуля"); return c; };

async function user(req: Request) {
  const t = token(req); const s = t && await kv.get(["sess", t]);
  const a = s && s.value && await kv.get(["acct", s.value]);
  if (!a || !a.value) throw new Err("Войдите в аккаунт", 401);
  return a.value;
}
async function admin(req: Request) {
  const t = token(req); const s = t && await kv.get(["asess", t]);
  if (!s || !s.value) throw new Err("Нет доступа", 401);
}
async function move(from: string | null, to: string | null, cents: number, type: string) {
  for (let i = 0; i < 8; i++) {
    const f = from ? await kv.get(["acct", from]) : null, t = to ? await kv.get(["acct", to]) : null;
    if (f && !f.value) throw new Err("Аккаунт отправителя не найден");
    if (t && !t.value) throw new Err("Аккаунт получателя не найден");
    if (f && f.value.bal < cents) throw new Err("Недостаточно средств на счёте");
    const op = kv.atomic();
    if (f) op.check(f).set(f.key, { ...f.value, bal: f.value.bal - cents });
    if (t) op.check(t).set(t.key, { ...t.value, bal: t.value.bal + cents });
    const now = Date.now();
    op.set(["tx", now, crypto.randomUUID()], { ts: now, type, cents, fromE: from, toE: to, from: f?.value.name, to: t?.value.name });
    if ((await op.commit()).ok) return;
  }
  throw new Err("Сервер занят, повторите попытку", 503);
}
async function session(prefix: string, val: string, ttl: number) {
  const t = crypto.randomUUID() + crypto.randomUUID();
  await kv.set([prefix, t], val, { expireIn: ttl });
  return t;
}

async function sendCode(email: string) {
  const p = await kv.get(["pend", email]);
  if (!p.value) throw new Err("Сначала заполните регистрацию");
  if (Date.now() - p.value.sent < 30000) throw new Err("Подождите 30 секунд перед повторной отправкой");
  const E = (k: string) => Deno.env.get(k) ?? "";
  if (!E("EMAILJS_SERVICE_ID") || !E("EMAILJS_TEMPLATE_ID") || !E("EMAILJS_PUBLIC_KEY") || !E("EMAILJS_PRIVATE_KEY")) throw new Err("Отправка писем не настроена администратором", 500);
  const code = String(100000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900000));
  const r = await fetch("https://api.emailjs.com/api/v1.0/email/send", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ service_id: E("EMAILJS_SERVICE_ID"), template_id: E("EMAILJS_TEMPLATE_ID"), user_id: E("EMAILJS_PUBLIC_KEY"), accessToken: E("EMAILJS_PRIVATE_KEY"), template_params: { to_email: email, name: p.value.name, code } }),
  });
  if (!r.ok) { console.error("EmailJS:", r.status, await r.text()); throw new Err("Не удалось отправить письмо. Проверьте адрес и повторите попытку", 502); }
  await kv.set(p.key, { ...p.value, code, tries: 0, sent: Date.now() }, { expireIn: 15 * 6e4 });
}

async function api(path: string, req: Request, b: any) {
  if (path === "register") {
    const name = String(b.name || "").trim().replace(/\s+/g, " "), nk = normName(name), email = String(b.email || "").trim().toLowerCase(), pw = String(b.password || "");
    if (nk.split(" ").length < 2 || nk.length < 4 || name.length > 80) throw new Err("Введите имя и фамилию");
    if (!/^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$/.test(email) || email.length > 120) throw new Err("Введите корректную почту");
    if (pw.length < 6 || pw.length > 200) throw new Err("Пароль должен быть не короче 6 символов");
    if ((await kv.get(["acct", email])).value || (await kv.get(["name", nk])).value) throw new Err("Эта почта или это имя и фамилия уже зарегистрированы");
    const salt = crypto.randomUUID();
    await kv.set(["pend", email], { name, nameKey: nk, salt, hash: await hashPw(pw, salt), code: "", tries: 0, sent: 0 }, { expireIn: 15 * 6e4 });
    await sendCode(email); return { sent: true };
  }
  if (path === "resend") { await sendCode(String(b.email || "").trim().toLowerCase()); return { sent: true }; }
  if (path === "verify") {
    const email = String(b.email || "").trim().toLowerCase(), p = await kv.get(["pend", email]);
    if (!p.value || !p.value.code) throw new Err("Код устарел, зарегистрируйтесь заново");
    if (String(b.code || "").trim() !== p.value.code) {
      if (p.value.tries + 1 >= 5) { await kv.delete(p.key); throw new Err("Слишком много попыток, зарегистрируйтесь заново"); }
      await kv.set(p.key, { ...p.value, tries: p.value.tries + 1 }, { expireIn: 15 * 6e4 });
      throw new Err("Неверный код");
    }
    const v = p.value, acct = { email, name: v.name, nameKey: v.nameKey, salt: v.salt, hash: v.hash, bal: 0, created: Date.now() };
    const r = await kv.atomic().check({ key: ["acct", email], versionstamp: null }).check({ key: ["name", v.nameKey], versionstamp: null })
      .set(["acct", email], acct).set(["name", v.nameKey], email).delete(p.key).commit();
    if (!r.ok) throw new Err("Эта почта или это имя и фамилия уже зарегистрированы");
    return { token: await session("sess", email, 30 * 864e5) };
  }
  if (path === "login") {
    const email = String(b.email || "").trim().toLowerCase(), a = await kv.get(["acct", email]);
    if (!a.value || await hashPw(String(b.password || ""), a.value.salt) !== a.value.hash) throw new Err("Неверная почта или пароль", 401);
    return { token: await session("sess", email, 30 * 864e5) };
  }
  if (path === "logout") { await kv.delete(["sess", token(req)]); await kv.delete(["asess", token(req)]); return {}; }
  if (path === "me") {
    const a = await user(req), history = [];
    for await (const e of kv.list({ prefix: ["tx"] }, { reverse: true, limit: 500 })) {
      if (e.value.fromE === a.email || e.value.toE === a.email) history.push(e.value);
      if (history.length >= 15) break;
    }
    return { name: a.name, email: a.email, bal: a.bal, history };
  }
  if (path === "transfer") {
    const a = await user(req), cents = toCents(b.amount), n = await kv.get(["name", normName(b.to)]);
    if (!n.value) throw new Err("Получатель с таким именем и фамилией не найден");
    if (n.value === a.email) throw new Err("Нельзя переводить деньги самому себе");
    await move(a.email, n.value, cents, "transfer"); return {};
  }
  if (path === "admin/login") {
    if (!ADMIN_PW || String(b.password || "") !== ADMIN_PW) throw new Err("Неверный пароль администратора", 401);
    return { token: await session("asess", "1", 12 * 36e5) };
  }
  await admin(req);
  if (path === "admin/list") {
    const accounts = [];
    for await (const e of kv.list({ prefix: ["acct"] })) accounts.push({ name: e.value.name, email: e.value.email, bal: e.value.bal });
    return { accounts };
  }
  if (path === "admin/adjust") {
    const amt = Number(b.amount), c = toCents(Math.abs(amt)), email = String(b.email);
    await (amt > 0 ? move(null, email, c, "admin") : move(email, null, c, "admin")); return {};
  }
  if (path === "admin/transfer") {
    if (b.from === b.to) throw new Err("Выберите два разных аккаунта");
    await move(String(b.from), String(b.to), toCents(b.amount), "transfer"); return {};
  }
  throw new Err("Не найдено", 404);
}

const CSS = `:root{--bg:#f4f6fb;--card:#fff;--tx:#1b2233;--mu:#6b7488;--ac:#3b5bdb;--at:#fff;--bd:#dde2ee;--ok:#2b8a3e;--bad:#c92a2a;--hd:#1b2a6b;color-scheme:light dark}
@media(prefers-color-scheme:dark){:root{--bg:#12151f;--card:#1b2030;--tx:#e8ecf6;--mu:#9aa3b8;--ac:#6f8cff;--at:#0d1226;--bd:#2c3347;--ok:#5fd07a;--bad:#ff7b7b;--hd:#0c1236}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:16px/1.45 system-ui,Segoe UI,Roboto,Arial,sans-serif}
header{background:var(--hd);color:#fff;padding:14px 16px;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;font-weight:700;font-size:20px}
header span{font-weight:400;font-size:14px;opacity:.9}main{max-width:640px;margin:0 auto;padding:16px}main.w{max-width:880px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:18px;margin-bottom:16px}h2{margin:0 0 12px;font-size:18px}
label{display:block;font-size:14px;color:var(--mu);margin:10px 0 4px}
input,select{width:100%;padding:11px 12px;border:1px solid var(--bd);border-radius:10px;background:var(--bg);color:var(--tx);font:inherit}
button{font:inherit;cursor:pointer;border:0;border-radius:10px;padding:11px 16px;background:var(--ac);color:var(--at);font-weight:600}
button.g{background:transparent;color:#fff;border:1px solid #fff;padding:6px 12px;font-weight:500}button.r{background:var(--bad);color:#fff}
.f{width:100%;margin-top:14px}.tabs{display:flex;gap:8px;margin-bottom:6px}.tabs button{flex:1;background:var(--bg);color:var(--tx);border:1px solid var(--bd)}.tabs .on{background:var(--ac);color:var(--at)}
.msg{margin-top:12px;font-size:14px;min-height:20px}.err{color:var(--bad)}.ok{color:var(--ok)}.mu{color:var(--mu);font-size:14px}.big{font-size:30px;font-weight:700;padding:6px 0 4px}
ul{list-style:none;margin:0;padding:0}li{display:flex;justify-content:space-between;gap:10px;padding:9px 0;border-top:1px solid var(--bd);font-size:14px}li:first-child{border:0}
.p{color:var(--ok);font-weight:600}.n{color:var(--bad);font-weight:600}.sc{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:9px 8px;border-top:1px solid var(--bd);white-space:nowrap}th{border:0;color:var(--mu);font-weight:500}td input{width:110px;padding:7px}td button{padding:7px 10px;font-size:13px}`;

const JS = `const ADMIN=__ADMIN__,K=ADMIN?'pp_admin':'pp_user',$=s=>document.querySelector(s);let T='';try{T=localStorage.getItem(K)||''}catch(e){}
const esc=s=>String(s).replace(/[&<>"']/g,c=({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]);
const fmt=c=>(c/100).toLocaleString('ru-RU',{minimumFractionDigits:c%100?2:0,maximumFractionDigits:2});
const val=id=>document.getElementById(id).value;
async function api(p,b){const r=await fetch('/api/'+p,{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+T},body:JSON.stringify(b||{})});const d=await r.json();if(!r.ok){const e=new Error(d.error||'Ошибка');e.s=r.status;throw e}return d}
const show=h=>{$('#app').innerHTML=h};
function say(t,c){const m=$('#m');if(m){m.textContent=t;m.className='msg '+(c||'')}}
function setT(t){T=t;try{t?localStorage.setItem(K,t):localStorage.removeItem(K)}catch(e){}}
let tab='login',pend='';
const bar=r=>'<header>PartPay'+(ADMIN?' · администратор':'')+(r?'<div>'+r+'</div>':'')+'</header>';
function authV(){const reg=tab==='reg';show(bar()+'<main><div class="card">'+(ADMIN?'<h2>Вход администратора</h2><label>Пароль администратора</label><input id="pw" type="password"><button class="f" data-a="alogin">Войти</button>':
'<div class="tabs"><button data-a="tab" data-v="login" class="'+(reg?'':'on')+'">Вход</button><button data-a="tab" data-v="reg" class="'+(reg?'on':'')+'">Регистрация</button></div>'+
(reg?'<label>Имя и фамилия</label><input id="nm" autocomplete="name" placeholder="Ермолич Андрей"><p class="mu" style="margin:6px 0 0">Пожалуйста, введите своё настоящее имя и фамилию, иначе при начислении зарплаты вас не смогут идентифицировать и откажут в начислении.</p>':'')+
'<label>Электронная почта</label><input id="em" type="email" autocomplete="email" placeholder="ermolich@part.com"><label>Пароль</label><input id="pw" type="password">'+
(reg?'<label>Повторите пароль</label><input id="pw2" type="password">':'')+'<button class="f" data-a="'+(reg?'reg':'login')+'">'+(reg?'Создать аккаунт':'Войти')+'</button>')+'<div id="m" class="msg"></div></div></main>')}
function codeV(){show(bar()+'<main><div class="card"><h2>Подтверждение почты</h2><p class="mu">Мы отправили письмо с 6-значным кодом на '+esc(pend)+'. Код действует 15 минут.</p><label>Код из письма</label><input id="cd" inputmode="numeric" maxlength="6" autocomplete="one-time-code" placeholder="123456"><button class="f" data-a="verify">Подтвердить</button><button class="f" style="background:var(--bg);color:var(--tx);border:1px solid var(--bd)" data-a="resend">Отправить код ещё раз</button><button class="f" style="background:none;color:var(--mu)" data-a="tab" data-v="reg">Назад</button><div id="m" class="msg"></div></div></main>')}
function homeV(d){const li=d.history.map(e=>{const inc=e.toE===d.email,adm=e.type==='admin',sg=adm?(e.toE?1:-1):(inc?1:-1);
const l=adm?'Корректировка администратором':inc?'Перевод от '+esc(e.from):'Перевод для '+esc(e.to);
return '<li><span>'+l+'<br><span class="mu">'+new Date(e.ts).toLocaleString('ru-RU')+'</span></span><span class="'+(sg>0?'p':'n')+'">'+(sg>0?'+':'−')+fmt(e.cents)+'</span></li>'}).join('');
show(bar('<span>'+esc(d.name)+'</span> <button class="g" data-a="out">Выйти</button>')+'<main><div class="card"><h2>Ваш счёт</h2><div class="big">'+fmt(d.bal)+' партрублей</div></div>'+
'<div class="card"><h2>Перевод на другой аккаунт</h2><label>Имя и фамилия получателя</label><input id="to" placeholder="Иван Иванов"><label>Сумма, партрублей</label><input id="amt" type="number" inputmode="decimal" min="0.01" step="0.01"><button class="f" data-a="send">Перевести</button><div id="m" class="msg"></div></div>'+
'<div class="card"><h2>История операций</h2>'+(li?'<ul>'+li+'</ul>':'<p class="mu">Операций пока нет.</p>')+'</div></main>')}
function admV(d){const A=d.accounts.sort((a,b)=>a.name.localeCompare(b.name,'ru')),tot=A.reduce((s,a)=>s+a.bal,0);
const o=A.map(a=>'<option value="'+esc(a.email)+'">'+esc(a.name+' · '+a.email)+'</option>').join('');
const rows=A.map(a=>'<tr><td>'+esc(a.name)+'</td><td>'+esc(a.email)+'</td><td><b>'+fmt(a.bal)+'</b></td><td><input type="number" min="0.01" step="0.01" placeholder="Сумма" data-e="'+esc(a.email)+'"></td><td><button data-a="adj" data-s="1" data-e="'+esc(a.email)+'">Начислить</button> <button class="r" data-a="adj" data-s="-1" data-e="'+esc(a.email)+'">Снять</button></td></tr>').join('');
show(bar('<button class="g" data-a="out">Выйти</button>')+'<main class="w"><div id="m" class="msg"></div><div class="card"><h2>Все аккаунты ('+A.length+')</h2><p class="mu">Всего в обороте: '+fmt(tot)+' партрублей</p>'+
(A.length?'<div class="sc"><table><thead><tr><th>Имя</th><th>Почта</th><th>Счёт</th><th>Сумма</th><th></th></tr></thead><tbody>'+rows+'</tbody></table></div>':'<p class="mu">Аккаунтов пока нет.</p>')+'</div>'+
(A.length>1?'<div class="card"><h2>Перевод между аккаунтами</h2><label>С аккаунта</label><select id="fr">'+o+'</select><label>На аккаунт</label><select id="tt">'+o+'</select><label>Сумма, партрублей</label><input id="am" type="number" min="0.01" step="0.01"><button class="f" data-a="asend">Перевести</button></div>':'')+'</main>')}
async function load(m){try{if(!T)return authV();const d=await api(ADMIN?'admin/list':'me');ADMIN?admV(d):homeV(d);if(m)say(m,'ok')}catch(e){if(e.s===401){setT('');authV();if(m!==undefined)say(e.message,'err')}else{authV();say(e.message,'err')}}}
document.addEventListener('click',async ev=>{const t=ev.target.closest('[data-a]');if(!t)return;const a=t.dataset.a;
try{if(a==='tab'){tab=t.dataset.v;authV()}
else if(a==='login'){const d=await api('login',{email:val('em'),password:val('pw')});setT(d.token);load()}
else if(a==='reg'){if(val('pw')!==val('pw2'))return say('Пароли не совпадают','err');const em=val('em').trim().toLowerCase();await api('register',{name:val('nm'),email:em,password:val('pw')});pend=em;codeV()}
else if(a==='verify'){const d=await api('verify',{email:pend,code:val('cd')});setT(d.token);load()}
else if(a==='resend'){await api('resend',{email:pend});say('Код отправлен повторно.','ok')}
else if(a==='alogin'){const d=await api('admin/login',{password:val('pw')});setT(d.token);load()}
else if(a==='out'){try{await api('logout')}catch(e){}setT('');authV()}
else if(a==='send'){await api('transfer',{to:val('to'),amount:val('amt')});load('Перевод выполнен.')}
else if(a==='adj'){const i=document.querySelector('input[data-e="'+t.dataset.e+'"]');await api('admin/adjust',{email:t.dataset.e,amount:t.dataset.s*i.value});load('Готово.')}
else if(a==='asend'){await api('admin/transfer',{from:val('fr'),to:val('tt'),amount:val('am')});load('Перевод выполнен.')}
}catch(e){if(e.s===401&&a!=='login'&&a!=='alogin'){setT('');authV()}say(e.message,'err')}});
document.addEventListener('keydown',e=>{if(e.key==='Enter'&&e.target.tagName==='INPUT'){const b=document.querySelector('button.f');if(b)b.click()}});
authV();load();`;

const page = (adm: boolean) => `<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PartPay</title><style>${CSS}</style></head><body><div id="app"></div><script>${JS.replace("__ADMIN__", String(adm))}</script></body></html>`;

Deno.serve(async (req) => {
  const u = new URL(req.url);
  try {
    if (req.method === "GET") {
      const h = { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" };
      if (u.pathname === "/") return new Response(page(false), { headers: h });
      if (u.pathname === "/admin") return new Response(page(true), { headers: h });
      return new Response("Не найдено", { status: 404 });
    }
    if (req.method === "POST" && u.pathname.startsWith("/api/")) {
      const b = await req.json().catch(() => ({}));
      return json(await api(u.pathname.slice(5), req, b));
    }
    return new Response("Не найдено", { status: 404 });
  } catch (e) {
    if (e instanceof Err) return json({ error: e.message }, e.s);
    console.error(e); return json({ error: "Ошибка сервера" }, 500);
  }
});
