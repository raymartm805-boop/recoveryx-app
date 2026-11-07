require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { DatabaseSync } = require('node:sqlite');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.resolve(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });
const dbPath = process.env.DB_FILE ? path.resolve(__dirname, process.env.DB_FILE) : path.join(DATA_DIR, 'recoveryx.sqlite');
const db = new DatabaseSync(dbPath);
db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','staff')),
 active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS accounts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, customer_name TEXT NOT NULL, platform TEXT NOT NULL,
 reference_code TEXT NOT NULL DEFAULT '', email TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'review'
 CHECK(status IN ('active','frozen','review','closed')),
 notes TEXT NOT NULL DEFAULT '', created_by INTEGER REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS requests (
 id INTEGER PRIMARY KEY AUTOINCREMENT, account_id INTEGER REFERENCES accounts(id) ON DELETE SET NULL,
 customer_name TEXT NOT NULL, request_type TEXT NOT NULL DEFAULT 'Account review',
 details TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending'
 CHECK(status IN ('pending','in_review','approved','rejected','completed')),
 created_by INTEGER REFERENCES users(id), assigned_to INTEGER REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS payments (
 id INTEGER PRIMARY KEY AUTOINCREMENT, account_id INTEGER REFERENCES accounts(id) ON DELETE SET NULL,
 customer_name TEXT NOT NULL, amount_cents INTEGER NOT NULL CHECK(amount_cents >= 0),
 currency TEXT NOT NULL DEFAULT 'PHP', method TEXT NOT NULL DEFAULT 'Manual record',
 reference_code TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'unverified'
 CHECK(status IN ('unverified','verified','refunded','void')),
 note TEXT NOT NULL DEFAULT '', recorded_by INTEGER REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS activity (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
 actor_name TEXT NOT NULL, action TEXT NOT NULL, entity_type TEXT NOT NULL DEFAULT '',
 entity_id INTEGER, details TEXT NOT NULL DEFAULT '', ip_address TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);
CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status);
CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status);
CREATE INDEX IF NOT EXISTS idx_activity_created ON activity(created_at);
`);

const sessionSecret = process.env.SESSION_SECRET || 'dev-only-change-this-secret-before-deploying-please';
if (process.env.NODE_ENV === 'production' && sessionSecret.length < 32) {
  throw new Error('SESSION_SECRET must be at least 32 characters in production.');
}
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"],
  imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], fontSrc: ["'self'", 'data:'], objectSrc: ["'none'"], frameAncestors: ["'none'"]
}}}));
app.use(express.json({ limit: '100kb' }));
app.use(session({
  name: 'recoveryx.sid', secret: sessionSecret, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: 8 * 60 * 60 * 1000 }
}));
app.use((req, res, next) => {
  if (['POST','PUT','PATCH','DELETE'].includes(req.method) && req.headers.origin) {
    const origin = new URL(req.headers.origin).host;
    if (origin !== req.headers.host) return res.status(403).json({ error: 'Request origin rejected.' });
  }
  next();
});
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many attempts. Please try again later.' } });
const q = (sql) => db.prepare(sql);
const clean = (v, max=500) => String(v ?? '').trim().slice(0, max);
const validEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const currentUser = (req) => req.session.user || null;
function audit(req, action, entityType='', entityId=null, details='') {
  const u = currentUser(req);
  q(`INSERT INTO activity(user_id,actor_name,action,entity_type,entity_id,details,ip_address) VALUES(?,?,?,?,?,?,?)`)
    .run(u?.id || null, u?.name || 'System', action, entityType, entityId, clean(details, 1000), clean(req.ip, 80));
}
function requireAuth(req,res,next) { if (!currentUser(req)) return res.status(401).json({error:'Please sign in.'}); next(); }
function requireAdmin(req,res,next) { if (!currentUser(req) || currentUser(req).role !== 'admin') return res.status(403).json({error:'Administrator access required.'}); next(); }
function csrf(req,res,next) {
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(24).toString('hex');
  res.set('Cache-Control','no-store');
  res.json({ csrfToken: req.session.csrf });
}
function requireCsrf(req,res,next) {
  if (!req.session.csrf || req.get('x-csrf-token') !== req.session.csrf) return res.status(403).json({error:'Security token expired. Refresh and try again.'});
  next();
}
app.get('/api/csrf', csrf);
app.get('/api/setup-status', (req,res) => res.json({ setupRequired: q('SELECT COUNT(*) AS n FROM users').get().n === 0 }));
app.post('/api/setup', authLimiter, requireCsrf, async (req,res) => {
  if (q('SELECT COUNT(*) AS n FROM users').get().n !== 0) return res.status(403).json({error:'Initial setup is already complete.'});
  const name=clean(req.body.name,100), email=clean(req.body.email,180).toLowerCase(), password=String(req.body.password||'');
  if (!name || !validEmail(email) || password.length < 12) return res.status(400).json({error:'Enter a name, valid email and password with at least 12 characters.'});
  const hash=await bcrypt.hash(password,12);
  const result=q('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)').run(name,email,hash,'admin');
  req.session.regenerate(err => { if(err) return res.status(500).json({error:'Could not start secure session.'});
    req.session.user={id:Number(result.lastInsertRowid),name,email,role:'admin'}; req.session.csrf=crypto.randomBytes(24).toString('hex');
    audit(req,'Initial administrator created','user',Number(result.lastInsertRowid),'First-run setup');
    res.json({user:req.session.user,csrfToken:req.session.csrf});
  });
});
app.post('/api/login', authLimiter, requireCsrf, async (req,res) => {
  const email=clean(req.body.email,180).toLowerCase(), password=String(req.body.password||'');
  const user=q('SELECT * FROM users WHERE email=? AND active=1').get(email);
  if (!user || !(await bcrypt.compare(password,user.password_hash))) return res.status(401).json({error:'Email or password is incorrect.'});
  req.session.regenerate(err => { if(err) return res.status(500).json({error:'Could not start secure session.'});
    req.session.user={id:user.id,name:user.name,email:user.email,role:user.role}; req.session.csrf=crypto.randomBytes(24).toString('hex');
    audit(req,'Signed in','session',null,'Successful login'); res.json({user:req.session.user,csrfToken:req.session.csrf});
  });
});
app.post('/api/logout', requireAuth, requireCsrf, (req,res) => { audit(req,'Signed out','session'); req.session.destroy(()=>{res.clearCookie('recoveryx.sid',{sameSite:'strict'});res.json({ok:true});}); });
app.get('/api/me', requireAuth, (req,res) => res.json({user:currentUser(req),csrfToken:req.session.csrf}));

app.get('/api/dashboard', requireAuth, (req,res) => {
 const counts={accounts:q('SELECT COUNT(*) n FROM accounts').get().n, active:q("SELECT COUNT(*) n FROM accounts WHERE status='active'").get().n,
 frozen:q("SELECT COUNT(*) n FROM accounts WHERE status='frozen'").get().n, requests:q("SELECT COUNT(*) n FROM requests WHERE status IN ('pending','in_review')").get().n,
 payments:q('SELECT COUNT(*) n FROM payments').get().n, verifiedCents:q("SELECT COALESCE(SUM(amount_cents),0) n FROM payments WHERE status='verified'").get().n};
 res.json({counts,recent:q('SELECT id,actor_name,action,entity_type,details,created_at FROM activity ORDER BY id DESC LIMIT 8').all()});
});
app.get('/api/accounts', requireAuth, (req,res) => {
 const search=`%${clean(req.query.search,100)}%`, status=clean(req.query.status,20);
 const rows=status ? q(`SELECT * FROM accounts WHERE (customer_name LIKE ? OR platform LIKE ? OR reference_code LIKE ?) AND status=? ORDER BY id DESC`).all(search,search,search,status)
 : q(`SELECT * FROM accounts WHERE customer_name LIKE ? OR platform LIKE ? OR reference_code LIKE ? ORDER BY id DESC`).all(search,search,search);
 res.json(rows);
});
app.post('/api/accounts', requireAuth, requireCsrf, (req,res) => {
 const name=clean(req.body.customer_name,120), platform=clean(req.body.platform,80), ref=clean(req.body.reference_code,100), email=clean(req.body.email,180), status=clean(req.body.status,20), notes=clean(req.body.notes,1000);
 if(!name||!platform||!['active','frozen','review','closed'].includes(status||'review')|| (email&&!validEmail(email))) return res.status(400).json({error:'Check the account fields.'});
 const r=q(`INSERT INTO accounts(customer_name,platform,reference_code,email,status,notes,created_by) VALUES(?,?,?,?,?,?,?)`).run(name,platform,ref,email,status||'review',notes,currentUser(req).id);
 audit(req,'Created account record','account',Number(r.lastInsertRowid),`${name} · ${platform}`); res.status(201).json(q('SELECT * FROM accounts WHERE id=?').get(r.lastInsertRowid));
});
app.patch('/api/accounts/:id', requireAuth, requireCsrf, (req,res) => {
 const id=Number(req.params.id), old=q('SELECT * FROM accounts WHERE id=?').get(id); if(!old)return res.status(404).json({error:'Account record not found.'});
 const allowed=['active','frozen','review','closed']; const status=clean(req.body.status,20);
 const name=clean(req.body.customer_name ?? old.customer_name,120), platform=clean(req.body.platform ?? old.platform,80), ref=clean(req.body.reference_code ?? old.reference_code,100), email=clean(req.body.email ?? old.email,180), notes=clean(req.body.notes ?? old.notes,1000);
 if(!name||!platform||!allowed.includes(status||old.status)||(email&&!validEmail(email)))return res.status(400).json({error:'Invalid account fields.'});
 q(`UPDATE accounts SET customer_name=?,platform=?,reference_code=?,email=?,status=?,notes=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).run(name,platform,ref,email,status||old.status,notes,id);
 audit(req,'Updated account record','account',id,`Status: ${old.status} → ${status||old.status}`);res.json(q('SELECT * FROM accounts WHERE id=?').get(id));
});
app.delete('/api/accounts/:id', requireAuth, requireAdmin, requireCsrf, (req,res) => { const id=Number(req.params.id), old=q('SELECT * FROM accounts WHERE id=?').get(id);if(!old)return res.status(404).json({error:'Not found.'});q('DELETE FROM accounts WHERE id=?').run(id);audit(req,'Deleted account record','account',id,old.customer_name);res.json({ok:true}); });

app.get('/api/requests', requireAuth, (req,res) => res.json(q(`SELECT r.*,a.platform,a.reference_code FROM requests r LEFT JOIN accounts a ON a.id=r.account_id ORDER BY r.id DESC`).all()));
app.post('/api/requests', requireAuth, requireCsrf, (req,res) => {
 const name=clean(req.body.customer_name,120), type=clean(req.body.request_type,80), details=clean(req.body.details,1200), accountId=req.body.account_id?Number(req.body.account_id):null;
 if(!name||!type)return res.status(400).json({error:'Customer name and request type are required.'});
 if(accountId&&!q('SELECT id FROM accounts WHERE id=?').get(accountId))return res.status(400).json({error:'Selected account does not exist.'});
 const r=q('INSERT INTO requests(account_id,customer_name,request_type,details,created_by) VALUES(?,?,?,?,?)').run(accountId,name,type,details,currentUser(req).id);
 audit(req,'Created recovery request','request',Number(r.lastInsertRowid),`${name} · ${type}`);res.status(201).json(q('SELECT * FROM requests WHERE id=?').get(r.lastInsertRowid));
});
app.patch('/api/requests/:id', requireAuth, requireCsrf, (req,res) => {
 const id=Number(req.params.id), old=q('SELECT * FROM requests WHERE id=?').get(id);if(!old)return res.status(404).json({error:'Request not found.'});
 const status=clean(req.body.status,20);if(!['pending','in_review','approved','rejected','completed'].includes(status))return res.status(400).json({error:'Invalid request status.'});
 q('UPDATE requests SET status=?,assigned_to=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(status,currentUser(req).id,id);audit(req,'Updated recovery request','request',id,`${old.status} → ${status}`);res.json(q('SELECT * FROM requests WHERE id=?').get(id));
});

app.get('/api/payments', requireAuth, (req,res) => res.json(q('SELECT * FROM payments ORDER BY id DESC').all()));
app.post('/api/payments', requireAuth, requireCsrf, (req,res) => {
 const name=clean(req.body.customer_name,120), amount=Number(req.body.amount), method=clean(req.body.method||'Manual record',60), ref=clean(req.body.reference_code,100), note=clean(req.body.note,500), accountId=req.body.account_id?Number(req.body.account_id):null;
 if(!name||!Number.isFinite(amount)||amount<0||amount>100000000)return res.status(400).json({error:'Enter a valid customer name and amount.'});
 if(accountId&&!q('SELECT id FROM accounts WHERE id=?').get(accountId))return res.status(400).json({error:'Selected account does not exist.'});
 const r=q('INSERT INTO payments(account_id,customer_name,amount_cents,method,reference_code,note,recorded_by) VALUES(?,?,?,?,?,?,?)').run(accountId,name,Math.round(amount*100),method,ref,note,currentUser(req).id);
 audit(req,'Recorded payment entry (unverified)','payment',Number(r.lastInsertRowid),`${name} · PHP ${amount.toFixed(2)}`);res.status(201).json(q('SELECT * FROM payments WHERE id=?').get(r.lastInsertRowid));
});
app.patch('/api/payments/:id', requireAuth, requireAdmin, requireCsrf, (req,res) => {
 const id=Number(req.params.id), old=q('SELECT * FROM payments WHERE id=?').get(id);if(!old)return res.status(404).json({error:'Payment entry not found.'});
 const status=clean(req.body.status,20);if(!['unverified','verified','refunded','void'].includes(status))return res.status(400).json({error:'Invalid payment status.'});
 q('UPDATE payments SET status=? WHERE id=?').run(status,id);audit(req,'Updated payment ledger status','payment',id,`${old.status} → ${status}`);res.json(q('SELECT * FROM payments WHERE id=?').get(id));
});
app.delete('/api/payments/:id', requireAuth, requireAdmin, requireCsrf, (req,res)=>{const id=Number(req.params.id);if(!q('SELECT id FROM payments WHERE id=?').get(id))return res.status(404).json({error:'Not found.'});q('DELETE FROM payments WHERE id=?').run(id);audit(req,'Deleted payment entry','payment',id,'Admin deletion');res.json({ok:true});});

app.get('/api/users', requireAuth, requireAdmin, (req,res)=>res.json(q('SELECT id,name,email,role,active,created_at FROM users ORDER BY id').all()));
app.post('/api/users', requireAuth, requireAdmin, requireCsrf, async (req,res)=>{const name=clean(req.body.name,100),email=clean(req.body.email,180).toLowerCase(),password=String(req.body.password||''),role=clean(req.body.role,10);if(!name||!validEmail(email)||password.length<12||!['admin','staff'].includes(role))return res.status(400).json({error:'Provide valid details and a password of at least 12 characters.'});try{const hash=await bcrypt.hash(password,12);const r=q('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)').run(name,email,hash,role);audit(req,'Created team user','user',Number(r.lastInsertRowid),`${email} · ${role}`);res.status(201).json(q('SELECT id,name,email,role,active,created_at FROM users WHERE id=?').get(r.lastInsertRowid));}catch(e){res.status(409).json({error:'That email is already in use.'});}});
app.patch('/api/users/:id', requireAuth, requireAdmin, requireCsrf, (req,res)=>{const id=Number(req.params.id),u=q('SELECT * FROM users WHERE id=?').get(id);if(!u)return res.status(404).json({error:'User not found.'});if(id===currentUser(req).id&&req.body.active===false)return res.status(400).json({error:'You cannot deactivate your own account.'});const active=req.body.active===false?0:1;const role=['admin','staff'].includes(req.body.role)?req.body.role:u.role;q('UPDATE users SET active=?,role=? WHERE id=?').run(active,role,id);audit(req,'Updated team access','user',id,`${role} · ${active?'active':'inactive'}`);res.json({ok:true});});
app.get('/api/activity', requireAuth, (req,res)=>res.json(q('SELECT * FROM activity ORDER BY id DESC LIMIT 500').all()));
app.get('/api/export/:kind', requireAuth, (req,res)=>{
 const kind=req.params.kind;const config={accounts:['accounts','id,customer_name,platform,reference_code,email,status,notes,created_at,updated_at'],requests:['requests','id,account_id,customer_name,request_type,details,status,created_at,updated_at'],payments:['payments','id,account_id,customer_name,amount_cents,currency,method,reference_code,status,note,created_at'],activity:['activity','id,actor_name,action,entity_type,entity_id,details,ip_address,created_at']};
 if(!config[kind])return res.status(404).json({error:'Unknown export.'});const [table,cols]=config[kind];const rows=q(`SELECT ${cols} FROM ${table} ORDER BY id DESC`).all();const fields=cols.split(',');const esc=v=>'"'+String(v??'').replace(/"/g,'""')+'"';const csv=[fields.join(','),...rows.map(row=>fields.map(f=>esc(f==='amount_cents'?(row[f]/100).toFixed(2):row[f])).join(','))].join('\r\n');res.setHeader('Content-Type','text/csv; charset=utf-8');res.setHeader('Content-Disposition',`attachment; filename="recoveryx-${kind}.csv"`);res.send('\uFEFF'+csv);
});
app.get('/api/health',(req,res)=>res.json({ok:true,service:'RecoveryX Records Manager'}));
app.use(express.static(path.join(__dirname,'public')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Unexpected server error.'});});

if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD && q('SELECT COUNT(*) AS n FROM users').get().n===0) {
 const email=clean(process.env.ADMIN_EMAIL,180).toLowerCase();
 if(validEmail(email)&&process.env.ADMIN_PASSWORD.length>=12){const hash=bcrypt.hashSync(process.env.ADMIN_PASSWORD,12);q('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)').run('Administrator',email,hash,'admin');console.log('Initial administrator created from environment.');}
}
app.listen(PORT,()=>console.log(`RecoveryX running at http://localhost:${PORT}`));
