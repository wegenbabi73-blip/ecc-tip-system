
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";
import multer from "multer";
import dotenv from "dotenv";
import { authenticator } from "otplib";
import QRCode from "qrcode";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT || 8080);
const JWT_SECRET = process.env.JWT_SECRET || "";
const MFA_ISSUER = process.env.MFA_ISSUER || "Ethiopian Customs Commission";
const DB_FILE = process.env.DB_FILE || "./ecc.sqlite";
const UPLOAD_DIR = process.env.UPLOAD_DIR || "./uploads";
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

if (JWT_SECRET.length < 32) {
  console.warn("WARNING: Set JWT_SECRET to a random value of at least 32 characters.");
}

const db = new Database(DB_FILE);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'officer',
  mfa_enabled INTEGER NOT NULL DEFAULT 0,
  mfa_secret TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tips (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tracking_code TEXT NOT NULL UNIQUE,
  category TEXT NOT NULL,
  description TEXT NOT NULL,
  location TEXT,
  risk_level TEXT NOT NULL DEFAULT 'Medium',
  status TEXT NOT NULL DEFAULT 'New',
  contact TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  assigned_to INTEGER,
  FOREIGN KEY (assigned_to) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS tip_attachments (id INTEGER PRIMARY KEY AUTOINCREMENT, tip_id INTEGER NOT NULL, original_name TEXT, stored_name TEXT, mime_type TEXT, size INTEGER, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(tip_id) REFERENCES tips(id));
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT NOT NULL,
  entity_type TEXT,
  entity_id TEXT,
  ip TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  tip_id INTEGER,
  is_read INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (tip_id) REFERENCES tips(id)
);
`);

db.exec(`
CREATE TABLE IF NOT EXISTS tip_history (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 tip_id INTEGER NOT NULL,
 user_id INTEGER,
 action TEXT NOT NULL,
 from_status TEXT,
 to_status TEXT,
 note TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_tip_history_tip ON tip_history(tip_id);
CREATE INDEX IF NOT EXISTS idx_tips_status ON tips(status);
`);
ensureColumn(db,"tips","region","TEXT");
ensureColumn(db,"tips","zone","TEXT");
ensureColumn(db,"tips","woreda","TEXT");
ensureColumn(db,"tips","source_channel","TEXT");

// Create indexes only after legacy columns have been ensured.
db.exec(`CREATE INDEX IF NOT EXISTS idx_tips_risk ON tips(risk_level); CREATE INDEX IF NOT EXISTS idx_tips_region ON tips(region); CREATE INDEX IF NOT EXISTS idx_tips_zone ON tips(zone); CREATE INDEX IF NOT EXISTS idx_tips_woreda ON tips(woreda);`);


const allowedRoles = new Set(["admin","supervisor","officer","analyst"]);
const authLimiter = rateLimit({ windowMs: 15*60*1000, limit: 30, standardHeaders: true, legacyHeaders: false });
const publicTipLimiter = rateLimit({ windowMs: 15*60*1000, limit: 30, standardHeaders: true, legacyHeaders: false, message:{error:"Too many public requests; try again later."} });

app.use(helmet({ crossOriginResourcePolicy: false }));
const CORS_ORIGIN = process.env.CORS_ORIGIN || "";
app.use(cors({
  origin: CORS_ORIGIN ? CORS_ORIGIN.split(",").map(x=>x.trim()) : false,
  credentials: false
}));
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use("/api/auth", authLimiter);


const ALLOWED_MIME = new Set(["image/jpeg","image/png","application/pdf"]);
const upload = multer({
  dest: UPLOAD_DIR,
  limits: { fileSize: 5 * 1024 * 1024, files: 1 },
  fileFilter: (_req,file,cb) => ALLOWED_MIME.has(file.mimetype) ? cb(null,true) : cb(new Error("File type not allowed"))
});

app.use((err,req,res,next)=>{
  if(err?.code==="LIMIT_FILE_SIZE") return res.status(413).json({error:"Attachment exceeds 5 MB limit"});
  if(err?.name==="MulterError" || err?.message==="File type not allowed") return res.status(400).json({error:"Unsupported attachment type"});
  next(err);
});
function signAccess(user) {
  return jwt.sign(
    { sub: user.id, username: user.username, role: user.role, purpose: "access" },
    JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES || "8h" }
  );
}
function signMfa(user) {
  return jwt.sign(
    { sub: user.id, username: user.username, purpose: "mfa" },
    JWT_SECRET, { expiresIn: "5m" }
  );
}
function getToken(req) {
  const h = req.headers.authorization || "";
  return h.startsWith("Bearer ") ? h.slice(7) : null;
}
function requireAuth(req,res,next) {
  try {
    if (!JWT_SECRET) return res.status(500).json({error:"JWT_SECRET is not configured"});
    const token = getToken(req);
    if (!token) return res.status(401).json({error:"Authentication required"});
    const p = jwt.verify(token, JWT_SECRET);
    if (p.purpose !== "access") return res.status(401).json({error:"Invalid access token"});
    const user = db.prepare("SELECT id,username,role,active,mfa_enabled,created_at FROM users WHERE id=?").get(p.sub);
    if (!user || !user.active) return res.status(401).json({error:"User inactive or not found"});
    req.user = user;
    next();
  } catch { res.status(401).json({error:"Invalid or expired token"}); }
}
function requireRole(...roles) {
  return (req,res,next) => roles.includes(req.user.role) ? next() : res.status(403).json({error:"Forbidden"});
}
function audit(req, action, entityType="", entityId="") {
  db.prepare("INSERT INTO audit_logs(user_id,action,entity_type,entity_id,ip) VALUES(?,?,?,?,?)")
    .run(req.user?.id || null, action, entityType, String(entityId || ""), req.ip);
}
function makeTracking() {
  return "ECC-" + new Date().toISOString().slice(0,10).replaceAll("-","") + "-" +
    crypto.randomBytes(3).toString("hex").toUpperCase();
}

app.get("/api/health", (req,res)=>res.json({ok:true,version:"4.0.0"}));

app.post("/api/auth/login", (req,res)=>{
  const { username, password } = req.body || {};
  const user = db.prepare("SELECT * FROM users WHERE username=?").get(username);
  if (!user || !user.active || !bcrypt.compareSync(password || "", user.password_hash))
    return res.status(401).json({error:"Invalid username or password"});
  if (user.mfa_enabled) {
    return res.json({
      mfaRequired:true,
      mfaToken:signMfa(user),
      user:{id:user.id,username:user.username,role:user.role}
    });
  }
  const accessToken = signAccess(user);
  return res.json({mfaRequired:false,accessToken,user:{id:user.id,username:user.username,role:user.role}});
});

app.post("/api/auth/mfa/verify", (req,res)=>{
  try {
    const { mfaToken, code } = req.body || {};
    const p = jwt.verify(mfaToken, JWT_SECRET);
    if (p.purpose !== "mfa") throw new Error("purpose");
    const user = db.prepare("SELECT * FROM users WHERE id=?").get(p.sub);
    if (!user || !user.active || !user.mfa_enabled || !user.mfa_secret)
      return res.status(401).json({error:"MFA is not available for this account"});
    const ok = authenticator.check(String(code || "").replace(/\s/g,""), user.mfa_secret);
    if (!ok) return res.status(401).json({error:"Invalid MFA code"});
    return res.json({accessToken:signAccess(user),user:{id:user.id,username:user.username,role:user.role}});
  } catch {
    return res.status(401).json({error:"Invalid or expired MFA session"});
  }
});

app.get("/api/auth/me", requireAuth, (req,res)=>res.json({user:req.user}));

app.post("/api/auth/mfa/setup", requireAuth, async (req,res)=>{
  if (req.user.mfa_enabled) return res.status(400).json({error:"MFA is already enabled"});
  const secret = authenticator.generateSecret();
  const otpauth = authenticator.keyuri(req.user.username, MFA_ISSUER, secret);
  const qrDataUrl = await QRCode.toDataURL(otpauth);
  db.prepare("UPDATE users SET mfa_secret=? WHERE id=?").run(secret, req.user.id);
  audit(req,"MFA_SETUP_STARTED","user",req.user.id);
  // Secret is returned once for enrollment. Do not log it.
  res.json({otpauth, qrDataUrl});
});

app.post("/api/auth/mfa/enable", requireAuth, (req,res)=>{
  const { code } = req.body || {};
  const user = db.prepare("SELECT * FROM users WHERE id=?").get(req.user.id);
  if (!user?.mfa_secret) return res.status(400).json({error:"Run MFA setup first"});
  if (!authenticator.check(String(code || "").replace(/\s/g,""), user.mfa_secret))
    return res.status(400).json({error:"Invalid MFA code"});
  db.prepare("UPDATE users SET mfa_enabled=1 WHERE id=?").run(req.user.id);
  audit(req,"MFA_ENABLED","user",req.user.id);
  res.json({ok:true});
});

app.post("/api/tips", publicTipLimiter, upload.single("attachment"), (req,res)=>{
  const {category,description,location,risk_level="Medium",contact=""} = req.body || {};
  if (!category || !description) return res.status(400).json({error:"Category and description are required"});
  if (String(description).length > 10000) return res.status(400).json({error:"Description is too long"});
  if (!["Low","Medium","High"].includes(risk_level)) return res.status(400).json({error:"Invalid risk level"});
  const tracking = makeTracking();
  const info = db.prepare(`
    INSERT INTO tips(tracking_code,category,description,location,risk_level,contact)
    VALUES(?,?,?,?,?,?)
  `).run(tracking,category,description,location || "",risk_level,contact || "");
  const tipId = info.lastInsertRowid;
  if (req.file) {
    db.prepare("INSERT INTO tip_attachments(tip_id,original_name,stored_name,mime_type,size) VALUES(?,?,?,?,?)")
      .run(tipId, req.file.originalname, req.file.filename, req.file.mimetype, req.file.size);
  }
  const admins = db.prepare("SELECT id FROM users WHERE active=1 AND role IN ('admin','supervisor')").all();
  const stmt = db.prepare("INSERT INTO notifications(user_id,title,message,tip_id) VALUES(?,?,?,?)");
  const tx = db.transaction(()=>admins.forEach(u=>stmt.run(u.id,"New tip received",`New ${risk_level} risk tip: ${tracking}`,tipId)));
  tx();
  res.status(201).json({trackingCode:tracking,id:tipId});
});

app.get("/api/tips/:id/attachments", requireAuth, (req,res)=>{
  const rows = db.prepare("SELECT id,original_name,mime_type,size,created_at FROM tip_attachments WHERE tip_id=?").all(Number(req.params.id));
  res.json(rows);
});
app.get("/api/tips/track/:code", publicTipLimiter,(req,res)=>{
  const t = db.prepare("SELECT tracking_code,category,risk_level,status,created_at,updated_at FROM tips WHERE tracking_code=?").get(req.params.code);
  if (!t) return res.status(404).json({error:"Tracking code not found"});
  res.json(t);
});

app.get("/api/tips/:id", requireAuth, (req,res)=>{
  const tip=db.prepare(`SELECT t.*,u.username AS assigned_username FROM tips t LEFT JOIN users u ON u.id=t.assigned_to WHERE t.id=?`).get(Number(req.params.id));
  if(!tip) return res.status(404).json({error:"Tip not found"});
  const attachments=db.prepare("SELECT id,original_name,mime_type,size,created_at,stored_name FROM tip_attachments WHERE tip_id=?").all(Number(req.params.id));
  res.json({...tip,attachments});
});

app.patch("/api/tips/:id/assign", requireAuth, requireRole("admin","supervisor"), (req,res)=>{
  const tipId=Number(req.params.id), officerId=Number(req.body?.assigned_to);
  const officer=db.prepare("SELECT id,username,role,active FROM users WHERE id=?").get(officerId);
  if(!officer || !officer.active || !["officer","analyst","supervisor"].includes(officer.role))
    return res.status(400).json({error:"Invalid active assignee"});
  const r=db.prepare("UPDATE tips SET assigned_to=?,updated_at=CURRENT_TIMESTAMP,status='Assigned' WHERE id=?").run(officerId,tipId);
  if(!r.changes) return res.status(404).json({error:"Tip not found"});
  db.prepare("INSERT INTO notifications(user_id,title,message,tip_id) VALUES(?,?,?,?)")
    .run(officerId,"Tip assigned",`Tip #${tipId} has been assigned to you.`,tipId);
  audit(req,"TIP_ASSIGNED","tip",tipId);
  res.json({ok:true,assigned_to:officerId});
});

app.get("/api/users/officers", requireAuth, requireRole("admin","supervisor"), (req,res)=>{
  res.json(db.prepare("SELECT id,username,role FROM users WHERE active=1 AND role IN ('officer','analyst','supervisor') ORDER BY username").all());
});

app.get("/api/reports/summary", requireAuth, requireRole("admin","supervisor","analyst"), (req,res)=>{
  const total=db.prepare("SELECT COUNT(*) c FROM tips").get().c;
  const byRisk=db.prepare("SELECT risk_level name,COUNT(*) value FROM tips GROUP BY risk_level").all();
  const byStatus=db.prepare("SELECT status name,COUNT(*) value FROM tips GROUP BY status").all();
  const byCategory=db.prepare("SELECT category name,COUNT(*) value FROM tips GROUP BY category").all();
  const byDay=db.prepare("SELECT substr(created_at,1,10) day,COUNT(*) value FROM tips GROUP BY substr(created_at,1,10) ORDER BY day DESC LIMIT 30").all();
  res.json({total,byRisk,byStatus,byCategory,byDay});
});

app.get("/api/reports/tips.csv", requireAuth, requireRole("admin","supervisor","analyst"), (req,res)=>{
  const from=String(req.query.date_from||"").trim();
  const to=String(req.query.date_to||"").trim();
  let sql=`SELECT tracking_code,category,risk_level,status,location,assigned_to,created_at,updated_at FROM tips WHERE 1=1`;
  const args=[];
  if(/^\d{4}-\d{2}-\d{2}$/.test(from)){sql+=` AND date(created_at)>=date(?)`;args.push(from);}
  if(/^\d{4}-\d{2}-\d{2}$/.test(to)){sql+=` AND date(created_at)<=date(?)`;args.push(to);}
  sql+=` ORDER BY created_at DESC`;
  const rows=db.prepare(sql).all(...args);
  const esc=v=>`"${String(v??"").replaceAll('"','""')}"`;
  const csv=[["tracking_code","category","risk_level","status","location","assigned_to","created_at","updated_at"],...rows.map(r=>Object.values(r))].map(r=>r.map(esc).join(",")).join("\n");
  res.setHeader("Content-Type","text/csv; charset=utf-8");
  res.setHeader("Content-Disposition",'attachment; filename="ecc-tips-report.csv"');
  res.send("\ufeff"+csv);
});

app.get("/api/tips", requireAuth, (req,res)=>{
  const q = String(req.query.q || "").trim();
  const status = String(req.query.status || "").trim();
  const risk = String(req.query.risk || "").trim();
  let sql = "SELECT * FROM tips WHERE 1=1";
  const args = [];
  if(q){ sql += " AND (tracking_code LIKE ? OR category LIKE ? OR description LIKE ? OR location LIKE ?)"; const s=`%${q}%`; args.push(s,s,s,s); }
  if(status){ sql += " AND status=?"; args.push(status); }
  if(risk){ sql += " AND risk_level=?"; args.push(risk); }
  sql += " ORDER BY created_at DESC LIMIT 500";
  res.json(db.prepare(sql).all(...args));
});

app.patch("/api/tips/:id", requireAuth, (req,res)=>{
  const id = Number(req.params.id);
  const allowed = ["status","risk_level","assigned_to"];
  const sets=[]; const vals=[];
  for(const k of allowed) if(req.body?.[k] !== undefined){ sets.push(`${k}=?`); vals.push(req.body[k]); }
  if(!sets.length) return res.status(400).json({error:"No supported fields"});
  sets.push("updated_at=CURRENT_TIMESTAMP");
  vals.push(id);
  const result = db.prepare(`UPDATE tips SET ${sets.join(",")} WHERE id=?`).run(...vals);
  if(!result.changes) return res.status(404).json({error:"Tip not found"});
  audit(req,"TIP_UPDATED","tip",id);
  res.json({ok:true});
});

app.get("/api/notifications", requireAuth, (req,res)=>{
  const rows = db.prepare("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50").all(req.user.id);
  const unread = db.prepare("SELECT COUNT(*) c FROM notifications WHERE user_id=? AND is_read=0").get(req.user.id).c;
  res.json({unread,items:rows});
});
app.patch("/api/notifications/:id/read", requireAuth, (req,res)=>{
  db.prepare("UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?").run(Number(req.params.id),req.user.id);
  res.json({ok:true});
});

app.get("/api/users", requireAuth, requireRole("admin"), (req,res)=>{
  res.json(db.prepare("SELECT id,username,role,mfa_enabled,active,created_at FROM users ORDER BY id DESC").all());
});
app.post("/api/users", requireAuth, requireRole("admin"), (req,res)=>{
  const {username,password,role="officer"} = req.body || {};
  if(!username || !password || !allowedRoles.has(role)) return res.status(400).json({error:"username, password and valid role are required"});
  if(String(password).length < 12) return res.status(400).json({error:"Password must be at least 12 characters"});
  try {
    const hash=bcrypt.hashSync(password,12);
    const info=db.prepare("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)").run(username,hash,role);
    audit(req,"USER_CREATED","user",info.lastInsertRowid);
    res.status(201).json({id:info.lastInsertRowid,username,role});
  } catch { res.status(409).json({error:"Username already exists"}); }
});
app.patch("/api/users/:id", requireAuth, requireRole("admin"), (req,res)=>{
  const id=Number(req.params.id);
  const fields=[]; const vals=[];
  if(req.body?.role && allowedRoles.has(req.body.role)){fields.push("role=?");vals.push(req.body.role);}
  if(req.body?.active !== undefined){fields.push("active=?");vals.push(req.body.active?1:0);}
  if(req.body?.password){if(String(req.body.password).length<12)return res.status(400).json({error:"Password must be at least 12 characters"});fields.push("password_hash=?");vals.push(bcrypt.hashSync(req.body.password,12));}
  if(req.body?.resetMfa){fields.push("mfa_enabled=0");fields.push("mfa_secret=NULL");}
  if(!fields.length)return res.status(400).json({error:"No supported fields"});
  vals.push(id); const r=db.prepare(`UPDATE users SET ${fields.join(",")} WHERE id=?`).run(...vals);
  if(!r.changes)return res.status(404).json({error:"User not found"});
  audit(req,"USER_UPDATED","user",id); res.json({ok:true});
});

app.get("/api/audit", requireAuth, requireRole("admin","supervisor"), (req,res)=>{
  res.json(db.prepare(`
    SELECT a.*,u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id
    ORDER BY a.created_at DESC LIMIT 500
  `).all());
});


function recordHistory(tipId,userId,action,fromStatus,toStatus,note){
 db.prepare(`INSERT INTO tip_history(tip_id,user_id,action,from_status,to_status,note) VALUES(?,?,?,?,?,?)`)
   .run(tipId,userId||null,action,fromStatus||null,toStatus||null,note||null);
}
app.get("/api/tips/:id/history",requireAuth,(req,res)=>{
 const row=db.prepare("SELECT assigned_to FROM tips WHERE id=?").get(req.params.id);
 if(!row)return res.status(404).json({error:"Tip not found"});
 if(req.user.role==="officer"&&row.assigned_to!==req.user.id)return res.status(403).json({error:"Forbidden"});
 res.json({history:db.prepare(`SELECT h.*,u.username AS user_name FROM tip_history h LEFT JOIN users u ON u.id=h.user_id WHERE h.tip_id=? ORDER BY h.created_at DESC`).all(req.params.id)});
});
app.get("/api/attachments/:stored",requireAuth,(req,res)=>{
 const stored=path.basename(req.params.stored);
 if(stored!==req.params.stored)return res.status(400).json({error:"Invalid attachment name"});
 const row=db.prepare("SELECT a.*,t.assigned_to FROM tip_attachments a JOIN tips t ON t.id=a.tip_id WHERE a.stored_name=?").get(stored);
 if(!row)return res.status(404).json({error:"Attachment not found"});
 if(req.user.role==="officer"&&row.assigned_to!==req.user.id)return res.status(403).json({error:"Forbidden"});
 const fp=path.resolve(UPLOAD_DIR,stored);
 if(!fp.startsWith(path.resolve(UPLOAD_DIR)+path.sep)||!fs.existsSync(fp))return res.status(404).json({error:"File not found"});
 res.download(fp,row.original_name||stored);
});
app.get("/api/admin/overview",requireAuth,requireRole("admin"),(req,res)=>{
 const q=x=>db.prepare(x).get().n;
 res.json({users:q("SELECT COUNT(*) n FROM users"),activeUsers:q("SELECT COUNT(*) n FROM users WHERE active=1"),
 tips:q("SELECT COUNT(*) n FROM tips"),openTips:q("SELECT COUNT(*) n FROM tips WHERE status<>'Closed'"),
 audit:q("SELECT COUNT(*) n FROM audit_logs"),history:q("SELECT COUNT(*) n FROM tip_history")});
});

app.listen(PORT,()=>console.log(`ECC Tip Server v4 listening on ${PORT}`));
