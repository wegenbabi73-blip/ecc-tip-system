
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
dotenv.config();
const username=process.env.ADMIN_USERNAME, password=process.env.ADMIN_PASSWORD;
if(!username||!password||password.length<12) throw new Error("Set ADMIN_USERNAME and ADMIN_PASSWORD (12+ chars)");
const db=new Database(process.env.DB_FILE||"./ecc.sqlite");
const hash=bcrypt.hashSync(password,12);
db.prepare(`INSERT INTO users(username,password_hash,role) VALUES(?,?, 'admin')
ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash, role='admin', active=1`).run(username,hash);
console.log("Admin account created/updated.");
