
const ECC_API_BASE = localStorage.getItem("ecc_api_base") || "http://10.0.2.2:8080/api";

async function eccApi(path, options = {}) {
  const headers = new Headers(options.headers || {});
  const token = localStorage.getItem("ecc_access_token");
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (!(options.body instanceof FormData) && options.body !== undefined) headers.set("Content-Type","application/json");
  const res = await fetch(ECC_API_BASE + path, {...options, headers});
  const text = await res.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = {raw:text}; }
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}
async function eccLogin(username,password) {
  const data = await eccApi("/auth/login",{method:"POST",body:JSON.stringify({username,password})});
  if (data.mfaRequired) return data;
  localStorage.setItem("ecc_access_token",data.accessToken);
  localStorage.setItem("ecc_user",JSON.stringify(data.user));
  return data;
}
async function eccVerifyMfa(mfaToken,code) {
  const data = await eccApi("/auth/mfa/verify",{method:"POST",body:JSON.stringify({mfaToken,code})});
  localStorage.setItem("ecc_access_token",data.accessToken);
  localStorage.setItem("ecc_user",JSON.stringify(data.user));
  return data;
}
function eccLogout(){localStorage.removeItem("ecc_access_token");localStorage.removeItem("ecc_user");location.href="login.html";}
function eccCurrentUser(){try{return JSON.parse(localStorage.getItem("ecc_user")||"null")}catch{return null}}

function eccQueue(){
  try { return JSON.parse(localStorage.getItem("ecc_offline_queue") || "[]"); }
  catch { return []; }
}
function eccSaveQueue(q){ localStorage.setItem("ecc_offline_queue", JSON.stringify(q)); }
function eccQueueTip(payload){
  const q=eccQueue();
  q.push({...payload, queuedAt:new Date().toISOString(), localId:crypto.randomUUID?.() || String(Date.now())});
  eccSaveQueue(q);
  return q.length;
}
async function eccFlushQueue(){
  const q=eccQueue(); if(!q.length) return {sent:0,remaining:0};
  const remaining=[], sent=[];
  for(const item of q){
    try {
      const fd=new FormData();
      for(const [k,v] of Object.entries(item.fields||{})) fd.append(k,v ?? "");
      const r=await eccApi("/tips",{method:"POST",body:fd});
      sent.push({...item,server:r});
    } catch { remaining.push(item); }
  }
  eccSaveQueue(remaining);
  return {sent:sent.length,remaining:remaining.length,sentItems:sent};
}
