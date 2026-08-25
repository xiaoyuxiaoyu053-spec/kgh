const express=require("express"),http=require("http"),path=require("path"),fs=require("fs"),crypto=require("crypto"),bcrypt=require("bcryptjs"),{Server}=require("socket.io");
const app=express(),server=http.createServer(app),io=new Server(server);
const DATA_DIR=process.env.DATA_DIR||path.join(__dirname,"data"); fs.mkdirSync(DATA_DIR,{recursive:true});
const DB_FILE=path.join(DATA_DIR,"db.json");
let db;
try{db=JSON.parse(fs.readFileSync(DB_FILE,"utf8"))}catch{db={nextUserId:1,nextMessageId:1,users:[],messages:[]}}
if(!db.users.length){db.users.push({id:db.nextUserId++,username:"Admin",password:bcrypt.hashSync("AdminStar123456",10),nickname:"Admin",avatar:"",is_admin:1,created_at:Date.now()});save()}
function save(){const tmp=DB_FILE+".tmp";fs.writeFileSync(tmp,JSON.stringify(db));fs.renameSync(tmp,DB_FILE)}
function publicUser(u){return{id:u.id,username:u.username,nickname:u.nickname,avatar:u.avatar||"",is_admin:!!u.is_admin}}
function findUser(name){return db.users.find(u=>u.username.toLowerCase()===String(name||"").trim().toLowerCase())}
function token(){return crypto.randomBytes(32).toString("hex")}
const sessions=new Map();
function auth(req){return sessions.get(String(req.headers.authorization||"").replace(/^Bearer\s+/i,""))}
app.use(express.json({limit:"25mb"}));
const UPLOAD_DIR=path.join(DATA_DIR,"uploads");fs.mkdirSync(UPLOAD_DIR,{recursive:true});
app.use("/uploads",express.static(UPLOAD_DIR));app.use(express.static(path.join(__dirname,"public")));
app.post("/api/upload",(req,res)=>{
 const s=auth(req);if(!s)return res.status(401).json({error:"登录已失效"});
 const data=String(req.body?.data||""), name=String(req.body?.name||"file").replace(/[^A-Za-z0-9._-]/g,"_");
 const m=data.match(/^data:(image\/gif|image\/png|image\/jpeg|image\/webp|video\/mp4|video\/webm);base64,(.+)$/);
 if(!m)return res.status(400).json({error:"只支持 GIF/PNG/JPG/WEBP/MP4/WEBM"});
 const ext={"image/gif":"gif","image/png":"png","image/jpeg":"jpg","image/webp":"webp","video/mp4":"mp4","video/webm":"webm"}[m[1]];
 const buf=Buffer.from(m[2],"base64");if(buf.length>20*1024*1024)return res.status(413).json({error:"文件不能超过20MB"});
 const fn=crypto.randomBytes(12).toString("hex")+"."+ext;fs.writeFileSync(path.join(UPLOAD_DIR,fn),buf);res.json({url:"/uploads/"+fn,type:m[1],name});
});
app.get("/api/health",(req,res)=>res.json({ok:true,users:db.users.length,messages:db.messages.length}));
app.post("/api/register",(req,res)=>{
 const username=String(req.body?.username||"").trim(),password=String(req.body?.password||"");
 if(!/^[A-Za-z0-9_]{3,20}$/.test(username))return res.status(400).json({error:"账号必须是3-20位字母、数字或下划线"});
 if(password.length<6)return res.status(400).json({error:"密码至少需要6位"});
 if(findUser(username))return res.status(409).json({error:"这个账号已经存在，请直接登录"});
 const u={id:db.nextUserId++,username,password:bcrypt.hashSync(password,10),nickname:username,avatar:"",is_admin:0,created_at:Date.now()};
 db.users.push(u);save();const t=token();sessions.set(t,publicUser(u));res.json({token:t,user:publicUser(u)});
});
app.post("/api/login",(req,res)=>{
 const u=findUser(req.body?.username),password=String(req.body?.password||"");
 if(!u||!bcrypt.compareSync(password,u.password))return res.status(401).json({error:"账号或密码错误"});
 const t=token();sessions.set(t,publicUser(u));res.json({token:t,user:publicUser(u)});
});
app.post("/api/logout",(req,res)=>{const t=String(req.headers.authorization||"").replace(/^Bearer\s+/i,"");sessions.delete(t);res.json({ok:true})});
app.get("/api/me",(req,res)=>{const u=auth(req);if(!u)return res.status(401).json({error:"未登录"});res.json(u)});
app.get("/api/users",(req,res)=>res.json(db.users.map(publicUser)));
app.get("/api/messages",(req,res)=>res.json(db.messages.slice(-100)));
app.post("/api/admin/promote",(req,res)=>{
 const s=auth(req);if(!s||!s.is_admin)return res.status(403).json({error:"只有管理员可以设置管理员"});
 const u=db.users.find(x=>x.id===Number(req.body?.user_id));if(!u)return res.status(404).json({error:"用户不存在"});
 u.is_admin=1;save();const pu=publicUser(u);for(const [t,v] of sessions){if(v.id===u.id)sessions.set(t,pu)}io.emit("user_updated",pu);res.json(pu);
});
app.post("/api/admin/demote",(req,res)=>{
 const s=auth(req);if(!s||!s.is_admin)return res.status(403).json({error:"只有管理员可以设置管理员"});
 const u=db.users.find(x=>x.id===Number(req.body?.user_id));if(!u)return res.status(404).json({error:"用户不存在"});
 if(u.username==="Admin")return res.status(400).json({error:"不能取消主管理员权限"});
 u.is_admin=0;save();const pu=publicUser(u);for(const [t,v] of sessions){if(v.id===u.id)sessions.set(t,pu)}io.emit("user_updated",pu);res.json(pu);
});
app.post("/api/profile",(req,res)=>{
 const s=auth(req);if(!s)return res.status(401).json({error:"登录已失效"});
 const u=db.users.find(x=>x.id===s.id);if(!u)return res.status(401).json({error:"用户不存在"});
 const nickname=String(req.body?.nickname||"").trim().slice(0,24),avatar=String(req.body?.avatar||"").slice(0,300000);
 if(!nickname)return res.status(400).json({error:"昵称不能为空"});
 u.nickname=nickname;u.avatar=avatar;save();const p=publicUser(u);sessions.set(String(req.headers.authorization).replace(/^Bearer\s+/i,""),p);
 io.emit("user_updated",p);res.json(p)
});
io.on("connection",socket=>{
 socket.on("auth",t=>{const u=sessions.get(String(t||""));if(!u)return socket.emit("auth_error","登录已失效");socket.user=u;socket.join("public");socket.emit("ready",u);io.to("public").emit("presence",{username:u.username,nickname:u.nickname,online:true})});
 socket.on("send",data=>{
  const u=socket.user;if(!u)return;
  const text=String(data?.text||"").trim().slice(0,4000);if(!text)return;
  const type=["text","gif","image","video"].includes(data?.type)?data.type:"text";let reply=null;
  if(data?.reply_id)reply=db.messages.find(m=>m.id===Number(data.reply_id));
  const m={id:db.nextMessageId++,user_id:u.id,username:u.username,nickname:u.nickname,avatar:u.avatar||"",text,type,reply_id:reply?.id||null,reply_nickname:reply?.nickname||null,reply_text:reply?.text||null,created_at:Date.now()};
  db.messages.push(m);if(db.messages.length>500)db.messages=db.messages.slice(-500);save();io.to("public").emit("message",m)
 });
 socket.on("delete",id=>{const u=socket.user;if(!u)return;const i=db.messages.findIndex(m=>m.id===Number(id));if(i<0)return;const m=db.messages[i];if(m.user_id!==u.id&&!u.is_admin)return;db.messages.splice(i,1);save();io.to("public").emit("deleted",m.id)});
 socket.on("disconnect",()=>{if(socket.user)io.to("public").emit("presence",{username:socket.user.username,nickname:socket.user.nickname,online:false})})
});
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public/index.html")));
const port=Number(process.env.PORT)||3000;server.listen(port,"0.0.0.0",()=>console.log("StarChat ready on "+port));
