// Capture exact animation times through Chromium DevTools, with one browser
// for all frames. Requires local 'ws' Node package, never at runtime.
const WebSocket=require('ws'),fs=require('fs'),http=require('http');
const [port,variant,out]=process.argv.slice(2);
const get=path=>new Promise((resolve,reject)=>http.get(`http://127.0.0.1:${port}${path}`,r=>{let b='';r.on('data',x=>b+=x);r.on('end',()=>resolve(JSON.parse(b)))}).on('error',reject));
async function main(){
 let pages=await get('/json');const ws=new WebSocket(pages.find(x=>x.type==='page').webSocketDebuggerUrl);
 await new Promise((res,rej)=>{ws.once('open',res);ws.once('error',rej)});
 let seq=0,pending=new Map();ws.on('message',b=>{let m=JSON.parse(b);if(m.id&&pending.has(m.id)){let p=pending.get(m.id);pending.delete(m.id);m.error?p.reject(m.error):p.resolve(m.result)}});
 const call=(method,params={})=>new Promise((resolve,reject)=>{let id=++seq;pending.set(id,{resolve,reject});ws.send(JSON.stringify({id,method,params}))});
 await call('Page.enable');await call('Emulation.setDeviceMetricsOverride',{width:854,height:480,deviceScaleFactor:1,mobile:false});
 await call('Page.navigate',{url:`file:///work/gateway/assets/slate/slate.html?variant=${variant}`});
 for(let n=0;n<120;n++){let ok=await call('Runtime.evaluate',{expression:'typeof window.renderAt === "function"',returnByValue:true});if(ok.result.value)break;await new Promise(r=>setTimeout(r,50));if(n===119)throw Error('slate did not load')}
 for(let i=0;i<120;i++){await call('Runtime.evaluate',{expression:`window.renderAt(${i}/10)`});let shot=await call('Page.captureScreenshot',{format:'png',fromSurface:true,captureBeyondViewport:false});fs.writeFileSync(`${out}/frame${String(i).padStart(4,'0')}.png`,Buffer.from(shot.data,'base64'))}
 ws.close();
}main().catch(e=>{console.error(e);process.exit(1)});
