const {io}=require("socket.io-client");const mqtt=require("mqtt");
(async()=>{
 const r=await fetch("http://localhost:4300/api/admin/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:"root@ecotrack.test",password:"SuperSecure#12345"})});
 const {token}=await r.json();
 const sock=io("http://localhost:4300",{auth:{token}});const log=[];
 for(const ev of ["bin:reading","bin:alert","alert:updated","bin:emptied"])sock.on(ev,p=>log.push([ev,ev==="bin:reading"?p.reading.fillLevel:ev==="bin:emptied"?`${p.previousFill}->${p.fillLevel}`:`${p.severity}/${p.status}`]));
 await new Promise(res=>sock.on("connect",res));
 const m=mqtt.connect("mqtt://localhost:1883");await new Promise(res=>m.on("connect",res));
 for(const fill of [40,94,80,20]){m.publish("ecotrack/demo/bin001/alaka/telemetry",JSON.stringify({binId:"BIN-001",distance:100-fill,fillLevel:fill,messageId:"m"+fill+Date.now()}),{qos:1});await new Promise(r=>setTimeout(r,1200));}
 await new Promise(r=>setTimeout(r,800));
 console.log(log.map(x=>x.join(" ")).join("\n"));process.exit(0);
})();
