process.env.JWT_SECRET="x".repeat(40);process.env.SOCKET_GATEWAY_TOKEN="gw-token";process.env.API_PORT="4300";
require("./_preload");const stub=require("./test/prisma-memory-stub");const bcrypt=require("bcryptjs");
require("./api.js");
setTimeout(async()=>{await stub.holder.client.admin.create({data:{fullName:"Root",email:"root@ecotrack.test",passwordHash:await bcrypt.hash("SuperSecure#12345",4),role:"SUPER_ADMIN"}});console.log("api ready")},300);
