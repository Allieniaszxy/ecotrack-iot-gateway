const Module=require("module");
const stub=require("./test/prisma-memory-stub");
const orig=Module._load;
Module._load=function(r,...a){return r==="@prisma/client"?stub:orig.call(this,r,...a)};
