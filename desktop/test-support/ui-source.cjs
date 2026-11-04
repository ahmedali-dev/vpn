// Load the real ordered UI modules in VM tests; production uses HTML script tags.
const fs=require('node:fs'),path=require('node:path');
const root=path.join(__dirname,'../ui');
exports.applicationSource=()=>JSON.parse(fs.readFileSync(path.join(root,'script-manifest.json'),'utf8'))
 .map(file=>fs.readFileSync(path.join(root,file),'utf8')).join('\n');
