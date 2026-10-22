import fs from 'node:fs';
import {execFileSync} from 'node:child_process';
// Read the historical name from the sole migration rather than introducing a
// second product reference into this regression gate itself.
const migration='internal/controller/'+fs.readdirSync('internal/controller').find(f=>f.startsWith('migration_remove_')&&f.endsWith('.go'));
const name=fs.readFileSync(migration,'utf8').match(/const retiredEngineName\s*=\s*"([^"]+)"/)?.[1];
if(!name)throw Error('Retirement migration name not found');
const needle=name.toLowerCase();
const files=execFileSync('git',['ls-files','--cached','--others','--exclude-standard'],{encoding:'utf8'}).trim().split('\n').filter(Boolean);
const allowed=[],unexpected=[];
for(const file of files){
 if(!fs.existsSync(file))continue;
 if(file.toLowerCase().includes(needle)&&file!==migration)unexpected.push({file,scope:'filename'});
 const bytes=fs.readFileSync(file);if(bytes.includes(0))continue;
 for(const [index,line] of bytes.toString('utf8').split(/\r?\n/).entries()){
  if(!line.toLowerCase().includes(needle))continue;
  const permitted=file===migration||file==='docs/RELEASE-NOTES.md'&&line.startsWith(name[0].toUpperCase()+name.slice(1)+' removed at the owner');
  (permitted?allowed:unexpected).push({file,line:index+1});
 }
}
console.log(JSON.stringify({scope:'tracked/proposed working tree; immutable old Git history is retained',allowed,unexpected},null,2));
if(unexpected.length)process.exit(1);
