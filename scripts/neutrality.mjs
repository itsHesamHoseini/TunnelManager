import {execFileSync} from 'node:child_process';import fs from 'node:fs';
const pattern=new RegExp(['ar','va'].join(''),'i');
const git=(...args)=>execFileSync('git',args,{encoding:'utf8',maxBuffer:64*1024*1024});
let bad=0;for(const file of git('ls-files','--cached','--others','--exclude-standard').trim().split('\n').filter(Boolean)){if(pattern.test(file)){bad++;continue;}const b=fs.readFileSync(file);if(!b.includes(0)&&pattern.test(b.toString('utf8')))bad++;}
if(pattern.test(git('log','--all','-p','--format=%H%n%an <%ae>%n%cn <%ce>%n%B')))bad++;
for(const key of ['user.name','user.email']){try{if(pattern.test(git('config','--get',key)))bad++;}catch{}}
if(bad){console.error('Neutrality check failed ('+bad+' scopes). No offending content is printed.');process.exit(1);}console.log('Neutrality: tracked/proposed files, full history and authors passed.');
