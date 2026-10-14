import {execFileSync} from 'node:child_process';import fs from 'node:fs';
const git=(...args)=>execFileSync('git',args,{encoding:'utf8',maxBuffer:64*1024*1024});
const patterns=[/-----BEGIN (?:OPENSSH|RSA|EC|PRIVATE) PRIVATE KEY-----/,/gh[pousr]_[A-Za-z0-9]{30,}/,/AKIA[A-Z0-9]{16}/,/https?:\/\/[^\s/@:]+:[^\s/@]+@/];
const files=git('ls-files','--cached','--others','--exclude-standard').trim().split('\n').filter(Boolean);let bad=0;
for(const f of files){const b=fs.readFileSync(f);if(!b.includes(0)&&patterns.some(p=>p.test(b.toString())))bad++;}
if(patterns.some(p=>p.test(git('log','--all','-p','--format=%B'))))bad++;
if(bad){console.error('Secret check failed; sensitive contents suppressed.');process.exit(1);}console.log('Local secret precheck passed. Full gitleaks history scan required by CI and M6.');
