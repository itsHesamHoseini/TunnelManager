import fs from 'node:fs';
import path from 'node:path';
// Disposable CI only. Remove exactly the known generated outputs so an early
// failure cannot upload a tracked historical capture as evidence of this run.
if(process.env.CI!=='true')throw Error('Disposable native CI only');
const root=path.resolve('docs/evidence');
const files=['m4-native-backhaul-tcp-preview.png','m4-native-backhaul-tcp-path-fa.png','m4-native-backhaul-wss-preview.png','m4-native-backhaul-wss-path-fa.png','m4-native-mobile.png','console-native-discovery-en.png','console-native-service-tools-en.png','native-failure.png','revision2/wp2-port-edit-native.webm'];
for(const file of files){const target=path.resolve(root,file);if(!target.startsWith(root+path.sep))throw Error('Invalid evidence path');fs.rmSync(target,{force:true})}
console.log('Cleared only known generated native captures; the next artifact contains fresh outputs.');
