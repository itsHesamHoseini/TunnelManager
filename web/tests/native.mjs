import {chromium}from'playwright';
import fs from'node:fs';
import {openConsoleService,displayedConfiguration} from './console-selectors.mjs';
const fixture=JSON.parse(fs.readFileSync(process.env.TUNNELMANAGER_NATIVE_FIXTURE,'utf8'));
if(!/^https:\/\/127\.0\.0\.1:\d+$/.test(fixture.url)||process.env.CI!=='true')throw Error('Disposable native CI fixture only');
const browser=await chromium.launch({channel:'chrome',headless:true});
const ctx=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1440,height:1000}});
let page=await ctx.newPage();page.setDefaultTimeout(65000);let stage='login';
fs.mkdirSync('docs/evidence',{recursive:true});
try{
 await page.goto(fixture.url);await page.getByLabel('Username',{exact:true}).fill('testadmin');await page.getByLabel('Password',{exact:true}).fill('Synthetic-Password-2026!');await page.getByRole('button',{name:'Continue',exact:true}).click();await page.getByRole('button',{name:'Recovery code',exact:true}).click();await page.getByLabel('Code',{exact:true}).fill(fixture.recovery);await page.getByRole('button',{name:'Continue',exact:true}).click();await page.getByRole('heading',{name:'Overview',exact:true}).waitFor();
 for(const [index,scenario]of [{engine:'backhaul',transport:'tcp'},{engine:'backhaul',transport:'wss'}].entries()){
 const{engine,transport}=scenario;const tunnelName='Synthetic native '+engine+' '+transport;
  stage=engine+'-form';await page.locator('nav').getByRole('button',{name:'Tunnels',exact:true}).click();await page.getByRole('button',{name:'Create tunnel',exact:true}).click();await page.getByLabel('Tunnel name',{exact:true}).fill(tunnelName);await page.getByLabel('User entry server',{exact:true}).selectOption(fixture.listener);await page.getByLabel('Destination server',{exact:true}).selectOption(fixture.dialer);await page.getByLabel('Connection type',{exact:true}).selectOption(transport);if(['tls','wss'].includes(transport)){await page.getByLabel('Deployed transport certificate',{exact:true}).selectOption(fixture.certificate)};if(transport==='wss'){await page.getByLabel('I understand this engine version encrypts traffic but does not verify the other server certificate.',{exact:true}).check()};
  await page.getByLabel('Tunnel connection port',{exact:true}).fill(String(28100+index));await page.getByLabel('Entry server connection address',{exact:true}).fill(fixture.listener_ip);await page.getByLabel('User entry port',{exact:true}).fill(String(24443+index*10));await page.getByLabel('Destination port',{exact:true}).fill('29096');await page.locator('.editor-advanced>summary').click();await page.getByText('Application check (optional)',{exact:true}).click();
  await page.getByLabel('Expected protocol at user entry',{exact:true}).selectOption('http');await page.getByLabel('HTTP path',{exact:true}).fill('/probe');await page.getByLabel('Expected response text (optional)',{exact:true}).fill('synthetic-native-response');await page.getByRole('button',{name:'Check and preview',exact:true}).click();
  stage=engine+'-preview';await page.getByRole('button',{name:'Confirm impact and apply',exact:true}).waitFor();await page.getByText('Compare current and proposed configuration',{exact:true}).first().click();await page.screenshot({path:'docs/evidence/m4-native-'+engine+'-'+transport+'-preview.png',fullPage:true});await page.getByRole('button',{name:'Confirm impact and apply',exact:true}).click();
  stage=engine+'-activate';await page.getByRole('button',{name:'The path works; keep changes',exact:true}).waitFor();await page.getByRole('button',{name:'Check the pending path',exact:true}).click();await page.locator('.operation').last().locator(':scope > .heading .status').filter({hasText:'Finished'}).waitFor();await page.getByRole('button',{name:'The path works; keep changes',exact:true}).click();
  await page.getByRole('button',{name:'Return to tunnels',exact:true}).click();stage=engine+'-inspect';await page.getByRole('button',{name:tunnelName,exact:true}).waitFor();await page.getByRole('button',{name:tunnelName,exact:true}).click();await page.getByRole('button',{name:'Check connection',exact:true}).click();await page.locator('.healthstrip>div').filter({has:page.getByText('Application response',{exact:true})}).locator('.status').filter({hasText:'Passed'}).waitFor();
  await page.getByRole('button',{name:'فارسی',exact:true}).click();await page.getByRole('heading',{name:tunnelName,exact:true}).waitFor();await page.screenshot({path:'docs/evidence/m4-native-'+engine+'-'+transport+'-path-fa.png',fullPage:true});await page.getByRole('button',{name:'English',exact:true}).click();
  if(index===0){stage='native-entry-check';await page.getByText('Check user entry through the tunnel',{exact:true}).click();await page.getByRole('button',{name:'Run entry check',exact:true}).click();await page.locator('.entry-check .operation .status').filter({hasText:'Passed'}).waitFor();await page.getByText('Only this user-entry TCP/TLS check was recorded; it is not proof of VLESS.',{exact:true}).waitFor();await page.getByText('Check user entry through the tunnel',{exact:true}).click()}
  if(index===0){
   const originalPage=page;let videoContext,video;
   for(const change of ['user_port','destination','token','transport']){
    if(change==='user_port'){videoContext=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1448,height:1086},storageState:await ctx.storageState(),recordVideo:{dir:'.runtime/native-edit-video',size:{width:1280,height:960}}});page=await videoContext.newPage();page.setDefaultTimeout(65000);video=page.video();await page.goto(fixture.url);await page.locator('nav').getByRole('button',{name:'Tunnels',exact:true}).click();await page.evaluate(()=>{const b=document.createElement('div');b.textContent='native — disposable Linux / systemd / Backhaul; no production data';b.style.cssText='background:#fff3dd;padding:8px;text-align:center';document.body.prepend(b)})}
    else await page.locator('main').getByRole('button',{name:'Tunnels',exact:true}).first().click();
    await page.evaluate(()=>{window.__tmButtonClicks=[];if(!window.__tmClickListener){document.addEventListener('click',e=>{const b=e.target.closest?.('button');if(b)window.__tmButtonClicks.push(b.textContent.trim())});window.__tmClickListener=true}});

    stage='simple-edit-'+change;await page.getByRole('row').filter({has:page.getByRole('button',{name:tunnelName,exact:true})}).getByRole('button',{name:'Edit settings',exact:true}).click();
    if(change==='user_port')await page.getByLabel('User entry port',{exact:true}).fill('24543');
    if(change==='destination'){await page.getByLabel('Destination address',{exact:true}).fill('localhost');await page.getByLabel('Destination port',{exact:true}).fill('29097')}
    if(change==='token')await page.getByRole('button',{name:'Generate a new secure secret',exact:true}).click();
    if(change==='transport'){await page.getByLabel('Connection type',{exact:true}).selectOption('wss');await page.getByLabel('Deployed transport certificate',{exact:true}).selectOption(fixture.certificate);await page.getByLabel('I understand this engine version encrypts traffic but does not verify the other server certificate.',{exact:true}).check()}
    await page.getByRole('button',{name:'Check and preview',exact:true}).click();await page.getByRole('button',{name:'Confirm impact and apply',exact:true}).waitFor();
    if(change==='token')await page.getByText('The shared secret changes on both sides together. Users briefly disconnect.',{exact:true}).waitFor();
    await page.getByRole('button',{name:'Confirm impact and apply',exact:true}).click();await page.getByRole('button',{name:'The path works; keep changes',exact:true}).click();await page.getByRole('button',{name:'Return to tunnels',exact:true}).click();await page.getByRole('button',{name:tunnelName,exact:true}).click();await page.getByRole('heading',{name:tunnelName,exact:true}).waitFor();await page.getByRole('button',{name:'Check connection',exact:true}).click();await page.locator('.healthstrip>div').filter({has:page.getByText('Application response',{exact:true})}).locator('.status').filter({hasText:'Passed'}).waitFor();
    const buttons=await page.evaluate(()=>window.__tmButtonClicks);console.log(JSON.stringify({native_edit:change,reviewStages:3,recordedButtonClicks:buttons,measurement:'button clicks only; fill/select operations are separate field interactions',scope:'real signed agents/systemd/Backhaul and HTTP through user entry'}));
    if(change==='user_port'){fs.mkdirSync('docs/evidence/revision2',{recursive:true});await page.close();await video.saveAs('docs/evidence/revision2/wp2-port-edit-native.webm');await videoContext.close();page=originalPage}

   }
  }
  await page.locator('main').getByRole('button',{name:'Tunnels',exact:true}).first().click();
  console.log('Native browser '+engine+': actual form, two-peer preflight, impact confirmation, local rollback armed, real pending HTTP path check, explicit commit and independent health observations passed.');
 }

 stage='console-discovery';await page.setViewportSize({width:1448,height:1086});
 const actualNodes=await(await ctx.request.get(fixture.url+'/api/nodes')).json();
 await page.locator('nav').getByRole('button',{name:'Discovery',exact:true}).click();
 for(const id of [fixture.listener,fixture.dialer]){const n=actualNodes.find(x=>x.id===id);if(!n)throw Error('Native node missing');await page.getByLabel(n.name,{exact:true}).check()}
 await page.getByRole('button',{name:'Run discovery',exact:true}).click();
 await page.waitForFunction(()=>document.querySelectorAll('.operation>.heading .success').length===2,null,{timeout:90000});
 const discoveries=await(await ctx.request.get(fixture.url+'/api/discoveries')).json();
 const nativeService=discoveries.flatMap(n=>(n.instances||[]).map(v=>({...v,node:n}))).find(v=>v.managed&&v.node.id===fixture.listener);if(!nativeService)throw Error('Actual managed services absent after discovery');
 await page.screenshot({path:'docs/evidence/console-native-discovery-en.png',fullPage:true});
 stage='console-service-tools';await page.locator('nav').getByRole('button',{name:'Services',exact:true}).click();await openConsoleService(page,nativeService.name,nativeService.node.name);await page.getByRole('button',{name:'Read current configuration',exact:true}).click();
 await page.waitForFunction(()=>document.querySelectorAll('.operation>.heading .success').length===1,null,{timeout:60000});
 const nativeConfiguration=await displayedConfiguration(page,'Current redacted configuration');if(nativeConfiguration.length<20||!nativeConfiguration.includes('[redacted]'))throw Error('Real redacted configuration was not returned');
 await page.screenshot({path:'docs/evidence/console-native-service-tools-en.png',fullPage:true});
 stage='console-route-check';await page.locator('nav').getByRole('button',{name:'Routes',exact:true}).click();await page.locator('.console-panel table tbody .link').first().click();await page.getByRole('button',{name:'Inspect, check and manage tunnel',exact:true}).click();await page.getByRole('button',{name:'Check connection',exact:true}).click();await page.waitForFunction(()=>document.querySelectorAll('.operation>.heading .success').length===1,null,{timeout:60000});await page.locator('.healthstrip>div').filter({has:page.getByText('Application response',{exact:true})}).locator('.status').filter({hasText:'Passed'}).waitFor();
 await page.locator('nav').getByRole('button',{name:'Tunnels',exact:true}).click();
 console.log('Native operational console: selected-node discovery, direct service configuration read and logical-route application check passed against real signed Linux/systemd peers and engines.');
 stage='mobile';await page.setViewportSize({width:390,height:844});await page.screenshot({path:'docs/evidence/m4-native-mobile.png',fullPage:true});if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth))throw Error('mobile overflow');
}catch(e){if(stage!=='login'){try{const res=await page.request.get(fixture.url+'/api/operations');const ops=await res.json();console.error(JSON.stringify(ops.slice(0,8).map(x=>({kind:x.kind,phase:x.phase,error:x.error}))))}catch{};await page.screenshot({path:'docs/evidence/native-failure.png',fullPage:true}).catch(()=>{})};console.error('Native browser failed at '+stage+(stage==='login'?' (authentication details suppressed)':': '+String(e.message).split('\n')[0]));process.exitCode=1}finally{await browser.close()}
