import {chromium} from 'playwright';
import {createHmac} from 'node:crypto';
import fs from 'node:fs';
const url=process.env.TUNNELMANAGER_TEST_URL;
if(!url||!/^https:\/\/127\.0\.0\.1:\d+$/.test(url))throw Error('Isolated loopback test only');
const before=process.env.TUNNELMANAGER_REVISION_BEFORE==='1';
const output=before?'.runtime/revision2-before':'docs/evidence/revision2';fs.mkdirSync(output,{recursive:true});
function totp(s){const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';const bits=[...s].map(x=>alphabet.indexOf(x).toString(2).padStart(5,'0')).join('');const k=Buffer.from(bits.match(/.{8}/g).map(x=>parseInt(x,2)));const b=Buffer.alloc(8);b.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));const h=createHmac('sha1',k).update(b).digest();return ((h.readUInt32BE(h[19]&15)&0x7fffffff)%1000000).toString().padStart(6,'0')}
const browser=await chromium.launch({channel:'chrome',headless:true});
try{
 const ctx=await browser.newContext({ignoreHTTPSErrors:true});const page=await ctx.newPage();const exceptions=[];page.on('pageerror',e=>exceptions.push(e.message));
 await page.goto(url);await page.getByLabel('Username').fill('testadmin');await page.getByLabel('Password',{exact:true}).fill('Synthetic-Password-2026!');await page.getByRole('button',{name:'Continue',exact:true}).click();await page.locator('.private').waitFor();await page.getByLabel('Code',{exact:true}).fill(totp(await page.locator('.private').innerText()));await page.getByRole('button',{name:'Continue',exact:true}).click();await page.getByRole('button',{name:'I saved them'}).click();await page.getByRole('heading',{name:'Overview',exact:true}).waitFor();await page.getByRole('button',{name:'فارسی',exact:true}).click();
 const nav=name=>page.locator('nav').getByRole('button',{name,exact:true});
 for(const [width,height] of [[1448,1086],[1920,1086],[390,844]]){
  await page.setViewportSize({width,height});await nav('نمای کلی').click();await page.locator('.server-table').waitFor();
  await page.evaluate(()=>{if(document.querySelector('#sample-label'))return;const x=document.createElement('div');x.id='sample-label';x.textContent='نمونهٔ آزمایشی محلی — داده‌های ساختگی برای آزمون رابط';x.style.cssText='position:fixed;bottom:0;left:0;right:0;z-index:9999;background:#fff2ca;color:#3f3100;text-align:center;font:12px sans-serif;padding:3px';document.body.append(x)});
  await page.screenshot({path:`${output}/wp0-overview-sample-${width}.png`,fullPage:true});
  if(!before){
   const reported=await ctx.request.get(url+'/api/nodes').then(r=>r.json());
   const metric=page.locator('.console-metric').filter({has:page.getByText('عامل‌های متصل',{exact:true})});
   if(Number(await metric.locator('b').innerText())!==reported.filter(n=>n.online).length)throw Error('Online card disagrees with authoritative node state');
   for(const name of ['نمونه خارج قطع','نمونه ایران قدیمی','نمونه بدون داده']){
    const row=page.locator('.server-table tbody tr').filter({hasText:name});
    if(await row.locator('.resource-current').count())throw Error('Disconnected/missing resources presented as current: '+name);
    if(await row.locator('.status.success').count())throw Error('Disconnected node shown online: '+name);
   }
   const visibleText=await page.locator('.console-content').innerText();
   if(/operation-failed|node_observation_stale|unknown_internal_event|unknown_private_reason/.test(visibleText))throw Error('Raw event code leaked outside technical details');
   if(await page.locator('time[dir="ltr"][title]').count()===0)throw Error('Shared isolated timestamp missing');
   if(width>=1280&&await page.locator('.server-table').evaluate(x=>x.scrollWidth>x.parentElement.clientWidth+1))throw Error('Desktop server table overflow');
   await nav('تونل‌ها').click();await page.getByRole('button',{name:'نمونه تونل ایران به خارج',exact:true}).waitFor();
   if(await page.getByText('نمونه کنارگذاشته‌شده',{exact:true}).count())throw Error('Retired tunnel remains visible after real sample database migration');
   await page.screenshot({path:`${output}/wp1-tunnels-sample-${width}.png`,fullPage:true});
  }
 }
 if(!before){
  await page.route('**/api/nodes',async route=>{const response=await route.fetch();const rows=await response.json();const metric=Number(new URL(page.url()).hash.slice(1));for(const n of rows){if(n.id==='live-fixture'&&Number.isFinite(metric)){n.telemetry.cpu_percent=metric;n.telemetry.ram_used=metric;n.telemetry.ram_total=100;n.telemetry.disk_total=100;n.telemetry.disk_free=100-metric}}await route.fulfill({response,json:rows})});
  const thresholdResults=[];
  for(const [value,level,word] of [[69.9,'normal','عادی'],[70,'high','بالا'],[90,'high','بالا'],[90.1,'critical','بحرانی']]){
   await page.goto(url+'/#'+value);await page.reload();await page.getByRole('heading',{name:'نمای کلی',exact:true}).waitFor();const row=page.locator('.server-table tbody tr').filter({hasText:'نمونه ایران متصل'});await row.locator('.resource-'+level+'.resource-current').first().waitFor();
   if(await row.locator('.resource-'+level+'.resource-current').count()!==3)throw Error('Threshold classification failed: '+value);
   if(!await row.innerText().then(x=>x.includes(word)))throw Error('Threshold text absent: '+value);
   const color=await row.locator('.resource-current').first().evaluate(x=>getComputedStyle(x).color);thresholdResults.push({value,level,color});
  }
  if(new Set(thresholdResults.map(x=>x.color)).size!==3)throw Error('Threshold colors do not distinguish levels');
  console.log('Threshold boundary evidence: '+JSON.stringify(thresholdResults));
  await page.unroute('**/api/nodes');
  await page.evaluate(()=>{const x=document.createElement('div');x.id='sample-label';x.textContent='نمونهٔ آزمایشی محلی — داده‌های ساختگی برای آزمون رابط';x.style.cssText='position:fixed;bottom:0;left:0;right:0;z-index:9999;background:#fff2ca;color:#3f3100;text-align:center;font:12px sans-serif;padding:3px';document.body.append(x)});
  await page.setViewportSize({width:1448,height:1086});await nav('سرورها').click();await page.getByRole('button',{name:'نمونه خارج قطع',exact:true}).click();
  if(await page.locator('.server-summary .resource-current').count())throw Error('Summary reused stale current values');
  await page.getByRole('button',{name:'بازکردن ابزارهای سرور',exact:true}).click();await page.getByRole('heading',{name:'نمونه خارج قطع',exact:true}).waitFor();
  if(await page.locator('.summary .resource-current').count())throw Error('Node details reused stale values');
  await page.screenshot({path:`${output}/wp0-disconnected-detail-sample.png`,fullPage:true});
  await nav('نمای کلی').click();await page.route('**/api/nodes',route=>route.abort());
  // Let the real polling path fail; no synthetic state setter bypasses the application.
  await page.getByRole('alert').filter({hasText:/ارتباط|درخواست|دریافت/}).first().waitFor({timeout:20000});
  if(await page.locator('.server-table .status.success').count())throw Error('Failed refresh left online status');
  if(await page.locator('.server-table .resource-current').count())throw Error('Failed refresh left current resources');
  await page.screenshot({path:`${output}/wp0-api-error-sample.png`,fullPage:true});
 }
 if(exceptions.length)throw exceptions[0];
 console.log(JSON.stringify({scope:'sample UI with real Chrome and isolated Go/PostgreSQL authentication',before,widths:[1448,1920,390],screenshots:output,assertions:before?'baseline captures only':'offline/missing/API-failure resources, messages, time isolation, desktop layout'}));
}finally{await browser.close()}
