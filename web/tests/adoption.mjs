import {chromium} from 'playwright';
import {createHmac} from 'node:crypto';
import fs from 'node:fs';
const url=process.env.TUNNELMANAGER_TEST_URL;
if(!/^https:\/\/127\.0\.0\.1:\d+$/.test(url||''))throw Error('Loopback sample only');
function totp(s){const chars='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let bits='';for(const c of s)bits+=chars.indexOf(c).toString(2).padStart(5,'0');const key=Buffer.from(bits.match(/.{8}/g).map(x=>parseInt(x,2)));const b=Buffer.alloc(8);b.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));const h=createHmac('sha1',key).update(b).digest();return((h.readUInt32BE(h[19]&15)&0x7fffffff)%1000000).toString().padStart(6,'0')}
const browser=await chromium.launch({channel:'chrome',headless:true});
const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1448,height:1086}});
const page=await context.newPage();page.setDefaultTimeout(12000);let stage='login';const errors=[];page.on('pageerror',e=>errors.push(e.message));
const out='docs/evidence/revision2';fs.mkdirSync(out,{recursive:true});
try{
 await page.goto(url);await page.getByLabel('Username').fill('testadmin');await page.getByLabel('Password',{exact:true}).fill('Synthetic-Password-2026!');await page.getByRole('button',{name:'Continue',exact:true}).click();await page.waitForFunction(()=>document.querySelector('.private')?.textContent?.trim().length>=16);const secret=await page.locator('.private').innerText();await page.getByLabel('Code',{exact:true}).fill(totp(secret));await page.getByRole('button',{name:'Continue',exact:true}).click();await page.getByRole('button',{name:'I saved them'}).click();await page.getByRole('heading',{name:'Overview',exact:true}).waitFor();await page.getByRole('button',{name:'فارسی',exact:true}).click();
 await page.evaluate(()=>{const banner=document.createElement('div');banner.textContent='نمونه — Chrome واقعی و دیتابیس محلی؛ بدون اجرای لینوکسی یا پذیرش مدیریت';banner.style.cssText='background:#fff3dd;color:#714200;padding:8px;text-align:center';document.body.prepend(banner)});
 stage='classification';await page.locator('nav').getByRole('button',{name:'تونل‌ها',exact:true}).click();await page.getByText('بررسی سرویس‌ها و اقدام بعدی',{exact:true}).click();
 const report=page.locator('.adoption-report');await report.getByText('نسخهٔ not-verified تأیید نشده؛ باینری را در ابزارهای سرور بررسی کنید.',{exact:true}).waitFor();
 if((await report.locator('tbody tr').count())!==4)throw Error('Expected four service classifications');
 for(const width of [1448,1920,390]){await page.setViewportSize({width,height:width===390?844:1086});await page.screenshot({path:`${out}/wp3-classification-sample-${width}.png`,fullPage:true});if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth))throw Error('page overflow '+width)}
 await page.setViewportSize({width:1448,height:1086});
 stage='preview';await report.getByRole('button',{name:'بررسی پذیرش مدیریت',exact:true}).first().click();
 await page.getByRole('button',{name:'بررسی پیش از پذیرش',exact:true}).waitFor();
 if(await page.getByRole('button',{name:'پذیرش مدیریت همین سرویس‌ها',exact:true}).count())throw Error('Adoption offered before dry run');
 await page.getByRole('button',{name:'بررسی پیش از پذیرش',exact:true}).click();await page.getByRole('button',{name:'پذیرش مدیریت همین سرویس‌ها',exact:true}).waitFor();
 await page.screenshot({path:out+'/wp3-preview-sample.png',fullPage:true});
 const tunnels=await(await context.request.get(url+'/api/tunnels')).json();if(tunnels.some(t=>t.managed))throw Error('Read-only preview adopted infrastructure');
 if(errors.length)throw Error(errors[0]);console.log(JSON.stringify({scope:'sample only; actual Chrome/Go/PostgreSQL; canned read receipts, no Linux effects',counts:{adoptable:2,readonly:1,unpaired:1,managed:0},cases:['specific reasons','read-only preview before confirmation','no automatic adoption','responsive captures']}));
}catch(e){if(stage!=='login')await page.screenshot({path:out+'/wp3-failure-sample.png',fullPage:true});console.error('Adoption '+stage+': '+e.message.split('\n')[0]);process.exitCode=1}finally{await browser.close()}
