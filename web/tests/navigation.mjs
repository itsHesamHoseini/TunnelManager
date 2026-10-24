export async function navigateConsole(page,name){
 const groups=[
  [['مسیرها','Routes','دیسکاوری','Discovery','کشف سرویس‌های موجود','Discover existing services'],'تونل‌ها','Tunnels'],
  [['سرویس‌ها','Services','پورت‌ها','Ports','برچسب‌ها','Tags','مانیتورینگ','Monitoring'],'سرورها','Servers'],
  [['عملیات','Operations','هشدارها','Alerts'],'رویدادها و هشدارها','Events and alerts'],
  [['امنیت','Security'],'تنظیمات','Settings'],
 ];
 const fa=await page.locator('html').getAttribute('lang')==='fa';
 const group=groups.find(([children])=>children.includes(name));
 if(group){await page.locator('.console-sidebar nav').getByRole('button',{name:group[fa?1:2],exact:true}).click();
  if(group[1]==='سرورها')await page.locator('.workspace-navigation summary').click();
 }
 const aliases={'دیسکاوری':'کشف سرویس‌های موجود','Discovery':'Discover existing services'};
 await page.locator('nav').getByRole('button',{name:aliases[name]||name,exact:true}).click();
}
export async function verifyNavigation(page){
 const main=page.locator('.console-sidebar nav');
 if(await main.getByRole('button').count()!==6)throw Error('Main navigation must contain exactly six destinations');
 const names=await main.getByRole('button').allTextContents();
 if(new Set(names).size!==6)throw Error('Main navigation labels are ambiguous');
 for(const [legacy,target] of [['routes','tunnels?view=routes'],['discovery','tunnels?view=discovery'],['services','servers?view=services'],['ports','servers?view=ports'],['tags','servers?view=tags'],['monitoring','servers?view=monitoring'],['operations','events'],['alerts','events?view=alerts'],['security','settings?view=security']]){
  await page.evaluate(hash=>{location.hash=hash},'#/'+legacy);
  await page.waitForURL(url=>url.hash==='#/'+target);
  await page.locator('.console-content> .console-title h1').waitFor();
 }
 await navigateConsole(page,'نمای کلی');await navigateConsole(page,'سرورها');await page.goBack();await page.waitForURL(url=>url.hash==='#/overview');
 await page.setViewportSize({width:390,height:844});if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth))throw Error('Navigation causes mobile page overflow');
 await page.setViewportSize({width:1448,height:1086});
 console.log(JSON.stringify({navigation:'six destinations, retained advanced tools, nine old aliases, browser Back, mobile overflow',scope:'actual Chrome/Go/PostgreSQL; synthetic data'}));
}
