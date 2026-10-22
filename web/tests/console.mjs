import fs from 'node:fs';
export async function verifyConsole(page){
 await page.setViewportSize({width:1448,height:1086});fs.mkdirSync('docs/evidence',{recursive:true});
 const nav=name=>page.locator('nav').getByRole('button',{name,exact:true});
 await nav('نمای کلی').click();await page.locator('.console-metrics').waitFor();await page.screenshot({path:'docs/evidence/console-overview-fixture-fa.png'});
 await nav('مسیرها').click();await page.getByRole('button',{name:'Synthetic route',exact:true}).first().click();await page.locator('.port-map').waitFor();
 if(!await page.locator('.port-map').innerText().then(x=>x.includes('2096')&&x.includes('28101')&&x.includes('24444')))throw Error('Independent endpoint ports lost in route pane');
 await page.screenshot({path:'docs/evidence/console-routes-fixture-fa.png'});
 await page.getByLabel('جست‌وجوی مسیر',{exact:true}).fill('no-such-route');if(await page.locator('.console-panel table tbody tr').count())throw Error('Route search not applied');await page.getByRole('button',{name:'پاک‌کردن فیلترها',exact:true}).click();
 await nav('سرورها').click();await page.getByRole('button',{name:'Synthetic listener',exact:true}).click();await page.getByRole('button',{name:'بازکردن ابزارهای سرور',exact:true}).waitFor();await page.locator('.resource-chart svg').waitFor();await page.screenshot({path:'docs/evidence/console-servers-fixture-fa.png'});
 await page.getByLabel('فیلتر سرورها',{exact:true}).selectOption('iran');await page.getByText('سروری با این فیلتر پیدا نشد.',{exact:true}).waitFor();await page.getByLabel('فیلتر سرورها',{exact:true}).selectOption('all');
 await nav('دیسکاوری').click();await page.getByRole('button',{name:'Synthetic shared service',exact:true}).click();await page.getByRole('heading',{name:'جزئیات سرویس',exact:true}).waitFor();await page.screenshot({path:'docs/evidence/console-discovery-fixture-fa.png'});
 if(await page.getByRole('button',{name:'اجرای دیسکاوری',exact:true}).isEnabled())throw Error('Discovery allowed without selection');await page.getByLabel('Synthetic listener',{exact:true}).check();if(!await page.getByRole('button',{name:'اجرای دیسکاوری',exact:true}).isEnabled())throw Error('Selected server did not enable discovery');
 await page.getByLabel('جست‌وجوی کلی',{exact:true}).press('Control+k');if(!await page.getByLabel('جست‌وجوی کلی',{exact:true}).evaluate(el=>el===document.activeElement))throw Error('Search keyboard shortcut failed');
 for(const name of ['نمای کلی','مسیرها','سرورها','دیسکاوری']){await page.setViewportSize({width:390,height:844});await nav(name).click();if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth))throw Error('Console mobile overflow: '+name)}
 await page.screenshot({path:'docs/evidence/console-mobile-fixture-fa.png'});await page.setViewportSize({width:1448,height:1086});
 await nav('تونل‌ها').click();
}
