// Reused by fixture and real Linux browser tests: names can repeat across peers
// and between a service and its linked tunnel. Select the service-name cell.
export async function openConsoleService(page,serviceName,nodeName){
 const row=page.locator('.console-panel tbody tr').filter({has:page.getByRole('cell',{name:nodeName,exact:true})}).filter({has:page.getByRole('cell').first().getByRole('button',{name:serviceName,exact:true})});
 await row.locator('td').first().getByRole('button',{name:serviceName,exact:true}).click();
 await page.getByRole('heading',{name:nodeName,exact:true}).waitFor();
}
export async function displayedConfiguration(page,label){
 const panel=page.locator('.operation details[open]').filter({has:page.locator('summary').filter({hasText:label})});
 await panel.waitFor();return panel.locator('pre').innerText();
}
