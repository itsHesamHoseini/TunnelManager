import React,{useState} from 'react';
import {address,ErrorMessage,tr,useResource} from './operations';
import {Timestamp} from './presentation';
import type {Mapping,Spec} from './backhaul-model';
export type ReplacementEntry={node:string;server:string;instance:string;name:string;tunnels:string[]};
type Inventory={data?:{instances?:{id:string;parsed?:{bind?:string;remote?:string;routes?:Mapping[]}}[]};fresh?:boolean;at?:string};
type Tunnel={spec:Spec;affected_tunnels?:{name?:string}[]};
export function ReplacementGuide({entry,close}:{entry:ReplacementEntry;close:()=>void}){
 const paired=entry.tunnels.length>0;
 const {data,error}=useResource(paired?'tunnels/'+entry.tunnels[0]:'nodes/'+entry.node+'/inventory');
 const [maintenanceWindow,W]=useState('');
 const inventory=data as Inventory|null,tunnel=paired?data as Tunnel|null:null;
 const observed=!paired?inventory?.data?.instances?.find(item=>item.id===entry.instance):null;
 const routes:Mapping[]=tunnel?.spec?.routes||observed?.parsed?.routes||[];
 const endpoint=(value?:{host:string;port:number})=>value?.host&&value.port>0?address(value):tr('Not identified','مشخص نشده');
 const transport=tunnel?endpoint(tunnel.spec.transport_bind):observed?.parsed?.bind||observed?.parsed?.remote||tr('Not identified','مشخص نشده');
 const steps=[
  tr('Review both current configurations and every shared route; take backups before maintenance.','کانفیگ فعلی دو طرف و تمام مسیرهای مشترک را بازبینی و پیش از تعمیر بکاپ تهیه کنید.'),
  tr('Create a separately reviewed managed tunnel on unused test ports; keep this service running. Unsupported settings need explicit review, not silent removal.','تونل مدیریت‌شدهٔ جدا را با پورت‌های آزمایشی آزاد و پیش‌نمایش مستقل بسازید؛ این سرویس روشن بماند. تنظیمات ناسازگار باید بازبینی شوند، نه بی‌خبر حذف.'),
  tr('During the agreed maintenance window, explicitly switch user entry ports. The panel cannot stop or replace this unowned service for you.','در زمان تعمیر مورد توافق، ورودی کاربران را صریحاً جابه‌جا کنید. پنل این سرویس خارج از مدیریت را خودکار متوقف یا جایگزین نمی‌کند.'),
  tr('Check the actual user path before keeping changes. Failed new changes use their own local rollback; restore the old service separately if you intentionally stopped it.','پیش از نگه‌داشتن تغییرات، مسیر واقعی کاربران را بررسی کنید. تغییر ناموفق تونل تازه بازگشت محلی خودش را دارد؛ اگر سرویس قدیمی را عمداً متوقف کرده‌اید، بازگرداندنش اقدام جداست.')
 ];
 const affected=(tunnel?.affected_tunnels||[]).map(item=>item.name).filter((name):name is string=>!!name);
 const save=()=>{
  const text=[tr('Read-only replacement plan','برنامهٔ خواندنی جایگزینی'),entry.name+' · '+entry.server,tr('Unscheduled maintenance window: ','زمان پیشنهادی تعمیر؛ بدون زمان‌بندی اجرا: ')+(maintenanceWindow||tr('Not selected','انتخاب نشده')),tr('Transport endpoint: ','ارتباط دو سرور: ')+transport,...routes.map(r=>endpoint(r.user)+' → '+endpoint(r.backend)),!paired?tr('The peer and full path are not confirmed.','طرف مقابل و مسیر کامل تأیید نشده‌اند.'):'',...affected,...steps].filter(Boolean).join('\n');
  const url=URL.createObjectURL(new Blob([text],{type:'text/markdown;charset=utf-8'}));const a=document.createElement('a');a.href=url;a.download='replacement-plan.md';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
 };
 return <section className="replacement-guide" aria-label={tr('Replacement plan','برنامهٔ جایگزینی')}><div className="heading compact"><h3>{tr('Plan a managed replacement','برنامهٔ جایگزینی با تونل مدیریت‌شده')}</h3><button onClick={close}>{tr('Close plan','بستن برنامه')}</button></div><p><strong>{entry.name}</strong> · {entry.server}</p><ErrorMessage error={error}/>{!data&&!error?<p role="status">{tr('Reading existing evidence…','در حال خواندن شواهد موجود…')}</p>:data&&<><p>{tr('This is a read-only plan. No service is adopted, stopped or rewritten; choosing a time does not schedule an operation.','این برنامه فقط خواندنی است؛ هیچ سرویس پذیرفته، متوقف یا بازنویسی نمی‌شود و انتخاب زمان، عملیاتی را زمان‌بندی نمی‌کند.')}</p>{!paired&&<p className="notice warning">{tr('The peer is not confirmed. Pair and review both sides before deciding the full replacement map.','طرف مقابل تأیید نشده؛ پیش از تعیین نقشهٔ کامل جایگزینی، دو طرف را دستی وصل و بازبینی کنید.')}</p>}{!paired&&<small>{tr('Inventory observed: ','زمان کشف: ')}<Timestamp at={inventory?.at}/>{!inventory?.fresh&&' · '+tr('Old evidence; rediscover before changes','شواهد قدیمی؛ پیش از تغییر دوباره کشف کنید')}</small>}<p>{tr('Tunnel connection: ','ارتباط دو سرور: ')}<bdi>{transport}</bdi></p>{routes.length?<div className="tablewrap"><table><thead><tr><th>{tr('Observed user entry','ورودی شناسایی‌شدهٔ کاربران')}</th><th>{tr('Observed destination','مقصد شناسایی‌شده')}</th></tr></thead><tbody>{routes.map((r,i)=><tr key={r.id||i}><td><bdi>{endpoint(r.user)}</bdi></td><td><bdi>{endpoint(r.backend)}</bdi></td></tr>)}</tbody></table></div>:<p className="notice warning">{tr('Entry and destination mappings are not identified; do not infer them from the transport port.','نگاشت ورودی و مقصد مشخص نشده است؛ آن‌ها را از پورت ارتباط دو سرور حدس نزنید.')}</p>}{affected.length>0&&<p>{tr('Affected recorded tunnels: ','تونل‌های ثبت‌شدهٔ متأثر: ')}{affected.join('، ')}</p>}<label>{tr('Proposed maintenance window (not scheduled)','زمان پیشنهادی تعمیر (بدون اجرای زمان‌بندی‌شده)')}<input dir="ltr" type="text" maxLength={120} placeholder={tr('For example: tomorrow at 02:00 local time','مثلاً فردا ساعت ۲ بامداد به وقت تهران')} value={maintenanceWindow} onChange={e=>W(e.target.value)}/></label><ol>{steps.map(step=><li key={step}>{step}</li>)}</ol><button disabled={!!error} onClick={save}>{tr('Download plan without secrets','دریافت برنامه بدون اسرار')}</button></>}</section>;
}
