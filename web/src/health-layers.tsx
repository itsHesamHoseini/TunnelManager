import React from 'react';
import {Badge,MessageCode,label,tr} from './operations';
import {Timestamp} from './presentation';
type Layer={status?:string;at?:string;source?:string;code?:string};
type Observation={at?:string;stale?:boolean;process?:Layer[];transport?:Layer;tls?:Layer;application?:Layer};
export function HealthLayers({health,historical=false,nodes=[]}:{health?:Observation;historical?:boolean;nodes?:{id:string;name:string}[]}){
 const processes=Array.isArray(health?.process)?health.process:[];
 const age=Date.now()-Date.parse(health?.at||''),current=historical||!health?.stale&&Number.isFinite(age)&&age>=0&&age<=180000;
 const processState=processes.length?(processes.some(x=>x.status==='failed')?'failed':processes.every(x=>x.status==='passed')?'passed':processes.some(x=>x.status==='stopped')?'stopped':'unknown'):'unknown';
 const all:{kind:string;value:Layer;observations:Layer[];help:string}[]=[
  {kind:'process',value:{status:processState},observations:processes,help:tr('Whether the two selected services are running.','آیا دو سرویس انتخاب‌شده در حال اجرا هستند؟')},
  {kind:'transport',value:health?.transport||{},observations:health?.transport?[health.transport]:[],help:tr('TCP: whether the other server accepts the tunnel connection.','TCP: آیا سرور مقابل ارتباط تونل را می‌پذیرد؟')},
  {kind:'tls',value:health?.tls||{},observations:health?.tls?[health.tls]:[],help:tr('TLS: a separate encrypted-connection and certificate check.','TLS: بررسی جداگانهٔ ارتباط رمزگذاری‌شده و گواهی.')},
  {kind:'application',value:health?.application||{},observations:health?.application?[health.application]:[],help:tr('Only the configured protocol is tested. This is not proof of VLESS.','فقط پروتکل تنظیم‌شده سنجیده می‌شود؛ اثبات سلامت VLESS نیست.')}
 ];
 return <div className="healthstrip">{all.map(({kind,value,observations,help})=><div key={kind}><strong>{label(kind)}</strong><Badge value={!current?(health?.stale||age>180000?'stale':'unknown'):value.status} at={historical?undefined:value.at||health?.at}/><p>{help}</p>{observations.length?observations.map((o,i)=><small key={i}>{o.source?nodes.find(n=>n.id===o.source)?.name||tr('Server no longer listed','سرور دیگر در فهرست نیست'):tr('Source not recorded','مبدأ ثبت نشده')} · <Timestamp at={o.at||health?.at}/>{o.code&&<MessageCode code={o.code}/>}</small>):<small>{tr('Not observed','مشاهده نشده')}</small>}</div>)}</div>
}
