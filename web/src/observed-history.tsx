import React from 'react';
import {Timestamp} from './presentation';
import {tr} from './operations';
export type Sample={at:string;data:Record<string,unknown>;aggregation?:string};
const interval=(value?:string)=>value==='day'?86400000:value==='hour'?3600000:value==='5 minutes'?300000:90000;
export function measuredSegments(samples:Sample[],field:string){
 const sorted=[...samples].filter(s=>Number.isFinite(Date.parse(s.at))).sort((a,b)=>Date.parse(a.at)-Date.parse(b.at));
 const segments:Sample[][]=[];let current:Sample[]=[];let previous:Sample|undefined;
 for(const row of sorted){const value=row.data?.[field];const usable=typeof value==='number'&&Number.isFinite(value);const gap=previous&&Date.parse(row.at)-Date.parse(previous.at)>Math.max(interval(previous.aggregation),interval(row.aggregation))+1000;
  if(!usable||gap){if(current.length)segments.push(current);current=[]}
  if(usable)current.push(row);previous=row;
 }if(current.length)segments.push(current);return segments
}
export function ObservedHistoryChart({samples,field,label,unit=''}:{samples:Sample[];field:string;label:string;unit?:string}){
 const segments=measuredSegments(samples,field),points=segments.flat();
 if(!points.length)return <div className="chart"><h3>{label}</h3><p>{tr('No measured samples in this range.','در این بازه دادهٔ اندازه‌گیری‌شده‌ای وجود ندارد.')}</p></div>;
 const start=Date.parse(points[0].at),end=Date.parse(points.at(-1)!.at),values=points.map(s=>s.data[field] as number),min=field==='cpu_percent'?0:Math.min(...values),max=field==='cpu_percent'?100:Math.max(...values);
 const x=(s:Sample)=>(Date.parse(s.at)-start)/Math.max(end-start,1)*480+10,y=(s:Sample)=>90-((s.data[field] as number)-min)/Math.max(max-min,1)*70;
 return <div className="chart observed-history"><h3>{label}</h3><svg viewBox="0 0 500 100" role="img" aria-label={label}>{segments.map((segment,i)=><g key={i} data-measured-segment={segment.length}>{segment.length>1&&<polyline points={segment.map(p=>`${x(p)},${y(p)}`).join(' ')} fill="none" stroke="var(--accent)" strokeWidth="2"/>}{segment.map(p=><circle key={p.at} cx={x(p)} cy={y(p)} r="2" fill="var(--accent)"><title>{String(p.data[field])} {unit}</title></circle>)}</g>)}</svg><small><Timestamp at={points[0].at} absolute/> — <Timestamp at={points.at(-1)!.at} absolute/> · <bdi>{Math.min(...values).toFixed(1)}–{Math.max(...values).toFixed(1)} {unit}</bdi></small><small>{tr('Measured averages; gaps remain empty.','میانگین مشاهدات؛ فاصله‌های بدون داده خالی‌اند.')}</small></div>
}
