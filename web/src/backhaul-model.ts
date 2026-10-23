export type Endpoint={host:string;port:number};
export type Mapping={id:string;name:string;user:Endpoint;backend:Endpoint;protocol:string};
export type Probe={kind:string;endpoint:Endpoint;path:string;expected:string};
export type OptionValue=string|number|boolean;
export type Spec={engine:string;version:string;transport:string;listener:string;dialer:string;transport_bind:Endpoint;transport_remote:Endpoint;routes:Mapping[];token?:string;advanced?:Record<string,OptionValue>;peer_options?:Record<string,Record<string,OptionValue>>;certificate?:string;tls_name?:string;allow_unverified_tls?:boolean;application?:Probe|null;raw_server?:string;raw_client?:string};
export type Node={id:string;name:string;role:string;approved:boolean;fresh?:boolean;metadata?:{address?:string;host?:string};telemetry?:{addresses?:string[]}};
export type RecordValue={id?:string;name?:string;revision?:number;clone?:boolean;spec?:Spec;health?:{at?:string;stale?:boolean;transport?:{status?:string}};configurations?:Record<string,string>};
export type EngineOption={key:string;kind:'number'|'boolean'|'choice';default:OptionValue;max?:number;roles:string[];choices?:string[]};

export const newSpec=():Spec=>({engine:'backhaul',version:'0.7.2',transport:'tcp',listener:'',dialer:'',transport_bind:{host:'0.0.0.0',port:28100},transport_remote:{host:'',port:28100},routes:[{id:'route_1',name:'',user:{host:'0.0.0.0',port:443},backend:{host:'127.0.0.1',port:2096},protocol:'tcp'}],token:'',advanced:{}});
export function validHost(host:string){if(!host||host.length>253||/[\s/\\"'$]/.test(host))return false;if(host.includes(':')){try{return Boolean(new URL('http://['+host+']/').hostname)}catch{return false}}return host.replace(/\.$/,'').split('.').every(x=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(x))}
export const validPort=(n:number)=>Number.isInteger(n)&&n>=1&&n<=65535;
export function updateMapping(spec:Spec,index:number,value:Mapping):Spec{
 const old=spec.routes[index],probe=spec.application;
 let application=probe;
 if(probe&&probe.endpoint.host===spec.transport_remote.host&&probe.endpoint.port===old.user.port)application={...probe,endpoint:{...probe.endpoint,port:value.user.port}};
 return {...spec,application,routes:spec.routes.map((r,i)=>i===index?value:r)};
}
export function safeDraft(spec:Spec){const safe=structuredClone(spec);delete safe.token;delete safe.raw_server;delete safe.raw_client;if(safe.application)delete (safe.application as Partial<Probe>).expected;return safe}
export function ordinaryErrors(spec:Spec){
 const errors:Record<string,string>={};const invalid='پورت باید عددی بین ۱ و ۶۵۵۳۵ باشد.';
 if(!validPort(spec.transport_bind.port))errors.transport_port=invalid;
 if(!validHost(spec.transport_remote.host))errors.connection_address='نشانی سرور ورودی را در تنظیمات پیشرفته کامل کنید.';
 if(spec.routes.length<1)errors.routes='حداقل یک نگاشت لازم است.';
 const conflict=(a:Endpoint,b:Endpoint)=>a.port===b.port&&(a.host===b.host||['0.0.0.0','::','*'].includes(a.host)||['0.0.0.0','::','*'].includes(b.host));
 spec.routes.forEach((r,i)=>{if(!validPort(r.user.port))errors[i+'.user_port']=invalid;else if(conflict(r.user,spec.transport_bind)||spec.routes.some((other,j)=>j!==i&&conflict(r.user,other.user)))errors[i+'.user_port']='این پورت با ورودی دیگری یا ارتباط تونل تداخل دارد.';if(!validPort(r.backend.port))errors[i+'.backend_port']=invalid;if(!validHost(r.backend.host))errors[i+'.backend_host']='دامنه یا IP معتبر وارد کنید؛ بدون http و شمارهٔ پورت.'});
 if((spec.token||'').length>512)errors.token='رمز مشترک حداکثر ۵۱۲ نویسه باشد.';
 return errors;
}
