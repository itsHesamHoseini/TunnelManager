import React, {useSyncExternalStore} from 'react';

let language = 'en';
export function presentationLanguage(value: string) { language = value; }
const localized = (en: string, fa: string) => language === 'fa' ? fa : en;

export interface ObservedNode {
 approved?: boolean; connected?: boolean; fresh?: boolean; seen?: string;
 telemetry?: Record<string, unknown>; observation_reason?: string;
}
export const sampleTime = (value?: string) => value ? Date.parse(value) : NaN;
export function isNodeOnline(node: ObservedNode, now = Date.now()) {
 const age = now - sampleTime(node.seen);
 return Boolean(node.approved && node.connected && node.fresh && Number.isFinite(age) && age >= 0 && age <= 90000 && Object.keys(node.telemetry || {}).length);
}
export function nodeReason(node: ObservedNode) {
 if (!node.approved) return localized('Compare this server’s identity before approval.', 'هویت این سرور را مقایسه و سپس تأیید کنید.');
 if (!node.seen || !Object.keys(node.telemetry || {}).length) return localized('No observations received. Check the agent on this server; its cause is not yet verified.', 'هنوز داده‌ای از این سرور نرسیده؛ عامل همین سرور را بررسی کنید. علت هنوز بررسی نشده است.');
 if (!node.connected) return localized('The agent connection is lost. Check its connection and logs; a stopped service is not established.', 'ارتباط عامل قطع است؛ اتصال و لاگ عامل را بررسی کنید. متوقف‌بودن سرویس هنوز اثبات نشده است.');
 if (!isNodeOnline(node)) return localized('The agent is not sending fresh observations. Check its logs and retry.', 'عامل دادهٔ تازه نمی‌فرستد؛ لاگ آن را بررسی و دوباره تلاش کنید.');
 return localized('Fresh server observation; tunnel health is checked separately.', 'دادهٔ تازهٔ سرور دریافت شده؛ سلامت تونل جدا بررسی می‌شود.');
}

export function dateText(value?: string) {
 const at = sampleTime(value);
 if (!Number.isFinite(at)) return '—';
 const date = new Date(at);
 const locale = language === 'fa' ? 'fa-IR-u-ca-persian' : 'en-GB';
 return new Intl.DateTimeFormat(locale, {year:'numeric', month:'2-digit', day:'2-digit'}).format(date)
  + ' · ' + new Intl.DateTimeFormat(locale, {hour:'2-digit', minute:'2-digit', second:'2-digit', hourCycle:'h23'}).format(date);
}
function relativeTime(value: string, now: number) {
 const delta = (sampleTime(value) - now) / 1000;
 if (Math.abs(delta) < 45) return localized('Just now', 'همین حالا');
 const scale = Math.abs(delta) >= 86400 ? 86400 : Math.abs(delta) >= 3600 ? 3600 : 60;
 return new Intl.RelativeTimeFormat(language === 'fa' ? 'fa-IR' : 'en-GB', {numeric:'always'}).format(Math.round(delta / scale), scale === 86400 ? 'day' : scale === 3600 ? 'hour' : 'minute');
}
let clockValue = Date.now();
let clockTimer: number | undefined;
const clockSubscribers = new Set<() => void>();
function subscribeClock(listener: () => void) {
 clockSubscribers.add(listener);
 if (clockTimer === undefined) {
  clockValue = Date.now();
  clockTimer = window.setInterval(() => { clockValue = Date.now(); clockSubscribers.forEach(notify => notify()); }, 15000);
 }
 return () => { clockSubscribers.delete(listener); if (!clockSubscribers.size) { window.clearInterval(clockTimer); clockTimer = undefined; } };
}
const clockSnapshot = () => clockValue;
export const useObservationClock = () => useSyncExternalStore(subscribeClock, clockSnapshot);
export function Timestamp({at, absolute = false}: {at?: string; absolute?: boolean}) {
 const now = useObservationClock();
 if (!Number.isFinite(sampleTime(at))) return <span className="timestamp-missing">{localized('Not observed', 'مشاهده نشده')}</span>;
 return <time className="timestamp" dateTime={at} title={dateText(at)} dir="ltr">{absolute ? dateText(at) : relativeTime(at!, now)}</time>;
}

export function resourceLevel(value: unknown): 'unknown' | 'normal' | 'high' | 'critical' {
 if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return 'unknown';
 return value > 90 ? 'critical' : value >= 70 ? 'high' : 'normal';
}
export function ResourceValue({value, node, suffix = '%'}: {value?: number | null; node: ObservedNode; suffix?: string}) {
 const now = useObservationClock();
 const valid = resourceLevel(value) !== 'unknown';
 const current = isNodeOnline(node, now) && valid;
 const level = current ? resourceLevel(value) : 'unknown';
 const label = level === 'critical' ? localized('Critical', 'بحرانی') : level === 'high' ? localized('High', 'بالا') : level === 'normal' ? localized('Normal', 'عادی') : localized('Not current', 'وضعیت فعلی نامعلوم');
 return <div className={`resource-value resource-${level} ${current ? 'resource-current' : 'resource-historical'}`}>
  <span><bdi>{valid ? new Intl.NumberFormat(language === 'fa' ? 'fa-IR' : 'en-GB', {maximumFractionDigits:0}).format(value!) + suffix : '—'}</bdi> <span className="resource-label">{label}</span></span>
  {current && <progress max={100} value={Math.min(100, value!)} aria-label={label}/>}
  {!current && valid && <small>{localized('Last value', 'آخرین مقدار')} <Timestamp at={node.seen}/></small>}
 </div>;
}
