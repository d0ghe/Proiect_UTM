const dns   = require('dns').promises;
const geoip = require('geoip-lite');

const { getGeoFilterState } = require('../store/geoFilterStore');

// Cache DNS per hostname
const dnsCache = new Map();
const DNS_CACHE_TTL = 5 * 60 * 1000;

// Log atacuri blocate (in-memory, ultimele 200)
const attackLog = [];
const MAX_ATTACKS = 200;

// Coordonate centru tara [lon, lat]
const COUNTRY_COORDS = {
  AF:[67.7,33.9],AL:[20.2,41.2],DZ:[1.7,28.0],AO:[17.9,-11.2],AR:[-63.6,-38.4],
  AM:[45.0,40.1],AU:[133.8,-25.3],AT:[14.6,47.5],AZ:[47.6,40.1],BD:[90.4,23.7],
  BY:[28.0,53.7],BE:[4.5,50.5],BJ:[2.3,9.3],BA:[17.7,44.2],BR:[-51.9,-14.2],
  BG:[25.5,42.7],KH:[105.0,12.6],CM:[12.4,4.1],CA:[-96.8,56.1],CL:[-71.5,-35.7],
  CN:[104.2,35.9],CO:[-74.3,4.6],CG:[15.8,-0.2],CU:[-79.5,21.5],CZ:[15.5,49.8],
  DE:[10.5,51.2],DK:[10.0,56.3],DO:[-70.2,18.7],EG:[30.8,26.8],ET:[39.6,9.1],
  FI:[26.3,64.0],FR:[2.2,46.2],GE:[43.4,42.3],GH:[-1.0,7.9],GR:[22.0,39.1],
  GT:[-90.2,15.8],HN:[-86.6,15.2],HK:[114.2,22.4],HU:[19.5,47.2],IN:[78.7,20.6],
  ID:[113.9,-0.8],IR:[53.7,32.4],IQ:[43.7,33.2],IE:[-8.2,53.2],IL:[34.9,31.5],
  IT:[12.6,42.8],JP:[138.3,36.2],JO:[37.2,31.2],KZ:[67.0,48.0],KE:[37.9,0.0],
  KP:[127.5,40.3],KR:[127.8,36.6],XK:[20.9,42.6],KW:[47.5,29.3],LB:[35.9,33.9],
  LY:[17.2,26.3],LT:[23.9,55.2],MY:[109.7,2.6],MX:[-102.5,23.6],MA:[-7.1,31.8],
  MM:[95.9,21.9],NP:[84.1,28.4],NL:[5.3,52.3],NZ:[172.0,-40.9],NG:[8.7,9.1],
  NO:[8.5,60.5],PK:[69.3,30.4],PH:[122.9,12.9],PL:[19.1,51.9],PT:[-8.2,39.4],
  RO:[24.9,45.9],RU:[105.3,61.5],SA:[45.1,23.9],SN:[-14.5,14.5],RS:[21.0,44.0],
  SL:[-11.8,8.5],SO:[46.2,6.1],ZA:[22.9,-30.6],SD:[29.9,12.9],SY:[38.3,35.0],
  TW:[120.9,23.7],TZ:[34.9,-6.4],TH:[100.5,15.9],TN:[9.5,34.0],TR:[35.2,39.1],
  TM:[59.6,38.9],UA:[31.2,48.4],AE:[53.8,24.0],GB:[-3.4,55.4],US:[-95.7,37.1],
  UZ:[63.9,41.4],VE:[-66.6,6.4],VN:[108.3,14.1],YE:[48.5,15.6],ZM:[27.8,-13.1],
  ZW:[29.2,-19.0],
};

function addAttack(type, country, hostname, geo) {
  const coords = COUNTRY_COORDS[country];
  if (!coords) return;
  attackLog.push({ type, country, hostname, city: geo?.city || '', coords, timestamp: Date.now() });
  if (attackLog.length > MAX_ATTACKS) attackLog.shift();
}

function addContentBlock(hostname) {
  resolveIp(hostname).then((ip) => {
    const geo     = ip ? geoip.lookup(ip) : null;
    const country = geo?.country || 'XX';
    const coords  = COUNTRY_COORDS[country];
    if (!coords) return;
    attackLog.push({ type: 'content', country, hostname, city: geo?.city || '', coords, timestamp: Date.now() });
    if (attackLog.length > MAX_ATTACKS) attackLog.shift();
  }).catch(() => {});
}

function getRecentAttacks(limit = 50) {
  return attackLog.slice(-limit).reverse();
}

// Domenii cunoscute per tara care folosesc CDN global (IP-ul nu e clasificat corect)
const KNOWN_DOMAINS = {
  CN: [
    'baidu.com','qq.com','wechat.com','weixin.qq.com','weibo.com','sina.com','sina.com.cn',
    'taobao.com','tmall.com','jd.com','alibaba.com','aliexpress.com','aliyun.com','1688.com',
    'bilibili.com','youku.com','iqiyi.com','mgtv.com','sohu.com','163.com','126.com',
    'douyin.com','tiktok.com','kuaishou.com','tencent.com','qq.com','netease.com',
    'zhihu.com','douban.com','renren.com','xiaomi.com','huawei.com','oppo.com','vivo.com',
  ],
  RU: [
    'vk.com','mail.ru','yandex.com','yandex.ru','yandex.net','ok.ru','rambler.ru',
    'sberbank.ru','gazprom.ru','rt.com','ria.ru','tass.ru','interfax.ru',
  ],
  KP: ['kcna.kp','naenara.com.kp','rodong.rep.kp'],
  IR: ['aparat.com','digikala.com','irna.ir','tasnimnews.com','farsnews.ir'],
  BY: ['tut.by','onliner.by','belta.by'],
  CU: ['cubadebate.cu','granma.cu'],
};

// TLD-uri de tara
const TLD_MAP = { cn:'CN', ru:'RU', su:'RU', ir:'IR', kp:'KP', cu:'CU', by:'BY', sy:'SY' };

function countryFromKnownDomains(hostname) {
  const h = hostname.toLowerCase();
  for (const [country, domains] of Object.entries(KNOWN_DOMAINS)) {
    if (domains.some((d) => h === d || h.endsWith(`.${d}`))) return country;
  }
  return null;
}

function countryFromTld(hostname) {
  const tld = hostname.split('.').pop().toLowerCase();
  return TLD_MAP[tld] || null;
}

// Rezolva TOATE A record-urile (nu doar primul) + fallback la lookup
async function resolveAllIps(hostname) {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return [hostname];
  const cached = dnsCache.get(hostname);
  if (cached && Date.now() - cached.ts < DNS_CACHE_TTL) return cached.ips;
  try {
    const ips = await dns.resolve4(hostname);
    dnsCache.set(hostname, { ips, ts: Date.now() });
    return ips;
  } catch {
    try {
      const { address } = await dns.lookup(hostname, { family: 4 });
      dnsCache.set(hostname, { ips: [address], ts: Date.now() });
      return [address];
    } catch {
      return [];
    }
  }
}

async function getCountry(hostname) {
  const known = countryFromKnownDomains(hostname) || countryFromTld(hostname);
  if (known) return known;
  const ips = await resolveAllIps(hostname);
  for (const ip of ips) {
    const geo = geoip.lookup(ip);
    if (geo?.country) return geo.country;
  }
  return null;
}

async function isGeoBlocked(hostname) {
  const state = getGeoFilterState();
  if (!state.enabled || state.blockedCountries.length === 0) return { blocked: false };

  // Strat 1: domenii cunoscute (baidu.com, vk.com etc.)
  const knownCountry = countryFromKnownDomains(hostname);
  if (knownCountry && state.blockedCountries.includes(knownCountry)) {
    addAttack('geo', knownCountry, hostname, null);
    return { blocked: true, country: knownCountry };
  }

  // Strat 2: TLD-based (.cn, .ru etc.)
  const tldCountry = countryFromTld(hostname);
  if (tldCountry && state.blockedCountries.includes(tldCountry)) {
    addAttack('geo', tldCountry, hostname, null);
    return { blocked: true, country: tldCountry };
  }

  // Strat 3: Toate IP-urile DNS → geoip lookup
  const ips = await resolveAllIps(hostname);
  for (const ip of ips) {
    const geo = geoip.lookup(ip);
    if (!geo?.country) continue;
    if (state.blockedCountries.includes(geo.country)) {
      addAttack('geo', geo.country, hostname, geo);
      return { blocked: true, country: geo.country };
    }
  }

  return { blocked: false };
}

module.exports = { isGeoBlocked, getCountry, getRecentAttacks, addContentBlock };
