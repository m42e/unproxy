if (typeof String.prototype.substr !== 'function') {
  String.prototype.substr = __unproxySubstr;
}

function dnsDomainIs(host, domain) { return host.endsWith(domain); }
function dnsDomainLevels(host) { return (host.match(/\./g)||[]).length; }
function isPlainHostName(host) { return !host.includes('.'); }
function isResolvable(host) { return dnsResolve(host) !== null; }
function localHostOrDomainIs(host, hostdom) { return host===hostdom || hostdom.startsWith(host+'.'); }
function isValidIpAddress(s) { return __unproxyParseIPv4(s) !== null; }
function convert_addr(s) {
  if (!isValidIpAddress(s)) return 0;
  const value = __unproxyParseIPv4(s);
  // Retain the former coercion behavior when a PAC script overrides validation.
  if (value === null) { let n=0; for(const x of s.split('.')) n=(n<<8)|(+x); return n|0; }
  return value | 0;
}
const __originalIsValidIpAddress = isValidIpAddress;
const __originalConvertAddr = convert_addr;
const __originalParseIPv4 = __unproxyParseIPv4;
const __originalDnsResolve = dnsResolve;
function isInNet(host, pattern, mask) {
  if (typeof host === 'string' && dnsResolve === __originalDnsResolve && isValidIpAddress === __originalIsValidIpAddress && convert_addr === __originalConvertAddr && __unproxyParseIPv4 === __originalParseIPv4) {
    const network = __unproxyParseIPv4(pattern), subnet = __unproxyParseIPv4(mask);
    if (network === null || subnet === null) return false;
    let address = __unproxyParseIPv4(host);
    if (address === null) address = __unproxyParseIPv4(dnsResolve(host));
    return address !== null && ((address & subnet) === (network & subnet));
  }
  if (!isValidIpAddress(pattern)||!isValidIpAddress(mask)) return false;
  let ip=isValidIpAddress(host)?host:dnsResolve(host);
  return ip!==null && ip!==undefined && isValidIpAddress(ip) && ((convert_addr(ip)&convert_addr(mask))===(convert_addr(pattern)&convert_addr(mask)));
}
const _wd=['SUN','MON','TUE','WED','THU','FRI','SAT'], _mo=['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC'];
function weekdayRange(...a) { let g=a[a.length-1]==='GMT'; if(g)a.pop(); if(a.length<1||a.length>2||a.some(x=>!_wd.includes(x)))return false; let d=new Date(),v=g?d.getUTCDay():d.getDay(); let x=_wd.indexOf(a[0]),y=_wd.indexOf(a[a.length-1]); return a.length===1?v===x:(x<=y?v>=x&&v<=y:v===x||v===y); }
function dateRange(...a) {
  let g=a[a.length-1]==='GMT'; if(g)a.pop(); if(!a.length)return false;
  const n=new Date(), get=k=>n['get'+(g?'UTC':'')+k](), cy=get('FullYear'), cm=get('Month'), cd=get('Date');
  const typ=x=>typeof x==='number'?(x<32?'d':'y'):(typeof x==='string'&&_mo.includes(x)?'m':'?');
  const mk=(y,m,d,end=false)=>g?Date.UTC(y,m,d,end?23:0,end?59:0,end?59:0):new Date(y,m,d,end?23:0,end?59:0,end?59:0).getTime();
  const t=a.map(typ), month=x=>_mo.indexOf(x); if(t.some(x=>x==='?')||a.some(x=>typeof x==='number'&&(!Number.isInteger(x)||x<1||x>9999)))return false;
  let lo,hi;
  if(a.length===1){if(t[0]==='d')lo=mk(cy,cm,a[0]),hi=mk(cy,cm,a[0],true);else if(t[0]==='m')lo=mk(cy,month(a[0]),1),hi=mk(cy,month(a[0])+1,0,true);else lo=mk(a[0],0,1),hi=mk(a[0],11,31,true);}
  else if(a.length===2&&t.includes('d')&&t.includes('m')){return cd===a[t.indexOf('d')]&&cm===month(a[t.indexOf('m')]);}
  else if(a.length===3&&t.includes('d')&&t.includes('m')&&t.includes('y')){return cd===a[t.indexOf('d')]&&cm===month(a[t.indexOf('m')])&&cy===a[t.indexOf('y')];}
  else if(a.length===2&&t[0]===t[1]){if(t[0]==='d')lo=mk(cy,cm,a[0]),hi=mk(cy,cm,a[1],true);else if(t[0]==='m')lo=mk(cy,month(a[0]),1),hi=mk(cy,month(a[1])+1,0,true);else lo=mk(a[0],0,1),hi=mk(a[1],11,31,true);}
  else if(a.length===2&&t[0]==='m'&&t[1]==='y'){lo=mk(a[1],month(a[0]),1);hi=mk(a[1],11,31,true);}
  else if(a.length===4&&t.join('')==='dmdm'){lo=mk(cy,month(a[1]),a[0]);hi=mk(cy,month(a[3]),a[2],true);}
  else if(a.length===4&&t.join('')==='mymy'){lo=mk(a[1],month(a[0]),1);hi=mk(a[3],month(a[2])+1,0,true);}
  else if(a.length===6&&t.join('')==='dmydmy'){lo=mk(a[2],month(a[1]),a[0]);hi=mk(a[5],month(a[4]),a[3],true);}else return false;
  const now=mk(cy,cm,cd); return lo<=hi?now>=lo&&now<=hi:now>=lo||now<=hi;
}
function timeRange(...a) {let g=a[a.length-1]==='GMT';if(g)a.pop();if(a.length===0)return false;if(![1,2,4,6].includes(a.length))throw new Error('invalid timeRange arity');let d=new Date(),h=g?d.getUTCHours():d.getHours(),m=g?d.getUTCMinutes():d.getMinutes(),s=g?d.getUTCSeconds():d.getSeconds(),v=h*3600+m*60+s;let l,r;if(a.length===1)return h===a[0];if(a.length===2)return a[0]<=a[1]?(h>=a[0]&&h<=a[1]):(h===a[0]||h===a[1]);if(a.length===4)l=a[0]*3600+a[1]*60,r=a[2]*3600+a[3]*60+59;else l=a[0]*3600+a[1]*60+a[2],r=a[3]*3600+a[4]*60+a[5];return l<=r?v>=l&&v<=r:v>=l||v<=r;}
function DomainTable(domains) { if(!Array.isArray(domains)) throw new TypeError('DomainTable expects an array'); this._domains=domains.map(x=>{if(typeof x!=='string')throw new TypeError('domain must be a string');return x.replace(/^[\t\n\v\f\r .]+|[\t\n\v\f\r .]+$/g,'');}); }
DomainTable.prototype.contains=function(d){if(typeof d!=='string')throw new TypeError('domain must be a string');d=d.replace(/^[\t\n\v\f\r .]+|[\t\n\v\f\r .]+$/g,'');return this._domains.some(x=>d===x||d.endsWith('.'+x));};
var _dnsCache = new _DnsCache();
