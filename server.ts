import express, { Request, Response } from 'express';
import dns from 'node:dns';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { REMEDIATION_TEMPLATES } from './src/utils/remediationTemplates';
import { SqliAnalysisData } from './src/types/security';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const isProd = process.env.NODE_ENV === 'production';

app.use(express.json());

// Helper for timing out promises safely
function withTimeout<T>(promise: Promise<T>, ms: number, fallbackValue: T): Promise<T> {
  let timeoutId: NodeJS.Timeout;
  const timeoutPromise = new Promise<T>((resolve) => {
    timeoutId = setTimeout(() => resolve(fallbackValue), ms);
  });
  return Promise.race([promise, timeoutPromise]).then((res) => {
    clearTimeout(timeoutId);
    return res;
  });
}

// Shannon entropy calculation for domain heuristics
function calculateEntropy(str: string): number {
  const len = str.length;
  if (len === 0) return 0;
  const freq: Record<string, number> = {};
  for (let i = 0; i < len; i++) {
    const char = str[i];
    freq[char] = (freq[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in freq) {
    const p = freq[char] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

// DoH (DNS over HTTPS) fallback query function using Google DoH
async function queryDoH(name: string, type: string): Promise<any[]> {
  try {
    const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3500);
    const res = await fetch(url, { signal: controller.signal, headers: { Accept: 'application/dns-json' } });
    clearTimeout(timeout);
    if (!res.ok) return [];
    const data = await res.json();
    return data.Answer || [];
  } catch {
    return [];
  }
}

// Sample test targets
const SAMPLE_DOMAINS = [
  { hostname: 'github.com', category: 'Dev Platform', expectedGrade: 'A' },
  { hostname: 'cloudflare.com', category: 'Security / Edge CDN', expectedGrade: 'A+' },
  { hostname: 'google.com', category: 'Tech Giant', expectedGrade: 'A+' },
  { hostname: 'wikipedia.org', category: 'Encyclopedia', expectedGrade: 'A' },
  { hostname: 'httpbin.org', category: 'HTTP Testbed', expectedGrade: 'B' },
  { hostname: 'expired.badssl.com', category: 'BadSSL (Expired)', expectedGrade: 'F' },
];

app.get('/api/sample-domains', (_req: Request, res: Response) => {
  res.json({ samples: SAMPLE_DOMAINS });
});

// Main Analysis Endpoint
app.post('/api/analyze', async (req: Request, res: Response) => {
  const startTime = Date.now();
  let rawUrl = (req.body.url || '').trim();

  if (!rawUrl) {
    return res.status(400).json({ error: 'URL is required' });
  }

  // Normalize protocol
  let targetUrl = rawUrl;
  if (!/^https?:\/\//i.test(targetUrl)) {
    targetUrl = 'https://' + targetUrl;
  }

  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch (err) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  const hostname = parsed.hostname.toLowerCase();
  const isIp = net.isIP(hostname) !== 0;

  // 1. Heuristic Analysis
  const entropy = calculateEntropy(hostname);
  const isPunycode = hostname.startsWith('xn--') || hostname.includes('.xn--');
  const subdomainParts = hostname.split('.');
  const subdomainDepth = subdomainParts.length > 2 ? subdomainParts.length - 2 : 0;
  const tld = subdomainParts.length > 1 ? subdomainParts[subdomainParts.length - 1] : '';

  const suspiciousTerms = [
    'login', 'signin', 'verify', 'account', 'banking', 'secure', 'wallet', 'update',
    'support', 'appleid', 'paypal', 'microsoft', 'recover', 'token', 'auth'
  ];
  const suspiciousKeywordsFound = suspiciousTerms.filter(
    (term) => hostname.includes(term) && !hostname.endsWith(`${term}.com`) && !hostname.endsWith(`${term}.org`)
  );

  const highRiskTlds = ['top', 'xyz', 'work', 'click', 'link', 'gq', 'cf', 'ml', 'tk', 'zip', 'mov'];
  const tldRiskLevel = highRiskTlds.includes(tld) ? 'high' : ['net', 'info', 'biz', 'io'].includes(tld) ? 'medium' : 'low';

  let riskAssessment: 'Clean' | 'Low Risk' | 'Suspicious' | 'High Risk' = 'Clean';
  if (isPunycode || suspiciousKeywordsFound.length >= 2 || (isIp && !['127.0.0.1', 'localhost'].includes(hostname))) {
    riskAssessment = 'High Risk';
  } else if (suspiciousKeywordsFound.length === 1 || tldRiskLevel === 'high' || entropy > 4.2) {
    riskAssessment = 'Suspicious';
  } else if (tldRiskLevel === 'medium' || subdomainDepth >= 3) {
    riskAssessment = 'Low Risk';
  }

  const heuristicsData = {
    hostname,
    entropy,
    isPunycode,
    punycodeDecoded: isPunycode ? decodeURI(hostname) : undefined,
    subdomainDepth,
    isIpHostname: isIp,
    suspiciousKeywordsFound,
    tld,
    tldRiskLevel: tldRiskLevel as 'low' | 'medium' | 'high',
    urlLength: targetUrl.length,
    hasBasicAuthInUrl: parsed.username !== '' || parsed.password !== '',
    riskAssessment,
  };

  // 2. DNS Records Resolution
  const dnsPromises = dns.promises;
  let aRecords: string[] = [];
  let aaaaRecords: string[] = [];
  let mxRecords: Array<{ exchange: string; priority: number }> = [];
  let txtRecords: string[] = [];
  let nsRecords: string[] = [];
  let cnameRecords: string[] = [];
  let caaRecords: Array<{ critical: number; tag: string; value: string }> = [];
  let dmarcRecord: string | undefined = undefined;

  // Run native DNS queries with timeouts
  try {
    const [a, aaaa, mx, txt, ns, cname, caa, dmarcTxt] = await Promise.all([
      withTimeout(dnsPromises.resolve4(hostname).catch(() => []), 3000, []),
      withTimeout(dnsPromises.resolve6(hostname).catch(() => []), 3000, []),
      withTimeout(dnsPromises.resolveMx(hostname).catch(() => []), 3000, []),
      withTimeout(dnsPromises.resolveTxt(hostname).catch(() => []), 3000, []),
      withTimeout(dnsPromises.resolveNs(hostname).catch(() => []), 3000, []),
      withTimeout(dnsPromises.resolveCname(hostname).catch(() => []), 3000, []),
      withTimeout(dnsPromises.resolveCaa(hostname).catch(() => []), 3000, []),
      withTimeout(dnsPromises.resolveTxt(`_dmarc.${hostname}`).catch(() => []), 3000, []),
    ]);

    aRecords = a;
    aaaaRecords = aaaa;
    mxRecords = mx;
    txtRecords = txt.map((t) => t.join(' '));
    nsRecords = ns;
    cnameRecords = cname;
    caaRecords = caa.map((c) => ({
      critical: c.critical,
      tag: (c as any).issue ? 'issue' : (c as any).issuewild ? 'issuewild' : (c as any).iodef ? 'iodef' : 'unknown',
      value: (c as any).issue || (c as any).issuewild || (c as any).iodef || JSON.stringify(c),
    }));
    if (dmarcTxt && dmarcTxt.length > 0) {
      dmarcRecord = dmarcTxt.map((t) => t.join(' ')).find((t) => t.startsWith('v=DMARC1'));
    }
  } catch (err) {
    // If native DNS fails, fallback to DoH (DNS over HTTPS)
  }

  // DoH Fallback if A records empty
  if (aRecords.length === 0 && !isIp) {
    try {
      const dohA = await queryDoH(hostname, 'A');
      aRecords = dohA.filter((x: any) => x.type === 1).map((x: any) => x.data);
      const dohMx = await queryDoH(hostname, 'MX');
      mxRecords = dohMx.filter((x: any) => x.type === 15).map((x: any) => {
        const parts = (x.data || '').split(' ');
        return { priority: parseInt(parts[0], 10) || 10, exchange: parts[1] || parts[0] };
      });
      const dohTxt = await queryDoH(hostname, 'TXT');
      txtRecords = dohTxt.filter((x: any) => x.type === 16).map((x: any) => (x.data || '').replace(/^"|"$/g, ''));
      const dohNs = await queryDoH(hostname, 'NS');
      nsRecords = dohNs.filter((x: any) => x.type === 2).map((x: any) => x.data);
      const dohCaa = await queryDoH(hostname, 'CAA');
      caaRecords = dohCaa.map((c: any) => ({ critical: 0, tag: 'issue', value: c.data }));
      const dohDmarc = await queryDoH(`_dmarc.${hostname}`, 'TXT');
      const dmarcHit = dohDmarc.find((x: any) => (x.data || '').includes('v=DMARC1'));
      if (dmarcHit) dmarcRecord = dmarcHit.data.replace(/^"|"$/g, '');
    } catch {
      // ignore
    }
  }

  // 3. Email Security (SPF & DMARC)
  const spfRecord = txtRecords.find((t) => t.startsWith('v=spf1'));
  let spfAllMechanism: '-all' | '~all' | '?all' | '+all' | 'none' = 'none';
  let spfStatus: 'hardfail_safe' | 'softfail_moderate' | 'neutral_weak' | 'allow_dangerous' | 'missing' = 'missing';

  if (spfRecord) {
    if (spfRecord.includes('-all')) {
      spfAllMechanism = '-all';
      spfStatus = 'hardfail_safe';
    } else if (spfRecord.includes('~all')) {
      spfAllMechanism = '~all';
      spfStatus = 'softfail_moderate';
    } else if (spfRecord.includes('?all')) {
      spfAllMechanism = '?all';
      spfStatus = 'neutral_weak';
    } else if (spfRecord.includes('+all')) {
      spfAllMechanism = '+all';
      spfStatus = 'allow_dangerous';
    }
  }

  let dmarcPolicy: 'reject' | 'quarantine' | 'none' | 'missing' = 'missing';
  let dmarcStatus: 'enforced' | 'monitoring_only' | 'none' | 'missing' = 'missing';
  let dmarcPercentage: number | undefined = undefined;
  let dmarcReportEmail: string | undefined = undefined;

  if (dmarcRecord) {
    const policyMatch = dmarcRecord.match(/p=(reject|quarantine|none)/i);
    if (policyMatch) {
      dmarcPolicy = policyMatch[1].toLowerCase() as 'reject' | 'quarantine' | 'none';
      dmarcStatus = dmarcPolicy === 'reject' || dmarcPolicy === 'quarantine' ? 'enforced' : 'monitoring_only';
    }
    const pctMatch = dmarcRecord.match(/pct=(\d+)/i);
    if (pctMatch) dmarcPercentage = parseInt(pctMatch[1], 10);
    const ruaMatch = dmarcRecord.match(/rua=mailto:([^\s;]+)/i);
    if (ruaMatch) dmarcReportEmail = ruaMatch[1];
  }

  let spoofingResistance: 'High' | 'Moderate' | 'Vulnerable' | 'Severe' = 'Severe';
  if (dmarcPolicy === 'reject' && (spfStatus === 'hardfail_safe' || spfStatus === 'softfail_moderate')) {
    spoofingResistance = 'High';
  } else if ((dmarcPolicy === 'quarantine' || dmarcPolicy === 'reject') || (spfStatus === 'hardfail_safe')) {
    spoofingResistance = 'Moderate';
  } else if (spfRecord || dmarcRecord) {
    spoofingResistance = 'Vulnerable';
  }

  const emailSecurity = {
    hasSpf: !!spfRecord,
    spfRecord,
    spfAllMechanism,
    spfStatus,
    hasDmarc: !!dmarcRecord,
    dmarcRecord,
    dmarcPolicy,
    dmarcPercentage,
    dmarcReportEmail,
    dmarcStatus,
    spoofingResistance,
  };

  // 4. TLS / SSL Certificate Handshake Inspection
  let sslInfo: any = {
    subject: {},
    issuer: {},
    validFrom: '',
    validTo: '',
    daysRemaining: 0,
    isExpired: false,
    isExpiringSoon: false,
    isSelfSigned: false,
    subjectAltNames: [],
    protocolVersion: 'Unknown',
    cipherSuite: 'Unknown',
    authorized: false,
    status: 'not_found',
  };

  await new Promise<void>((resolve) => {
    const targetHost = hostname;
    const socket = tls.connect(
      {
        host: targetHost,
        port: 443,
        servername: targetHost,
        rejectUnauthorized: false,
        timeout: 4000,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          const cipher = socket.getCipher();
          const protocol = socket.getProtocol();
          const authorized = socket.authorized;
          const authError = socket.authorizationError ? String(socket.authorizationError) : undefined;

          if (cert && cert.valid_to) {
            const validTo = new Date(cert.valid_to);
            const validFrom = new Date(cert.valid_from);
            const now = new Date();
            const daysRemaining = Math.round((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
            const isExpired = daysRemaining <= 0;
            const isExpiringSoon = daysRemaining > 0 && daysRemaining <= 30;

            const sans = cert.subjectaltname
              ? cert.subjectaltname.split(', ').map((s: string) => s.replace(/^DNS:/, ''))
              : [];

            const isSelfSigned =
              cert.issuer &&
              cert.subject &&
              cert.issuer.CN === cert.subject.CN &&
              !authorized;

            let status: 'valid' | 'expiring' | 'expired' | 'untrusted' | 'not_found' = 'valid';
            if (isExpired) status = 'expired';
            else if (!authorized && isSelfSigned) status = 'untrusted';
            else if (isExpiringSoon) status = 'expiring';
            else if (!authorized) status = 'untrusted';

            sslInfo = {
              subject: {
                commonName: cert.subject?.CN,
                organization: cert.subject?.O,
                country: cert.subject?.C,
              },
              issuer: {
                commonName: cert.issuer?.CN,
                organization: cert.issuer?.O,
                country: cert.issuer?.C,
              },
              validFrom: validFrom.toISOString(),
              validTo: validTo.toISOString(),
              daysRemaining,
              isExpired,
              isExpiringSoon,
              isSelfSigned,
              subjectAltNames: sans,
              protocolVersion: protocol || 'TLSv1.3',
              cipherSuite: cipher ? `${cipher.name} (${cipher.standardName || cipher.version})` : 'Unknown',
              serialNumber: cert.serialNumber,
              fingerprint256: cert.fingerprint256,
              authorized,
              authorizationError: authError,
              status,
            };
          }
        } catch {
          // ignore error inside connect
        } finally {
          socket.destroy();
          resolve();
        }
      }
    );

    socket.on('error', () => {
      socket.destroy();
      resolve();
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve();
    });
  });

  // 5. HTTP Response & Redirect Chain & Security Headers & Cookies
  const hops: Array<{ statusCode: number; url: string; location?: string; protocol: 'http:' | 'https:' }> = [];
  let currentUrl = targetUrl;
  let finalHeaders: Record<string, string | string[]> = {};
  let setCookiesList: string[] = [];
  let finalResponseBody = '';

  // Follow up to 5 redirects
  for (let hop = 0; hop < 5; hop++) {
    try {
      const parsedHop = new URL(currentUrl);
      const isHttps = parsedHop.protocol === 'https:';
      const client = isHttps ? https : http;

      const hopResult = await new Promise<{
        statusCode: number;
        headers: http.IncomingHttpHeaders;
        bodySnippet: string;
      }>((resolve, reject) => {
        const req = client.request(
          currentUrl,
          {
            method: 'GET',
            timeout: 5000,
            headers: {
              'User-Agent':
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 CyberScan-Auditor/1.0',
              Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
              'Accept-Language': 'en-US,en;q=0.9',
            },
            rejectUnauthorized: false,
          },
          (res) => {
            let body = '';
            res.setEncoding('utf8');
            res.on('data', (chunk) => {
              if (body.length < 65536) {
                body += chunk;
              }
            });
            res.on('end', () => {
              resolve({
                statusCode: res.statusCode || 200,
                headers: res.headers,
                bodySnippet: body.slice(0, 65536),
              });
            });
            res.on('error', () => {
              resolve({
                statusCode: res.statusCode || 200,
                headers: res.headers,
                bodySnippet: body,
              });
            });
          }
        );

        req.on('error', reject);
        req.on('timeout', () => {
          req.destroy();
          reject(new Error('Hop timeout'));
        });
        req.end();
      });

      hops.push({
        statusCode: hopResult.statusCode,
        url: currentUrl,
        location: (hopResult.headers.location as string) || undefined,
        protocol: isHttps ? 'https:' : 'http:',
      });

      if (hopResult.headers['set-cookie']) {
        const sc = hopResult.headers['set-cookie'];
        if (Array.isArray(sc)) {
          setCookiesList.push(...sc);
        } else {
          setCookiesList.push(sc);
        }
      }

      finalHeaders = hopResult.headers as Record<string, string | string[]>;
      finalResponseBody = hopResult.bodySnippet || '';

      if (
        [301, 302, 303, 307, 308].includes(hopResult.statusCode) &&
        hopResult.headers.location
      ) {
        let nextUrl = hopResult.headers.location;
        if (nextUrl.startsWith('/')) {
          nextUrl = `${parsedHop.protocol}//${parsedHop.host}${nextUrl}`;
        }
        currentUrl = nextUrl;
      } else {
        break;
      }
    } catch {
      break;
    }
  }

  // Check HTTP -> HTTPS redirect behavior
  let enforcesHttps = targetUrl.startsWith('https://');
  if (hops.length > 0) {
    const firstHop = hops[0];
    const lastHop = hops[hops.length - 1];
    enforcesHttps = lastHop.protocol === 'https:';
  }

  const hasDowngrade = hops.some(
    (h, idx) => idx > 0 && h.protocol === 'http:' && hops[idx - 1].protocol === 'https:'
  );

  const redirectData = {
    initialUrl: targetUrl,
    finalUrl: currentUrl,
    totalHops: hops.length,
    hops,
    enforcesHttps,
    hasDowngrade,
    excessiveHops: hops.length >= 4,
    status: hasDowngrade ? ('critical' as const) : !enforcesHttps ? ('warning' as const) : ('secure' as const),
  };

  // 6. Security Headers Audit
  const getHeader = (name: string): string | undefined => {
    const lower = name.toLowerCase();
    const val = finalHeaders[lower];
    if (Array.isArray(val)) return val.join(', ');
    return val;
  };

  const hsts = getHeader('strict-transport-security');
  const csp = getHeader('content-security-policy');
  const xfo = getHeader('x-frame-options');
  const xcto = getHeader('x-content-type-options');
  const rp = getHeader('referrer-policy');
  const pp = getHeader('permissions-policy') || getHeader('feature-policy');
  const coop = getHeader('cross-origin-opener-policy');
  const coep = getHeader('cross-origin-embedder-policy');
  const server = getHeader('server');
  const poweredBy = getHeader('x-powered-by');

  const headersList = [
    {
      name: 'Strict-Transport-Security (HSTS)',
      present: !!hsts,
      value: hsts,
      status: !hsts
        ? ('missing' as const)
        : hsts.includes('preload') && hsts.includes('includeSubDomains')
        ? ('optimal' as const)
        : ('warning' as const),
      importance: 'critical' as const,
      description: 'Enforces HTTPS encryption and prevents SSL-stripping man-in-the-middle attacks.',
      recommendation: 'Set max-age >= 31536000 (1 year) with includeSubDomains and preload flags.',
    },
    {
      name: 'Content-Security-Policy (CSP)',
      present: !!csp,
      value: csp,
      status: !csp
        ? ('missing' as const)
        : csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'")
        ? ('warning' as const)
        : ('optimal' as const),
      importance: 'critical' as const,
      description: 'Mitigates Cross-Site Scripting (XSS), data injection, and malicious script execution.',
      recommendation: "Define restrictive default-src, script-src, object-src 'none', and frame-ancestors.",
    },
    {
      name: 'X-Frame-Options',
      present: !!xfo,
      value: xfo,
      status: !xfo
        ? ('missing' as const)
        : ['deny', 'sameorigin'].includes(xfo.toLowerCase().trim())
        ? ('optimal' as const)
        : ('warning' as const),
      importance: 'high' as const,
      description: 'Defends users from clickjacking attacks by forbidding iframe embedding.',
      recommendation: 'Set to DENY or SAMEORIGIN (or enforce via CSP frame-ancestors).',
    },
    {
      name: 'X-Content-Type-Options',
      present: !!xcto,
      value: xcto,
      status: xcto?.toLowerCase().trim() === 'nosniff' ? ('optimal' as const) : ('missing' as const),
      importance: 'high' as const,
      description: 'Prevents MIME-type confusion attacks by forcing browsers to respect declared Content-Type.',
      recommendation: 'Set to "nosniff".',
    },
    {
      name: 'Referrer-Policy',
      present: !!rp,
      value: rp,
      status: !rp
        ? ('missing' as const)
        : ['strict-origin-when-cross-origin', 'no-referrer', 'same-origin', 'strict-origin'].includes(
            rp.toLowerCase().trim()
          )
        ? ('optimal' as const)
        : ('warning' as const),
      importance: 'medium' as const,
      description: 'Protects user privacy by controlling URL information sent in the HTTP Referer header.',
      recommendation: 'Set to "strict-origin-when-cross-origin" or "no-referrer".',
    },
    {
      name: 'Permissions-Policy',
      present: !!pp,
      value: pp,
      status: pp ? ('optimal' as const) : ('missing' as const),
      importance: 'medium' as const,
      description: 'Restricts powerful browser capabilities like geolocation, camera, microphone, and payment APIs.',
      recommendation: 'Explicitly disable unused hardware APIs (e.g. camera=(), microphone=(), geolocation=()).',
    },
    {
      name: 'Cross-Origin-Opener-Policy (COOP)',
      present: !!coop,
      value: coop,
      status: coop ? ('optimal' as const) : ('missing' as const),
      importance: 'low' as const,
      description: 'Isolates top-level browsing context to protect against Spectre-style side-channel attacks.',
      recommendation: 'Set to "same-origin" for complete window cross-origin isolation.',
    },
    {
      name: 'Cross-Origin-Embedder-Policy (COEP)',
      present: !!coep,
      value: coep,
      status: coep ? ('optimal' as const) : ('missing' as const),
      importance: 'low' as const,
      description: 'Prevents loading cross-origin resources that do not grant explicit permission.',
      recommendation: 'Set to "require-corp" when high security isolation is required.',
    },
    {
      name: 'Server Header Disclosure',
      present: !!server,
      value: server,
      status: !server
        ? ('optimal' as const)
        : /\d+\.\d+/.test(server)
        ? ('insecure' as const)
        : ('warning' as const),
      importance: 'medium' as const,
      description: 'Reveals underlying web server software and precise version numbers to attackers.',
      recommendation: 'Suppress server banner tokens in web server config (e.g., server_tokens off).',
    },
  ];

  // 7. Cookies Audit
  const parsedCookies = setCookiesList.map((rawCookie) => {
    const parts = rawCookie.split(';').map((s) => s.trim());
    const [nameVal, ...attrs] = parts;
    const eqIdx = nameVal.indexOf('=');
    const name = eqIdx > -1 ? nameVal.slice(0, eqIdx) : nameVal;
    const value = eqIdx > -1 ? nameVal.slice(eqIdx + 1) : '';

    let secure = false;
    let httpOnly = false;
    let sameSite: 'Strict' | 'Lax' | 'None' | 'Unset' = 'Unset';
    let domain: string | undefined = undefined;
    let pathAttr: string | undefined = undefined;
    let expires: string | undefined = undefined;
    let maxAge: number | undefined = undefined;

    attrs.forEach((attr) => {
      const lower = attr.toLowerCase();
      if (lower === 'secure') secure = true;
      else if (lower === 'httponly') httpOnly = true;
      else if (lower.startsWith('samesite=')) {
        const ss = attr.split('=')[1]?.trim().toLowerCase();
        if (ss === 'strict') sameSite = 'Strict';
        else if (ss === 'lax') sameSite = 'Lax';
        else if (ss === 'none') sameSite = 'None';
      } else if (lower.startsWith('domain=')) {
        domain = attr.split('=')[1]?.trim();
      } else if (lower.startsWith('path=')) {
        pathAttr = attr.split('=')[1]?.trim();
      } else if (lower.startsWith('expires=')) {
        expires = attr.split('=')[1]?.trim();
      } else if (lower.startsWith('max-age=')) {
        maxAge = parseInt(attr.split('=')[1]?.trim(), 10);
      }
    });

    const prefix = name.startsWith('__Host-')
      ? ('host' as const)
      : name.startsWith('__Secure-')
      ? ('secure' as const)
      : ('none' as const);

    const warnings: string[] = [];
    let riskScore = 0;

    if (!secure) {
      warnings.push('Missing "Secure" flag (cookie transmitted unencrypted over HTTP)');
      riskScore += 35;
    }
    if (!httpOnly) {
      warnings.push('Missing "HttpOnly" flag (accessible to JavaScript / XSS theft)');
      riskScore += 35;
    }
    if (sameSite === 'Unset' || sameSite === 'None') {
      warnings.push(`SameSite is ${sameSite} (vulnerable to Cross-Site Request Forgery / CSRF)`);
      riskScore += 25;
    }

    return {
      name,
      valueSnippet: value.length > 8 ? `${value.substring(0, 6)}...` : value,
      domain,
      path: pathAttr,
      expires,
      maxAge,
      secure,
      httpOnly,
      sameSite,
      prefix,
      riskScore: Math.min(100, riskScore),
      warnings,
    };
  });

  // 8. Probe security.txt & robots.txt
  let hasSecurityTxt = false;
  let securityTxtUrl: string | undefined = undefined;
  let securityTxtContent: string | undefined = undefined;

  let hasRobotsTxt = false;
  let robotsDisallowedPaths: string[] = [];

  try {
    const secRes = await withTimeout(
      fetch(`https://${hostname}/.well-known/security.txt`, {
        headers: { 'User-Agent': 'CyberScan-Auditor/1.0' },
      }).catch(() => null),
      2500,
      null
    );
    if (secRes && secRes.ok) {
      const text = await secRes.text();
      if (text.includes('Contact:')) {
        hasSecurityTxt = true;
        securityTxtUrl = `https://${hostname}/.well-known/security.txt`;
        securityTxtContent = text.slice(0, 500);
      }
    }
  } catch {
    // ignore
  }

  try {
    const robRes = await withTimeout(
      fetch(`https://${hostname}/robots.txt`, {
        headers: { 'User-Agent': 'CyberScan-Auditor/1.0' },
      }).catch(() => null),
      2500,
      null
    );
    if (robRes && robRes.ok) {
      const text = await robRes.text();
      hasRobotsTxt = true;
      const lines = text.split('\n');
      robotsDisallowedPaths = lines
        .filter((l) => l.toLowerCase().startsWith('disallow:'))
        .map((l) => l.split(':')[1]?.trim())
        .filter((p): p is string => Boolean(p && p.length > 1 && !p.startsWith('/_')))
        .slice(0, 10);
    }
  } catch {
    // ignore
  }

  // 9. IP Reverse DNS & Geo / ASN data
  let ipAddress = aRecords[0] || (isIp ? hostname : undefined);
  let reverseDns: string | undefined = undefined;
  let asn: string | undefined = undefined;
  let asnOrg: string | undefined = undefined;
  let country: string | undefined = undefined;
  let countryCode: string | undefined = undefined;
  let city: string | undefined = undefined;

  if (ipAddress) {
    try {
      const ptr = await withTimeout(dnsPromises.reverse(ipAddress).catch(() => []), 2000, []);
      if (ptr && ptr.length > 0) reverseDns = ptr[0];
    } catch {
      // ignore
    }

    try {
      const geoRes = await withTimeout(
        fetch(`https://ipapi.co/${ipAddress}/json/`).catch(() => null),
        2500,
        null
      );
      if (geoRes && geoRes.ok) {
        const geoData = await geoRes.json();
        asn = geoData.asn;
        asnOrg = geoData.org;
        country = geoData.country_name;
        countryCode = geoData.country_code;
        city = geoData.city;
      }
    } catch {
      // ignore
    }
  }

  const infrastructureData = {
    ipAddress,
    reverseDns,
    asn,
    asnOrg,
    country,
    countryCode,
    city,
    serverBanner: server,
    poweredByHeader: poweredBy,
    httpVersion: 'HTTP/2',
    hasSecurityTxt,
    securityTxtUrl,
    securityTxtContent,
    hasRobotsTxt,
    robotsDisallowedPaths,
  };

  // 10. Compute Category Scores and Findings
  const findings: any[] = [];

  // SSL Scoring (Weight: 25%)
  let sslScore = 0;
  if (sslInfo.status === 'valid') {
    sslScore = 100;
    if (sslInfo.isExpiringSoon) {
      sslScore -= 20;
      findings.push({
        id: 'ssl-expiring-soon',
        category: 'ssl',
        title: `SSL Certificate Expiring Soon (${sslInfo.daysRemaining} days)`,
        severity: 'medium',
        description: `The SSL/TLS certificate for ${hostname} expires on ${new Date(sslInfo.validTo).toLocaleDateString()}. Renewal is recommended within 30 days.`,
        impact: 'Service outage and browser warning alerts if the certificate lapses.',
        remediation: 'Renew your certificate via your CA or automated ACME / Let’s Encrypt client.',
        owasp: 'A02:2021-Cryptographic Failures',
      });
    } else {
      findings.push({
        id: 'ssl-valid',
        category: 'ssl',
        title: `Valid TLS Certificate (${sslInfo.daysRemaining} days remaining)`,
        severity: 'passed',
        description: `Certificate issued by ${sslInfo.issuer.organization || sslInfo.issuer.commonName || 'Trusted CA'}. Protocol: ${sslInfo.protocolVersion}.`,
        impact: 'Data in transit is strongly encrypted with authenticated identity.',
        remediation: 'Maintain automated certificate renewal.',
      });
    }
  } else if (sslInfo.status === 'expired') {
    sslScore = 10;
    findings.push({
      id: 'ssl-expired',
      category: 'ssl',
      title: 'SSL Certificate Expired',
      severity: 'critical',
      description: `The certificate expired on ${new Date(sslInfo.validTo).toLocaleDateString()}.`,
      impact: 'Browsers show full-screen security warnings blocking visitors.',
      remediation: 'Immediately re-issue and deploy a new valid certificate.',
      owasp: 'A02:2021-Cryptographic Failures',
    });
  } else if (sslInfo.status === 'untrusted') {
    sslScore = 20;
    findings.push({
      id: 'ssl-untrusted',
      category: 'ssl',
      title: 'Untrusted or Self-Signed Certificate',
      severity: 'critical',
      description: 'The certificate chain cannot be verified against trusted root certificate authorities.',
      impact: 'Vulnerable to active man-in-the-middle decryption.',
      remediation: 'Deploy an SSL certificate from an established WebTrust CA or Let’s Encrypt.',
      owasp: 'A02:2021-Cryptographic Failures',
    });
  } else {
    sslScore = 0;
    findings.push({
      id: 'ssl-missing',
      category: 'ssl',
      title: 'No SSL / HTTPS Connection Detected',
      severity: 'critical',
      description: `Could not establish a secure TLS handshake with ${hostname} on port 443.`,
      impact: 'Traffic is completely unencrypted and susceptible to interception and injection.',
      remediation: 'Install a TLS certificate and bind port 443 with HTTPS support.',
      owasp: 'A02:2021-Cryptographic Failures',
    });
  }

  // Security Headers Scoring (Weight: 25%)
  let headersScore = 100;

  // HSTS check
  if (!hsts) {
    headersScore -= 25;
    findings.push({
      id: 'hdr-hsts-missing',
      category: 'headers',
      title: 'Missing HTTP Strict Transport Security (HSTS)',
      severity: 'high',
      description: 'The Strict-Transport-Security header is not present on the response.',
      impact: 'Users making initial HTTP requests can be intercepted via SSL-stripping MITM attacks.',
      remediation: 'Add Strict-Transport-Security with max-age >= 31536000 and includeSubDomains.',
      codeSnippet: REMEDIATION_TEMPLATES.hsts,
      owasp: 'A05:2021-Security Misconfiguration',
      cwe: 'CWE-319',
    });
  } else if (!hsts.includes('includeSubDomains')) {
    headersScore -= 5;
    findings.push({
      id: 'hdr-hsts-nosub',
      category: 'headers',
      title: 'HSTS Missing includeSubDomains Directive',
      severity: 'low',
      description: 'HSTS is active for the apex domain but does not enforce HTTPS across subdomains.',
      impact: 'Subdomains remain susceptible to SSL downgrade attacks.',
      remediation: 'Append includeSubDomains to your Strict-Transport-Security header.',
      codeSnippet: REMEDIATION_TEMPLATES.hsts,
    });
  } else {
    findings.push({
      id: 'hdr-hsts-passed',
      category: 'headers',
      title: 'Strict-Transport-Security (HSTS) Enforced',
      severity: 'passed',
      description: `HSTS is active (${hsts.slice(0, 40)}...).`,
      impact: 'Enforces HTTPS encryption directly at the browser layer.',
      remediation: 'No action required.',
    });
  }

  // CSP check
  if (!csp) {
    headersScore -= 30;
    findings.push({
      id: 'hdr-csp-missing',
      category: 'headers',
      title: 'Missing Content-Security-Policy (CSP)',
      severity: 'high',
      description: 'No Content-Security-Policy response header was detected.',
      impact: 'Significantly increases vulnerability to Cross-Site Scripting (XSS) and code injection.',
      remediation: 'Deploy a tailored Content-Security-Policy defining explicit source origins.',
      codeSnippet: REMEDIATION_TEMPLATES.csp,
      owasp: 'A03:2021-Injection',
      cwe: 'CWE-79',
    });
  } else if (csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'")) {
    headersScore -= 10;
    findings.push({
      id: 'hdr-csp-unsafe',
      category: 'headers',
      title: 'CSP Contains Unsafe Directives',
      severity: 'medium',
      description: "Content-Security-Policy contains 'unsafe-inline' or 'unsafe-eval'.",
      impact: 'Allows execution of inline scripts and dynamic code evaluation, weakening XSS defense.',
      remediation: 'Migrate to cryptographic nonces or SHA-256 hashes for inline script elements.',
      codeSnippet: REMEDIATION_TEMPLATES.csp,
    });
  } else {
    findings.push({
      id: 'hdr-csp-passed',
      category: 'headers',
      title: 'Content-Security-Policy Configured',
      severity: 'passed',
      description: 'Content-Security-Policy is defined without critical unsafe wildcards.',
      impact: 'Limits unauthorized external script injection.',
      remediation: 'No action required.',
    });
  }

  // X-Frame-Options
  if (!xfo && (!csp || !csp.includes('frame-ancestors'))) {
    headersScore -= 15;
    findings.push({
      id: 'hdr-xfo-missing',
      category: 'headers',
      title: 'Missing X-Frame-Options (Clickjacking Risk)',
      severity: 'medium',
      description: 'Neither X-Frame-Options nor CSP frame-ancestors is configured.',
      impact: 'The web application can be framed in hidden iframes to deceive users into unauthorized actions.',
      remediation: 'Set X-Frame-Options: DENY or SAMEORIGIN.',
      codeSnippet: REMEDIATION_TEMPLATES.xFrameOptions,
      owasp: 'A05:2021-Security Misconfiguration',
      cwe: 'CWE-1021',
    });
  } else {
    findings.push({
      id: 'hdr-xfo-passed',
      category: 'headers',
      title: 'Frame Protection Configured',
      severity: 'passed',
      description: xfo ? `X-Frame-Options set to ${xfo}.` : 'Protected via CSP frame-ancestors.',
      impact: 'Prevents UI redressing and clickjacking.',
      remediation: 'No action required.',
    });
  }

  // X-Content-Type-Options
  if (xcto?.toLowerCase().trim() !== 'nosniff') {
    headersScore -= 10;
    findings.push({
      id: 'hdr-xcto-missing',
      category: 'headers',
      title: 'Missing X-Content-Type-Options Header',
      severity: 'low',
      description: 'X-Content-Type-Options is not set to "nosniff".',
      impact: 'Browsers may attempt MIME sniffing on user-uploaded files, executing malicious payloads.',
      remediation: 'Set X-Content-Type-Options: nosniff on all static and dynamic responses.',
      codeSnippet: REMEDIATION_TEMPLATES.xContentType,
      cwe: 'CWE-16',
    });
  } else {
    findings.push({
      id: 'hdr-xcto-passed',
      category: 'headers',
      title: 'MIME Sniffing Protection Enabled',
      severity: 'passed',
      description: 'X-Content-Type-Options is set to nosniff.',
      impact: 'Ensures strict adherence to declared media types.',
      remediation: 'No action required.',
    });
  }

  // Referrer-Policy
  if (!rp) {
    headersScore -= 8;
    findings.push({
      id: 'hdr-rp-missing',
      category: 'headers',
      title: 'Missing Referrer-Policy Header',
      severity: 'low',
      description: 'No explicit Referrer-Policy configured.',
      impact: 'Sensitive tokens, user identifiers, or private path parameters in URLs may leak to external third parties.',
      remediation: 'Set Referrer-Policy: strict-origin-when-cross-origin.',
      codeSnippet: REMEDIATION_TEMPLATES.referrerPolicy,
    });
  }

  // Server Header Version Disclosure
  if (server && /\d+\.\d+/.test(server)) {
    headersScore -= 8;
    findings.push({
      id: 'hdr-server-leak',
      category: 'headers',
      title: `Server Software Version Leaked (${server})`,
      severity: 'low',
      description: `The Server header reveals specific version numbers (${server}).`,
      impact: 'Provides reconnaissance intelligence to attackers identifying known CVEs.',
      remediation: 'Disable version disclosure tokens in web server configuration.',
      codeSnippet: REMEDIATION_TEMPLATES.serverHide,
      cwe: 'CWE-200',
    });
  }

  if (poweredBy) {
    headersScore -= 5;
    findings.push({
      id: 'hdr-powered-leak',
      category: 'headers',
      title: `X-Powered-By Header Exposed (${poweredBy})`,
      severity: 'low',
      description: `Reveals underlying technology stack: ${poweredBy}.`,
      impact: 'Assists attackers in profiling target application framework.',
      remediation: 'Disable X-Powered-By in application framework settings.',
      codeSnippet: REMEDIATION_TEMPLATES.serverHide,
    });
  }

  headersScore = Math.max(0, Math.min(100, headersScore));

  // DNS & Email Security (Weight: 20%)
  let dnsEmailScore = 100;
  if (!emailSecurity.hasSpf) {
    dnsEmailScore -= 30;
    findings.push({
      id: 'dns-spf-missing',
      category: 'dns',
      title: 'Missing SPF (Sender Policy Framework) Record',
      severity: 'medium',
      description: `No SPF TXT record found on ${hostname}.`,
      impact: 'Attackers can spoof outgoing phishing emails appearing from your domain name.',
      remediation: 'Add a DNS TXT record specifying authorized mail servers (e.g. v=spf1 include:_spf.google.com ~all).',
      codeSnippet: REMEDIATION_TEMPLATES.emailDns,
      cwe: 'CWE-346',
    });
  } else if (emailSecurity.spfAllMechanism === '+all') {
    dnsEmailScore -= 35;
    findings.push({
      id: 'dns-spf-dangerous',
      category: 'dns',
      title: 'Dangerous SPF Record (+all permits any host)',
      severity: 'high',
      description: 'SPF record ends with +all, which explicitly authorizes any IP worldwide to send emails for your domain.',
      impact: 'Completely eliminates email origin authentication.',
      remediation: 'Change +all to -all (hardfail) or ~all (softfail).',
      codeSnippet: REMEDIATION_TEMPLATES.emailDns,
    });
  } else {
    findings.push({
      id: 'dns-spf-passed',
      category: 'dns',
      title: 'SPF Record Configured',
      severity: 'passed',
      description: `SPF active with mechanism ${emailSecurity.spfAllMechanism}.`,
      impact: 'Authorizes legitimate sending mail servers and flags spoofing attempts.',
      remediation: 'No action required.',
    });
  }

  if (!emailSecurity.hasDmarc) {
    dnsEmailScore -= 35;
    findings.push({
      id: 'dns-dmarc-missing',
      category: 'dns',
      title: 'Missing DMARC Record',
      severity: 'medium',
      description: `No DMARC record found at _dmarc.${hostname}.`,
      impact: 'Receiving mail servers lack instructions on how to treat fraudulent emails impersonating this domain.',
      remediation: 'Add a TXT record at _dmarc with policy reject or quarantine.',
      codeSnippet: REMEDIATION_TEMPLATES.emailDns,
      cwe: 'CWE-346',
    });
  } else if (emailSecurity.dmarcPolicy === 'none') {
    dnsEmailScore -= 10;
    findings.push({
      id: 'dns-dmarc-monitoring',
      category: 'dns',
      title: 'DMARC in Monitoring Mode Only (p=none)',
      severity: 'low',
      description: 'DMARC is deployed but policy is set to p=none (no enforcement).',
      impact: 'Fraudulent emails failing authentication are still delivered to recipients’ inboxes.',
      remediation: 'Graduate DMARC policy from p=none to p=quarantine and eventually p=reject.',
      codeSnippet: REMEDIATION_TEMPLATES.emailDns,
    });
  } else {
    findings.push({
      id: 'dns-dmarc-passed',
      category: 'dns',
      title: `DMARC Enforced (p=${emailSecurity.dmarcPolicy})`,
      severity: 'passed',
      description: `DMARC policy actively instructs receiving servers to ${emailSecurity.dmarcPolicy} spoofed emails.`,
      impact: 'Maximum protection against brand impersonation and executive phishing.',
      remediation: 'No action required.',
    });
  }

  // CAA Records Check
  if (caaRecords.length === 0) {
    dnsEmailScore -= 10;
    findings.push({
      id: 'dns-caa-missing',
      category: 'dns',
      title: 'Missing CAA (Certificate Authority Authorization) Record',
      severity: 'low',
      description: 'No CAA DNS records found.',
      impact: 'Any public Certificate Authority could theoretically issue certificates for your domain.',
      remediation: 'Add CAA records specifying your authorized CAs (e.g. letsencrypt.org, digicert.com).',
      codeSnippet: REMEDIATION_TEMPLATES.caa,
    });
  } else {
    findings.push({
      id: 'dns-caa-passed',
      category: 'dns',
      title: 'CAA Record Restricts Certificate Issuance',
      severity: 'passed',
      description: `Found ${caaRecords.length} authorized CAA entries.`,
      impact: 'Restricts rogue or compromised CAs from minting unauthorized certs.',
      remediation: 'No action required.',
    });
  }

  dnsEmailScore = Math.max(0, Math.min(100, dnsEmailScore));

  // Cookies Scoring (Weight: 15%)
  let cookieScore = 100;
  if (parsedCookies.length > 0) {
    let unsecureCount = 0;
    let nonHttpOnlyCount = 0;
    let laxOrUnsetSameSite = 0;

    parsedCookies.forEach((c) => {
      if (!c.secure) unsecureCount++;
      if (!c.httpOnly) nonHttpOnlyCount++;
      if (c.sameSite === 'Unset' || c.sameSite === 'None') laxOrUnsetSameSite++;
    });

    if (unsecureCount > 0) {
      cookieScore -= unsecureCount * 15;
      findings.push({
        id: 'cookie-insecure',
        category: 'cookies',
        title: `${unsecureCount} Cookie(s) Missing "Secure" Attribute`,
        severity: 'high',
        description: 'Cookies without the Secure flag can be transmitted in plaintext across unencrypted HTTP.',
        impact: 'Session tokens can be sniffed on public Wi-Fi networks.',
        remediation: 'Always add the Secure flag to all Set-Cookie directives.',
        codeSnippet: REMEDIATION_TEMPLATES.cookies,
        owasp: 'A05:2021-Security Misconfiguration',
        cwe: 'CWE-614',
      });
    }

    if (nonHttpOnlyCount > 0) {
      cookieScore -= nonHttpOnlyCount * 10;
      findings.push({
        id: 'cookie-no-httponly',
        category: 'cookies',
        title: `${nonHttpOnlyCount} Cookie(s) Missing "HttpOnly" Attribute`,
        severity: 'medium',
        description: 'Cookies without HttpOnly are accessible to client-side JavaScript via document.cookie.',
        impact: 'If an XSS vulnerability exists, attackers can exfiltrate active session tokens.',
        remediation: 'Set HttpOnly on all sensitive session and authentication cookies.',
        codeSnippet: REMEDIATION_TEMPLATES.cookies,
        cwe: 'CWE-1004',
      });
    }

    if (laxOrUnsetSameSite > 0) {
      cookieScore -= laxOrUnsetSameSite * 8;
      findings.push({
        id: 'cookie-samesite-missing',
        category: 'cookies',
        title: `${laxOrUnsetSameSite} Cookie(s) with Lax / Unset SameSite`,
        severity: 'low',
        description: 'Cookies without explicit SameSite=Strict/Lax may be included in third-party cross-site requests.',
        impact: 'Increases exposure to Cross-Site Request Forgery (CSRF).',
        remediation: 'Configure SameSite=Lax (for standard web apps) or SameSite=Strict.',
        codeSnippet: REMEDIATION_TEMPLATES.cookies,
      });
    }
  } else {
    findings.push({
      id: 'cookie-clean',
      category: 'cookies',
      title: 'No Insecure Cookies Detected',
      severity: 'passed',
      description: 'Zero plaintext or untracked cookie headers observed on initial probe.',
      impact: 'Minimal cookie-based attack surface.',
      remediation: 'Ensure newly issued authentication cookies always include Secure and HttpOnly.',
    });
  }
  cookieScore = Math.max(0, Math.min(100, cookieScore));

  // Infrastructure & Redirects Scoring (Weight: 15%)
  let infrastructureScore = 100;
  if (!redirectData.enforcesHttps) {
    infrastructureScore -= 40;
    findings.push({
      id: 'redirect-no-https',
      category: 'redirects',
      title: 'HTTP Traffic Not Upgraded to HTTPS',
      severity: 'critical',
      description: 'Visitors reaching the site over plain HTTP are not redirected to HTTPS.',
      impact: 'Cleartext communications expose user credentials and confidential data.',
      remediation: 'Configure an immediate 301/308 redirect from port 80 (HTTP) to port 443 (HTTPS).',
      codeSnippet: REMEDIATION_TEMPLATES.hsts,
      cwe: 'CWE-319',
    });
  } else if (redirectData.hasDowngrade) {
    infrastructureScore -= 50;
    findings.push({
      id: 'redirect-downgrade',
      category: 'redirects',
      title: 'HTTPS Downgrade Detected in Redirect Chain',
      severity: 'critical',
      description: 'The redirect chain traverses from HTTPS back to an unencrypted HTTP endpoint.',
      impact: 'Severe protocol downgrade vulnerability.',
      remediation: 'Audit server redirect rules to guarantee strictly encrypted hops.',
    });
  } else {
    findings.push({
      id: 'redirect-passed',
      category: 'redirects',
      title: 'HTTPS Redirection Enforced',
      severity: 'passed',
      description: `Traffic smoothly terminates at encrypted endpoint: ${redirectData.finalUrl}.`,
      impact: 'Protects user sessions from wiretapping.',
      remediation: 'No action required.',
    });
  }

  if (hasSecurityTxt) {
    findings.push({
      id: 'security-txt-passed',
      category: 'infrastructure',
      title: 'RFC 9116 security.txt Disclosed',
      severity: 'passed',
      description: `Security contact endpoint detected at ${securityTxtUrl}.`,
      impact: 'Enables ethical security researchers to responsibly report vulnerabilities.',
      remediation: 'Keep contact details and PGP encryption keys up to date.',
    });
  } else {
    infrastructureScore -= 5;
    findings.push({
      id: 'security-txt-missing',
      category: 'infrastructure',
      title: 'Missing RFC 9116 security.txt File',
      severity: 'info',
      description: 'No /.well-known/security.txt file was found.',
      impact: 'Ethical vulnerability researchers have no standardized contact channel to report zero-days.',
      remediation: 'Publish a /.well-known/security.txt file specifying Contact and Expires fields.',
    });
  }

  if (heuristicsData.riskAssessment === 'High Risk') {
    infrastructureScore -= 30;
    findings.push({
      id: 'threat-high-risk',
      category: 'heuristics',
      title: 'Suspicious Domain Heuristics (High Risk)',
      severity: 'high',
      description: `Heuristic indicators triggered: ${[
        heuristicsData.isPunycode ? 'IDN Homograph/Punycode' : null,
        heuristicsData.suspiciousKeywordsFound.length ? `Keywords: ${heuristicsData.suspiciousKeywordsFound.join(', ')}` : null,
        heuristicsData.isIpHostname ? 'Raw IP address' : null,
      ]
        .filter(Boolean)
        .join('; ')}`,
      impact: 'Potential phishing, spoofing, or deceptive domain impersonation.',
      remediation: 'Verify domain legitimacy and ownership records.',
    });
  }

  infrastructureScore = Math.max(0, Math.min(100, infrastructureScore));

  // 11. SQL Injection & URL Query Parameter Hygiene Check (CWE-89, CWE-209, OWASP A03:2021)
  const DB_ERROR_SIGNATURES: Array<{ name: string; pattern: RegExp }> = [
    { name: 'MySQL Syntax / Query Error', pattern: /(SQL syntax.*MySQL|mysql_fetch_array|mysql_fetch_assoc|MySQL server version for the right syntax to use near)/i },
    { name: 'PostgreSQL Syntax / Query Error', pattern: /(PostgreSQL query failed|pg_query\(\)|syntax error at or near|unterminated quoted string at or near)/i },
    { name: 'Oracle SQL Syntax Error', pattern: /(ORA-[0-9]{5}|quoted string not properly terminated|oracle.*driver)/i },
    { name: 'Microsoft SQL Server Error', pattern: /(Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark before the character string|Syntax error in string in query expression|ODBC SQL Server Driver)/i },
    { name: 'SQLite Error', pattern: /(SQLite\/JDBCDriver|SQLite3::SQLException|near ".*": syntax error)/i },
    { name: 'Generic SQL Error / ORM Failure', pattern: /(SQLSTATE\[[0-9A-Z]{5}\]|org\.hibernate\.exception\.SQLGrammarException|JDBC Driver Error)/i },
  ];

  // Inspect response body for database error disclosures
  const detectedDbSignatures: string[] = [];
  DB_ERROR_SIGNATURES.forEach((sig) => {
    if (sig.pattern.test(finalResponseBody)) {
      detectedDbSignatures.push(sig.name);
    }
  });
  const dbErrorDisclosureDetected = detectedDbSignatures.length > 0;

  // Inspect headers for Web Application Firewall (WAF) detection
  let wafDetected = false;
  let wafProvider: string | undefined = undefined;

  const serverHeaderLower = (server || '').toLowerCase();
  if (finalHeaders['cf-ray'] || finalHeaders['cf-cache-status'] || serverHeaderLower.includes('cloudflare')) {
    wafDetected = true;
    wafProvider = 'Cloudflare WAF / Edge Shield';
  } else if (finalHeaders['x-amz-cf-id'] || finalHeaders['awswaf'] || serverHeaderLower.includes('awselb')) {
    wafDetected = true;
    wafProvider = 'AWS WAF / CloudFront';
  } else if (finalHeaders['x-akamai-transformed'] || finalHeaders['akamai-grn'] || serverHeaderLower.includes('akamai')) {
    wafDetected = true;
    wafProvider = 'Akamai Kona Site Defender';
  } else if (finalHeaders['x-fastly-request-id'] || serverHeaderLower.includes('fastly')) {
    wafDetected = true;
    wafProvider = 'Fastly Next-Gen WAF (Signal Sciences)';
  } else if (finalHeaders['x-sucuri-id'] || finalHeaders['x-sucuri-cache']) {
    wafDetected = true;
    wafProvider = 'Sucuri CloudProxy WAF';
  } else if (finalHeaders['x-iinfo'] || finalHeaders['incap_ses']) {
    wafDetected = true;
    wafProvider = 'Imperva Incapsula WAF';
  } else if (finalHeaders['mod_security'] || serverHeaderLower.includes('mod_security')) {
    wafDetected = true;
    wafProvider = 'OWASP ModSecurity Core Rule Set';
  }

  // Parse and analyze query parameters for high-risk injection exposure
  const sensitiveQueryKeys: Record<string, { tier: 'high' | 'medium' | 'low'; note: string }> = {
    id: { tier: 'high', note: 'Primary key database identifier; high risk if passed directly to raw unparameterized SQL statements' },
    user_id: { tier: 'high', note: 'User record identifier; sensitive database target for horizontal privilege escalation and SQLi' },
    userid: { tier: 'high', note: 'Account record identifier; high risk if unparameterized' },
    account: { tier: 'high', note: 'Financial or tenant account identifier; requires strict input casting and prepared statements' },
    cat: { tier: 'medium', note: 'Category database filter; frequent vector for UNION-based SQL injection' },
    category: { tier: 'medium', note: 'Category filter query param; requires parameterized input' },
    sort: { tier: 'high', note: 'Dynamic sorting parameter; prepared statements do not parameterize ORDER BY clauses—requires strict column allowlists' },
    order: { tier: 'high', note: 'Dynamic ordering parameter; vulnerable to boolean/error-based injection if concatenated' },
    orderby: { tier: 'high', note: 'Column ordering directive; must be validated against a strict compile-time allowlist' },
    filter: { tier: 'medium', note: 'Dynamic search filter parameter; prone to boolean-based SQL injection' },
    query: { tier: 'medium', note: 'Free-text search parameter; requires prepared LIKE queries or full-text indexing' },
    q: { tier: 'low', note: 'Search input parameter; should be safely parameterized' },
    search: { tier: 'medium', note: 'Search string parameter; requires parameterized query syntax' },
    select: { tier: 'high', note: 'SQL projection keyword in URL query; critical risk if evaluated dynamically in database queries' },
    table: { tier: 'high', note: 'Table name parameter; identifiers cannot be parameterized—requires strict identifier allowlisting' },
    column: { tier: 'high', note: 'Column identifier in query; requires strict allowlist to avoid SQL injection' },
    limit: { tier: 'low', note: 'Pagination limit; requires explicit integer casting (parseInt) before SQL query' },
    offset: { tier: 'low', note: 'Pagination offset; requires integer casting before SQL query' },
    page: { tier: 'low', note: 'Pagination page number; requires strict numeric coercion' },
    item: { tier: 'medium', note: 'Inventory or entity key; requires parameterized query binding' },
    view: { tier: 'low', note: 'UI view or template key; ensure no dynamic query table injection' },
  };

  const queryParamsList: Array<{ name: string; value: string; riskTier: 'high' | 'medium' | 'low'; note: string }> = [];
  parsed.searchParams.forEach((val, key) => {
    const lowerKey = key.toLowerCase();
    const known = sensitiveQueryKeys[lowerKey];
    let tier: 'high' | 'medium' | 'low' = 'low';
    let note = 'Generic URL parameter; ensure parameterized binding in backend data access layer.';

    if (known) {
      tier = known.tier;
      note = known.note;
    } else if (/id$/i.test(lowerKey) || /_id$/i.test(lowerKey)) {
      tier = 'high';
      note = 'Entity reference identifier parameter; highly sensitive target for raw SQL injection.';
    } else if (/sort|order|filter|where|group/i.test(lowerKey)) {
      tier = 'high';
      note = 'Dynamic query clause parameter; vulnerable to SQL injection if concatenated directly.';
    }

    queryParamsList.push({
      name: key,
      value: val.length > 50 ? `${val.substring(0, 47)}...` : val,
      riskTier: tier,
      note,
    });
  });

  // Calculate SQL Injection Defense Score (0-100)
  let sqliScore = 100;
  const sqliRecommendations: string[] = [];

  if (dbErrorDisclosureDetected) {
    sqliScore -= 50;
    findings.push({
      id: 'sqli-db-error-disclosure',
      category: 'sqli',
      title: 'Database Error Information Disclosure Detected (CWE-209)',
      severity: 'critical',
      description: `Target HTTP response discloses raw database error signatures: ${detectedDbSignatures.join(', ')}.`,
      impact: 'Attackers can exploit detailed database error messages to map table structures, extract schema names, and construct targeted SQL injection payloads.',
      remediation: 'Disable database verbose error display in production (display_errors = Off). Log errors securely to internal logs and return generic 500 error messages.',
      codeSnippet: REMEDIATION_TEMPLATES.sqliDefense,
      owasp: 'A03:2021-Injection',
      cwe: 'CWE-209',
    });
    sqliRecommendations.push('Disable detailed database error messages and stack traces in production environments.');
  }

  const highTierParams = queryParamsList.filter((p) => p.riskTier === 'high');
  if (highTierParams.length > 0) {
    const penalty = wafDetected ? 10 : 25;
    sqliScore -= penalty;
    findings.push({
      id: 'sqli-high-risk-params',
      category: 'sqli',
      title: `${highTierParams.length} Sensitive Query Parameter(s) Detected in URL`,
      severity: wafDetected ? 'low' : 'medium',
      description: `High-risk database parameters exposed in query string: ${highTierParams.map((p) => `"${p.name}"`).join(', ')}. ${wafDetected ? `(Protected by ${wafProvider})` : 'No active WAF detected.'}`,
      impact: 'If passed into raw SQL queries without parameterized prepared statements, these parameters can lead to unauthorized data exfiltration, database tampering, or authentication bypass.',
      remediation: 'Always use parameterized queries (prepared statements) or an established ORM. Validate inputs with strict schemas before database queries.',
      codeSnippet: REMEDIATION_TEMPLATES.sqliDefense,
      owasp: 'A03:2021-Injection',
      cwe: 'CWE-89',
    });
    sqliRecommendations.push('Enforce prepared statements with parameterized inputs for all SQL queries handling URL parameters.');
  }

  if (wafDetected) {
    sqliScore = Math.min(100, sqliScore + 5);
    findings.push({
      id: 'sqli-waf-active',
      category: 'sqli',
      title: `Web Application Firewall (WAF) Detected (${wafProvider})`,
      severity: 'passed',
      description: `Edge defense active: ${wafProvider} inspects incoming HTTP requests for malicious SQL injection patterns and automated exploits.`,
      impact: 'Blocks automated vulnerability scanners and common SQL injection exploit vectors at the network perimeter.',
      remediation: 'Keep WAF managed rule sets (OWASP CRS) continuously updated.',
    });
    sqliRecommendations.push(`Maintain active WAF inspection rules on ${wafProvider}.`);
  } else {
    sqliScore -= 10;
    findings.push({
      id: 'sqli-no-waf',
      category: 'sqli',
      title: 'No Web Application Firewall (WAF) Fingerprint Detected',
      severity: 'low',
      description: 'No edge WAF signatures (Cloudflare, AWS WAF, Akamai, etc.) were identified in HTTP response headers.',
      impact: 'Backend application is directly exposed to brute force and automated SQL injection probing without edge filtering.',
      remediation: 'Deploy an edge Web Application Firewall to drop malicious payloads before they hit origin web servers.',
      codeSnippet: REMEDIATION_TEMPLATES.sqliDefense,
    });
    sqliRecommendations.push('Deploy an edge Web Application Firewall (e.g. Cloudflare WAF, AWS WAF, or ModSecurity).');
  }

  if (queryParamsList.length === 0 && !dbErrorDisclosureDetected) {
    findings.push({
      id: 'sqli-clean-surface',
      category: 'sqli',
      title: 'Clean URL Parameter Attack Surface',
      severity: 'passed',
      description: 'No exposed query parameters or database error leakages detected in analyzed URL.',
      impact: 'Reduced attack surface for URL-based SQL injection reconnaissance.',
      remediation: 'Maintain strict input validation on all backend API routes and POST endpoints.',
    });
  }

  sqliScore = Math.max(0, Math.min(100, sqliScore));

  let injectionPosture: 'Secure / Hardened' | 'Moderate' | 'Warning' | 'High Risk' = 'Secure / Hardened';
  if (sqliScore >= 90) injectionPosture = 'Secure / Hardened';
  else if (sqliScore >= 75) injectionPosture = 'Moderate';
  else if (sqliScore >= 50) injectionPosture = 'Warning';
  else injectionPosture = 'High Risk';

  const sqliData: SqliAnalysisData = {
    hasQueryParameters: queryParamsList.length > 0,
    parametersDetected: queryParamsList,
    dbErrorDisclosureDetected,
    detectedDbSignatures,
    wafDetected,
    wafProvider,
    injectionRiskScore: sqliScore,
    injectionPosture,
    recommendations: sqliRecommendations,
  };

  // Overall Weighted Score (6 Pillars)
  // Weights: SSL 20%, Headers 20%, SQLi & Parameter Defense 20%, DNS & Email 15%, Cookies 15%, Infrastructure 10%
  const overallScore = Math.round(
    sslScore * 0.20 +
    headersScore * 0.20 +
    sqliScore * 0.20 +
    dnsEmailScore * 0.15 +
    cookieScore * 0.15 +
    infrastructureScore * 0.10
  );

  let grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' = 'C';
  if (overallScore >= 95 && sslInfo.status === 'valid' && hsts && csp && sqliScore >= 80) grade = 'A+';
  else if (overallScore >= 85 && sslInfo.status === 'valid') grade = 'A';
  else if (overallScore >= 70) grade = 'B';
  else if (overallScore >= 50) grade = 'C';
  else if (overallScore >= 35) grade = 'D';
  else grade = 'F';

  // Finding counts
  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const highCount = findings.filter((f) => f.severity === 'high').length;
  const mediumCount = findings.filter((f) => f.severity === 'medium').length;
  const lowCount = findings.filter((f) => f.severity === 'low').length;
  const passedCount = findings.filter((f) => f.severity === 'passed').length;

  const scanDurationMs = Date.now() - startTime;

  let executiveStatement = '';
  if (grade === 'A+' || grade === 'A') {
    executiveStatement = `${hostname} demonstrates a strong security posture with robust encryption, strict protocol hygiene, and active defensive headers. Few minor hardening opportunities remain.`;
  } else if (grade === 'B') {
    executiveStatement = `${hostname} maintains acceptable baseline encryption but exhibits noticeable gaps in modern defensive security headers or email authentication policies that should be addressed.`;
  } else if (grade === 'C') {
    executiveStatement = `${hostname} has moderate security posture with missing core defense-in-depth controls (such as CSP, HSTS, or DMARC), leaving visitors exposed to avoidable web-based threats.`;
  } else {
    executiveStatement = `${hostname} displays high-risk security deficiencies including unencrypted or flawed TLS, missing core defensive controls, or severe misconfigurations requiring immediate remediation.`;
  }

  const report = {
    targetUrl,
    normalizedUrl: targetUrl,
    hostname,
    scanTimestamp: new Date().toISOString(),
    scanDurationMs,
    scores: {
      sslScore,
      headersScore,
      dnsEmailScore,
      cookieScore,
      infrastructureScore,
      sqliScore,
      overallScore,
      grade,
    },
    findings,
    summary: {
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      passedCount,
      keyRiskSummary: criticalCount > 0
        ? `${criticalCount} critical vulnerability detected that requires urgent resolution.`
        : highCount > 0
        ? `${highCount} high-priority finding(s) detected.`
        : 'All core security perimeters verified nominal.',
      executiveStatement,
    },
    parameters: {
      ssl: sslInfo,
      headers: headersList,
      cookies: parsedCookies,
      dns: {
        aRecords,
        aaaaRecords,
        mxRecords,
        txtRecords,
        nsRecords,
        cnameRecords,
        caaRecords,
        caaPresent: caaRecords.length > 0,
      },
      emailSecurity,
      redirects: redirectData,
      infrastructure: infrastructureData,
      heuristics: heuristicsData,
      sqli: sqliData,
    },
  };

  res.json(report);
});

// Setup Vite or static serving
async function setupServer() {
  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get('*', (_req, res) => {
        res.sendFile(path.resolve(distPath, 'index.html'));
      });
    }
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[CyberScan Server] Running on http://0.0.0.0:${PORT}`);
  });
}

export default app;

if (!process.env.VERCEL) {
  setupServer().catch((err) => {
    console.error('[CyberScan Server] Startup error:', err);
  });
}

