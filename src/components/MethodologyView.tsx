import React from 'react';
import { 
  Network, 
  Lock, 
  Layers, 
  Mail, 
  Cookie, 
  Globe, 
  Fingerprint, 
  Server, 
  ShieldCheck, 
  Code2,
  Database
} from 'lucide-react';

export const MethodologyView: React.FC = () => {
  const sections = [
    {
      title: '1. DNS Zone Resolution & CAA Validation',
      icon: Network,
      tech: 'Node.js node:dns/promises + RFC 8484 DNS over HTTPS (DoH)',
      description:
        'We execute asynchronous DNS queries directly against authoritative DNS resolvers. We fetch Address records (A/AAAA), Mail Exchange (MX) priorities, Text records (TXT), Nameservers (NS), and Certificate Authority Authorization (CAA) tags. If the sandbox environment restricts direct UDP port 53 egress, our engine automatically falls back to authenticated JSON queries via Google Public DoH (dns.google).',
      codeSnippet: `// DNS Records resolution via native promises
const [a, aaaa, mx, txt, ns, caa] = await Promise.all([
  dnsPromises.resolve4(hostname),
  dnsPromises.resolve6(hostname),
  dnsPromises.resolveMx(hostname),
  dnsPromises.resolveTxt(hostname),
  dnsPromises.resolveNs(hostname),
  dnsPromises.resolveCaa(hostname)
]);`,
    },
    {
      title: '2. TLS Handshake & X.509 Certificate Parsing',
      icon: Lock,
      tech: 'Node.js node:tls.connect() + OpenSSL Certificate Engine',
      description:
        'We open a raw TCP TLS socket to the host on port 443, supplying Server Name Indication (SNI) headers. During the cryptographic TLS handshake, we request the peer certificate object. This extracts the exact X.509 validity dates (valid_to, valid_from), calculates the remaining days until expiration, retrieves the Subject Alternative Names (SANs) array, inspects the CA issuer hierarchy, verifies self-signed status, and captures the negotiated TLS protocol version (TLSv1.3/TLSv1.2) and authenticated AEAD cipher suite.',
      codeSnippet: `const socket = tls.connect({
  host: hostname,
  port: 443,
  servername: hostname,
  rejectUnauthorized: false
}, () => {
  const cert = socket.getPeerCertificate(true);
  const cipher = socket.getCipher();
  const protocol = socket.getProtocol();
  const daysLeft = Math.round((new Date(cert.valid_to) - Date.now()) / 86400000);
});`,
    },
    {
      title: '3. HTTP Defensive Security Headers Audit',
      icon: Layers,
      tech: 'Node.js node:https + RFC 7230 Header Specification',
      description:
        'We initiate an HTTP probe and parse the raw response headers against OWASP Secure Headers guidelines. We specifically parse HSTS (Strict-Transport-Security), Content-Security-Policy (CSP source directives, checking for unsafe-inline or unsafe-eval), X-Frame-Options (DENY/SAMEORIGIN), X-Content-Type-Options (nosniff), Referrer-Policy, Permissions-Policy, COOP, COEP, and check for server software leakage in the "Server" and "X-Powered-By" headers.',
      codeSnippet: `const hsts = headers['strict-transport-security'];
const csp  = headers['content-security-policy'];
const xfo  = headers['x-frame-options'];
const xcto = headers['x-content-type-options'];
// Directives are evaluated against defensive baseline thresholds`,
    },
    {
      title: '4. Cookie Privacy & Attribute Inspection',
      icon: Cookie,
      tech: 'RFC 6265 Cookie Attribute Analyzer',
      description:
        'We extract all Set-Cookie directives from HTTP responses and parse attribute tokens: Secure (verifies cookie is only transmitted over encrypted TLS), HttpOnly (prevents document.cookie accessibility via XSS), SameSite (Strict/Lax/None for CSRF defense), and prefix adherence (__Host- and __Secure-).',
      codeSnippet: `// Parsing cookie tokens
const isSecure = rawCookie.toLowerCase().includes('secure');
const isHttpOnly = rawCookie.toLowerCase().includes('httponly');
const sameSiteMatch = rawCookie.match(/samesite=(strict|lax|none)/i);`,
    },
    {
      title: '5. Email Authentication & Anti-Spoofing (SPF & DMARC)',
      icon: Mail,
      tech: 'RFC 7208 (SPF) + RFC 7489 (DMARC) Evaluators',
      description:
        'We search TXT records for SPF declarations starting with "v=spf1" and parse the qualifier mechanism (-all hardfail, ~all softfail, +all dangerous). We query the specialized _dmarc.<domain> subdomain for DMARC policy records (p=reject, p=quarantine, p=none), reporting addresses (rua), and compute an anti-spoofing resilience tier.',
      codeSnippet: `const spf = txtRecords.find(t => t.startsWith('v=spf1'));
const dmarc = await dnsPromises.resolveTxt(\`_dmarc.\${hostname}\`);
const policy = dmarc.match(/p=(reject|quarantine|none)/i)?.[1];`,
    },
    {
      title: '6. Redirect Chain & HTTPS Downgrade Prober',
      icon: Globe,
      tech: 'Multi-Hop HTTP Redirect Tracer',
      description:
        'Starting from plaintext http:// or https://, our crawler follows 301, 302, 307, and 308 redirects up to 5 hops. It inspects whether unencrypted HTTP is strictly upgraded to HTTPS, identifies open redirect loops, and flags any insecure protocol downgrade hops.',
      codeSnippet: `for (let hop = 0; hop < 5; hop++) {
  const res = await fetch(currentUrl, { redirect: 'manual' });
  hops.push({ statusCode: res.status, url: currentUrl, protocol: url.protocol });
  if (res.headers.get('location')) currentUrl = res.headers.get('location');
  else break;
}`,
    },
    {
      title: '7. Infrastructure, Reverse DNS & ASN Lookup',
      icon: Server,
      tech: 'Reverse DNS PTR + BGP Autonomous System Mapping',
      description:
        'Once the primary IPv4 address is resolved, we perform an in-addr.arpa reverse DNS PTR lookup to determine the canonical server hostname. We cross-reference the IP with public BGP routing databases to identify the Autonomous System Number (ASN), network owner (e.g. Cloudflare, AWS, Fastly, Google Cloud), and geolocation (city, country).',
      codeSnippet: `const ptr = await dnsPromises.reverse(ipAddress);
// Cross-referenced with BGP ASN & Geo registry lookups`,
    },
    {
      title: '8. Domain & URL Threat Heuristics',
      icon: Fingerprint,
      tech: 'Shannon Entropy Equation + IDN Punycode Decoder',
      description:
        'We calculate character distribution randomness using the mathematical Shannon entropy formula: H = -sum(p_i * log2(p_i)). High randomness (entropy > 4.2) flags potential Domain Generation Algorithms (DGA) used by malware command-and-control. We also detect IDN Homograph Punycode attacks (domains starting with xn--) and scan for credential harvesting impersonation keywords.',
      codeSnippet: `function calculateEntropy(str) {
  const len = str.length;
  const freq = {};
  for (let c of str) freq[c] = (freq[c] || 0) + 1;
  return -Object.values(freq).reduce((acc, count) => {
    const p = count / len;
    return acc + p * Math.log2(p);
  }, 0);
}`,
    },
    {
      title: '9. SQL Injection & Database Error Disclosure Defense (OWASP A03 / CWE-89 & CWE-209)',
      icon: Database,
      tech: 'Query Parameter Risk Classifier + CWE-209 DB Error Pattern Engine + Edge WAF Fingerprinter',
      description:
        'We decompose URL query parameters into risk tiers (identifying sensitive primary keys, ORDER BY clauses, and dynamic filter projections). The engine inspects response body streams against known database syntax failure patterns (MySQL, PostgreSQL, Oracle, MSSQL, SQLite) to detect CWE-209 information disclosure. Simultaneously, edge headers are audited for Web Application Firewall (WAF) rule protection (Cloudflare, AWS WAF, Akamai, ModSecurity) and provides parameterized prepared statement templates.',
      codeSnippet: `// CWE-209 DB signature evaluation & parameterized query guidance
const DB_ERRORS = [
  /SQL syntax.*MySQL/i,
  /PostgreSQL query failed|pg_query/i,
  /ORA-[0-9]{5}/i,
  /Microsoft OLE DB Provider for SQL Server/i
];
const dbLeak = DB_ERRORS.some(pattern => pattern.test(responseBody));
// Generates defensive prepared statement templates across Node.js, Python, & PHP`,
    },
  ];

  return (
    <div className="space-y-6 max-w-5xl mx-auto font-serif">
      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
        <div className="flex items-center gap-2 text-white font-bold text-lg font-serif">
          <ShieldCheck className="w-5 h-5 text-emerald-400" />
          <h2>How CyberScan Audits & Extracts Data</h2>
        </div>
        <p className="text-sm text-slate-400 leading-relaxed font-serif">
          Every parameter in CyberScan is measured live by our backend Node.js engine through direct network sockets, DNS protocol queries, and cryptographic handshakes. We do not use simulated or mock datasets.
        </p>
      </div>

      <div className="space-y-4">
        {sections.map((sec, idx) => {
          const Icon = sec.icon;
          return (
            <div key={idx} className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2.5">
                  <div className="w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center shrink-0">
                    <Icon className="w-4 h-4 text-slate-300" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-white font-serif">{sec.title}</h3>
                    <span className="text-[11px] font-mono text-slate-400">{sec.tech}</span>
                  </div>
                </div>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed font-serif">
                {sec.description}
              </p>

              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 overflow-x-auto">
                <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-400 mb-1.5 uppercase">
                  <Code2 className="w-3.5 h-3.5" />
                  <span>Backend Execution Mechanism</span>
                </div>
                <pre className="text-xs font-mono text-slate-300 whitespace-pre">
                  {sec.codeSnippet}
                </pre>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
