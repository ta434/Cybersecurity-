/**
 * Server hardening configuration snippets for immediate remediation
 */

export const REMEDIATION_TEMPLATES = {
  hsts: {
    title: 'Strict-Transport-Security (HSTS)',
    nginx: `# Nginx: Enforce HTTPS for 2 years with preloading
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;`,
    apache: `# Apache (.htaccess / httpd.conf)
<IfModule mod_headers.c>
  Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
</IfModule>`,
    express: `// Node.js Express with Helmet
import helmet from 'helmet';

app.use(helmet.hsts({
  maxAge: 63072000,
  includeSubDomains: true,
  preload: true
}));`,
    cloudflare: `# Cloudflare SSL/TLS -> Edge Certificates
# Toggle "HTTP Strict Transport Security (HSTS)" ON:
# Max-Age: 2 years (63072000)
# Include subdomains: Yes
# Preload: Yes`,
  },

  csp: {
    title: 'Content-Security-Policy (CSP)',
    nginx: `# Nginx: Restrict sources to self and trusted domains
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-RANDOM_KEY'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests;" always;`,
    apache: `# Apache (.htaccess)
<IfModule mod_headers.c>
  Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';"
</IfModule>`,
    express: `// Express with Helmet CSP
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    },
  })
);`,
    cloudflare: `# Cloudflare Rules -> Transform Rules -> Modify Response Header
# Set dynamic/static header:
# Header: Content-Security-Policy
# Value: default-src 'self'; object-src 'none'; frame-ancestors 'none';`,
  },

  xFrameOptions: {
    title: 'X-Frame-Options (Clickjacking Defense)',
    nginx: `# Nginx: Prevent clickjacking framing
add_header X-Frame-Options "DENY" always;`,
    apache: `# Apache (.htaccess)
<IfModule mod_headers.c>
  Header always set X-Frame-Options "DENY"
</IfModule>`,
    express: `// Express with Helmet
app.use(helmet.frameguard({ action: 'deny' }));`,
    cloudflare: `# Transform Rule -> Set Header
# Header: X-Frame-Options
# Value: DENY`,
  },

  xContentType: {
    title: 'X-Content-Type-Options (MIME Sniffing Defense)',
    nginx: `# Nginx: Prevent MIME confusion attacks
add_header X-Content-Type-Options "nosniff" always;`,
    apache: `# Apache (.htaccess)
<IfModule mod_headers.c>
  Header always set X-Content-Type-Options "nosniff"
</IfModule>`,
    express: `// Express with Helmet
app.use(helmet.noSniff());`,
    cloudflare: `# Transform Rule -> Set Header
# Header: X-Content-Type-Options
# Value: nosniff`,
  },

  referrerPolicy: {
    title: 'Referrer-Policy',
    nginx: `# Nginx: Prevent leakage of sensitive URLs in Referer
add_header Referrer-Policy "strict-origin-when-cross-origin" always;`,
    apache: `# Apache (.htaccess)
<IfModule mod_headers.c>
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>`,
    express: `// Express with Helmet
app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));`,
    cloudflare: `# Transform Rule -> Set Header
# Header: Referrer-Policy
# Value: strict-origin-when-cross-origin`,
  },

  permissionsPolicy: {
    title: 'Permissions-Policy (Feature Control)',
    nginx: `# Nginx: Disable unused browser device APIs
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=()" always;`,
    apache: `# Apache (.htaccess)
<IfModule mod_headers.c>
  Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
</IfModule>`,
    express: `// Express custom header
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});`,
    cloudflare: `# Transform Rule -> Set Header
# Header: Permissions-Policy
# Value: camera=(), microphone=(), geolocation=()`,
  },

  serverHide: {
    title: 'Hide Server Version & Technology Disclosure',
    nginx: `# Nginx http/server block:
server_tokens off;`,
    apache: `# Apache httpd.conf
ServerTokens Prod
ServerSignature Off`,
    express: `// Express: Disable X-Powered-By
app.disable('x-powered-by');`,
    cloudflare: `# Cloudflare Network Settings:
# Server Masking is enabled by default on Cloudflare Enterprise/Pro`,
  },

  cookies: {
    title: 'Secure Cookie Attributes (HttpOnly, Secure, SameSite)',
    nginx: `# Nginx proxy cookie flags (if proxying to backend)
proxy_cookie_flags ~* samesite=lax secure httponly;`,
    apache: `# Apache mod_headers edit cookie
<IfModule mod_headers.c>
  Header edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Lax"
</IfModule>`,
    express: `// Express Session / Cookie Config
res.cookie('sessionId', token, {
  httpOnly: true, // Prevents XSS theft via document.cookie
  secure: true,   // Transmits only over HTTPS
  sameSite: 'lax',// Mitigates CSRF
  path: '/',
  maxAge: 86400000 // 24 hours
});`,
    cloudflare: `# Configure secure cookie attributes in backend application origin`,
  },

  emailDns: {
    title: 'SPF & DMARC DNS Records',
    nginx: `# DNS TXT Records for your domain provider (Route53, Cloudflare, etc.):
# SPF Record:
example.com. IN TXT "v=spf1 include:_spf.google.com ~all"

# DMARC Record (subdomain _dmarc):
_dmarc.example.com. IN TXT "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@example.com"`,
    apache: `# DNS Level Configuration (Not handled by web server)`,
    express: `# DNS Level Configuration (Not handled by web server)`,
    cloudflare: `# Cloudflare DNS Management -> Add TXT Records:
# Name: @ | Content: v=spf1 include:_spf.mx.cloudflare.net ~all
# Name: _dmarc | Content: v=DMARC1; p=reject; rua=mailto:reports@yourdomain.com`,
  },

  caa: {
    title: 'Certificate Authority Authorization (CAA) DNS Record',
    nginx: `# DNS Record in your DNS Zone:
example.com. IN CAA 0 issue "letsencrypt.org"
example.com. IN CAA 0 issue "digicert.com"
example.com. IN CAA 0 iodef "mailto:security@example.com"`,
    apache: `# DNS Level Configuration`,
    express: `# DNS Level Configuration`,
    cloudflare: `# Cloudflare DNS -> Add CAA Record:
# Tag: issue | Value: letsencrypt.org`,
  },

  sqliDefense: {
    title: 'SQL Injection Defense & Parameterized Queries (CWE-89)',
    nginx: `# Nginx: Reject obvious SQL injection keywords and union attacks in URI query string
if ($query_string ~* "(union.*select|insert.*into|drop.*table|select.*from|concat\(|load_file|information_schema)") {
  return 403;
}`,
    apache: `# Apache mod_security: Enable OWASP ModSecurity Core Rule Set (CRS)
# SecRule ARGS "(?i:(select.*from|union.*select|information_schema))" "id:1001,phase:2,deny,status:403"`,
    express: `// Express / Node.js: Prepared Statements / Parameterized Queries (pg / mysql2)
// 1. PostgreSQL (pg):
const { rows } = await pool.query(
  'SELECT id, username, email FROM accounts WHERE tenant_id = $1 AND role = $2',
  [tenantId, role]
);

// 2. Input Validation (Zod schema validation before query):
import { z } from 'zod';
const QuerySchema = z.object({ id: z.coerce.number().int().positive() });`,
    cloudflare: `# Cloudflare WAF:
# Under Security -> WAF -> Managed Rules:
# Enable "Cloudflare Managed Ruleset" and "Cloudflare OWASP Core Ruleset"
# Set Paranoia Level to 2 or 3 to actively inspect and drop SQLi patterns`,
    sqlParameterized: `-- Prepared Statement Pattern (ANSI SQL / Postgres / MySQL)
PREPARE fetch_user_record (int, varchar) AS
    SELECT user_id, display_name, email, role 
    FROM users 
    WHERE account_id = $1 AND status = $2;

EXECUTE fetch_user_record (1042, 'active');`,
  },
};

