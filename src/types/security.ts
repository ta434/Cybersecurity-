/**
 * Cybersecurity URL Analyzer Types
 */

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'passed';

export type SecurityGrade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';

export interface SecurityFinding {
  id: string;
  category: 'ssl' | 'headers' | 'dns' | 'cookies' | 'redirects' | 'infrastructure' | 'heuristics' | 'sqli';
  title: string;
  severity: SeverityLevel;
  description: string;
  impact: string;
  remediation: string;
  codeSnippet?: {
    nginx?: string;
    apache?: string;
    express?: string;
    cloudflare?: string;
    sqlParameterized?: string;
  };
  cwe?: string;
  owasp?: string;
}

export interface SslCertificateInfo {
  subject: {
    commonName?: string;
    organization?: string;
    country?: string;
  };
  issuer: {
    commonName?: string;
    organization?: string;
    country?: string;
  };
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  isExpired: boolean;
  isExpiringSoon: boolean; // < 30 days
  isSelfSigned: boolean;
  subjectAltNames: string[];
  protocolVersion: string; // e.g. TLSv1.3
  cipherSuite: string;
  serialNumber?: string;
  fingerprint256?: string;
  keyLength?: number;
  signatureAlgorithm?: string;
  authorized: boolean;
  authorizationError?: string;
  status: 'valid' | 'expiring' | 'expired' | 'untrusted' | 'not_found';
}

export interface SecurityHeaderItem {
  name: string;
  present: boolean;
  value?: string;
  status: 'optimal' | 'warning' | 'missing' | 'insecure';
  importance: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  recommendation: string;
}

export interface CookieItem {
  name: string;
  valueSnippet: string;
  domain?: string;
  path?: string;
  expires?: string;
  maxAge?: number;
  secure: boolean;
  httpOnly: boolean;
  sameSite: 'Strict' | 'Lax' | 'None' | 'Unset';
  prefix: 'host' | 'secure' | 'none';
  riskScore: number; // 0-100
  warnings: string[];
}

export interface DnsRecordsData {
  aRecords: string[];
  aaaaRecords: string[];
  mxRecords: Array<{ exchange: string; priority: number }>;
  txtRecords: string[];
  nsRecords: string[];
  cnameRecords: string[];
  soaRecord?: {
    primaryNs: string;
    adminEmail: string;
    serial: number;
    refresh: number;
    retry: number;
    expire: number;
    minimumTtl: number;
  };
  caaRecords: Array<{ critical: number; tag: string; value: string }>;
  caaPresent: boolean;
  dnssecActive?: boolean;
}

export interface EmailSecurityData {
  hasSpf: boolean;
  spfRecord?: string;
  spfAllMechanism?: '-all' | '~all' | '?all' | '+all' | 'none';
  spfStatus: 'hardfail_safe' | 'softfail_moderate' | 'neutral_weak' | 'allow_dangerous' | 'missing';
  
  hasDmarc: boolean;
  dmarcRecord?: string;
  dmarcPolicy?: 'reject' | 'quarantine' | 'none' | 'missing';
  dmarcPercentage?: number;
  dmarcReportEmail?: string;
  dmarcStatus: 'enforced' | 'monitoring_only' | 'none' | 'missing';
  
  spoofingResistance: 'High' | 'Moderate' | 'Vulnerable' | 'Severe';
}

export interface RedirectHop {
  statusCode: number;
  url: string;
  location?: string;
  protocol: 'http:' | 'https:';
}

export interface RedirectChainData {
  initialUrl: string;
  finalUrl: string;
  totalHops: number;
  hops: RedirectHop[];
  enforcesHttps: boolean;
  hasDowngrade: boolean;
  excessiveHops: boolean;
  status: 'secure' | 'warning' | 'critical';
}

export interface InfrastructureData {
  ipAddress?: string;
  reverseDns?: string;
  asn?: string;
  asnOrg?: string;
  country?: string;
  countryCode?: string;
  city?: string;
  hostingProvider?: string;
  serverBanner?: string;
  poweredByHeader?: string;
  httpVersion?: string;
  hasSecurityTxt: boolean;
  securityTxtUrl?: string;
  securityTxtContent?: string;
  hasRobotsTxt: boolean;
  robotsDisallowedPaths: string[];
}

export interface HeuristicAnalysisData {
  hostname: string;
  entropy: number;
  isPunycode: boolean;
  punycodeDecoded?: string;
  subdomainDepth: number;
  isIpHostname: boolean;
  suspiciousKeywordsFound: string[];
  tld: string;
  tldRiskLevel: 'low' | 'medium' | 'high';
  urlLength: number;
  hasBasicAuthInUrl: boolean;
  riskAssessment: 'Clean' | 'Low Risk' | 'Suspicious' | 'High Risk';
}

export interface SqliAnalysisData {
  hasQueryParameters: boolean;
  parametersDetected: Array<{
    name: string;
    value: string;
    riskTier: 'high' | 'medium' | 'low';
    note: string;
  }>;
  dbErrorDisclosureDetected: boolean;
  detectedDbSignatures: string[];
  wafDetected: boolean;
  wafProvider?: string;
  injectionRiskScore: number; // 0-100 (100 = strong defensive posture)
  injectionPosture: 'Secure / Hardened' | 'Moderate' | 'Warning' | 'High Risk';
  recommendations: string[];
}

export interface CategoryScores {
  sslScore: number; // 0-100
  headersScore: number; // 0-100
  dnsEmailScore: number; // 0-100
  cookieScore: number; // 0-100
  infrastructureScore: number; // 0-100
  sqliScore: number; // 0-100
  overallScore: number; // 0-100
  grade: SecurityGrade;
}

export interface SecurityAnalysisReport {
  targetUrl: string;
  normalizedUrl: string;
  hostname: string;
  scanTimestamp: string;
  scanDurationMs: number;
  scores: CategoryScores;
  findings: SecurityFinding[];
  summary: {
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    passedCount: number;
    keyRiskSummary: string;
    executiveStatement: string;
  };
  parameters: {
    ssl: SslCertificateInfo;
    headers: SecurityHeaderItem[];
    cookies: CookieItem[];
    dns: DnsRecordsData;
    emailSecurity: EmailSecurityData;
    redirects: RedirectChainData;
    infrastructure: InfrastructureData;
    heuristics: HeuristicAnalysisData;
    sqli: SqliAnalysisData;
  };
}

export interface RecentScanItem {
  id: string;
  hostname: string;
  targetUrl: string;
  grade: SecurityGrade;
  overallScore: number;
  timestamp: string;
  criticalCount: number;
  highCount: number;
}
