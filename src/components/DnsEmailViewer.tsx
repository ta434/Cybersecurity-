import React, { useState } from 'react';
import { DnsRecordsData, EmailSecurityData } from '../types/security';
import { Mail, Shield, CheckCircle2, AlertTriangle, AlertOctagon, Copy, Check } from 'lucide-react';

interface DnsEmailViewerProps {
  dns: DnsRecordsData;
  emailSecurity: EmailSecurityData;
  hostname: string;
}

export const DnsEmailViewer: React.FC<DnsEmailViewerProps> = ({ dns, emailSecurity, hostname }) => {
  const [activeDnsTab, setActiveDnsTab] = useState<'A' | 'AAAA' | 'MX' | 'TXT' | 'NS' | 'CAA'>('A');
  const [copiedRecord, setCopiedRecord] = useState<string | null>(null);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedRecord(id);
    setTimeout(() => setCopiedRecord(null), 2000);
  };

  const getSpoofingTheme = (res: EmailSecurityData['spoofingResistance']) => {
    switch (res) {
      case 'High':
        return {
          color: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10',
          label: 'HIGH RESISTANCE',
          desc: 'Domain is strictly protected against email spoofing (DMARC p=reject with SPF).',
          icon: CheckCircle2,
        };
      case 'Moderate':
        return {
          color: 'text-sky-400 border-sky-500/30 bg-sky-500/10',
          label: 'MODERATE RESISTANCE',
          desc: 'Quarantine or softfail policy in effect. Good baseline posture.',
          icon: CheckCircle2,
        };
      case 'Vulnerable':
        return {
          color: 'text-amber-400 border-amber-500/30 bg-amber-500/10',
          label: 'VULNERABLE TO SPOOFING',
          desc: 'SPF or DMARC present but missing enforcement (p=none or loose flags).',
          icon: AlertTriangle,
        };
      case 'Severe':
      default:
        return {
          color: 'text-rose-400 border-rose-500/30 bg-rose-500/10',
          label: 'CRITICAL SPOOFING RISK',
          desc: 'Zero SPF or DMARC records found. Anyone can forge emails from this domain.',
          icon: AlertOctagon,
        };
    }
  };

  const spoofTheme = getSpoofingTheme(emailSecurity.spoofingResistance);

  return (
    <div className="space-y-6 font-serif">
      {/* Email Anti-Spoofing & DMARC Banner */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center shrink-0">
              <Mail className="w-5 h-5 text-slate-300" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-semibold text-white">Email Authentication & Spoofing Defense</h3>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${spoofTheme.color}`}>
                  {spoofTheme.label}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5 font-serif">
                {spoofTheme.desc}
              </p>
            </div>
          </div>
        </div>

        {/* SPF & DMARC Side-by-Side Breakdown */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
          {/* SPF Box */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-white flex items-center gap-1.5 font-serif">
                SPF (Sender Policy Framework)
              </span>
              <span
                className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                  emailSecurity.hasSpf
                    ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30'
                    : 'text-rose-400 bg-rose-500/10 border-rose-500/30'
                }`}
              >
                {emailSecurity.hasSpf ? `ACTIVE (${emailSecurity.spfAllMechanism})` : 'MISSING'}
              </span>
            </div>

            {emailSecurity.spfRecord ? (
              <div className="p-2.5 rounded bg-slate-900 border border-slate-800 overflow-x-auto">
                <code className="text-xs font-mono text-slate-200 break-all whitespace-pre-wrap">
                  {emailSecurity.spfRecord}
                </code>
              </div>
            ) : (
              <p className="text-xs text-slate-500 italic font-serif">
                No TXT record starting with "v=spf1" found on apex domain.
              </p>
            )}

            <div className="text-[11px] text-slate-400 pt-1 font-serif">
              Mechanism: <span className="font-mono text-slate-200 font-semibold">{emailSecurity.spfAllMechanism}</span>{' '}
              {emailSecurity.spfAllMechanism === '-all' && '(Hardfail — Strict & Safe)'}
              {emailSecurity.spfAllMechanism === '~all' && '(Softfail — Flag as Spam)'}
              {emailSecurity.spfAllMechanism === '+all' && '(Dangerous — Permits All IPs)'}
            </div>
          </div>

          {/* DMARC Box */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-white flex items-center gap-1.5 font-serif">
                DMARC Enforcement
              </span>
              <span
                className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                  emailSecurity.dmarcPolicy === 'reject' || emailSecurity.dmarcPolicy === 'quarantine'
                    ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30'
                    : emailSecurity.dmarcPolicy === 'none'
                    ? 'text-amber-400 bg-amber-500/10 border-amber-500/30'
                    : 'text-rose-400 bg-rose-500/10 border-rose-500/30'
                }`}
              >
                {emailSecurity.hasDmarc ? `POLICY: p=${emailSecurity.dmarcPolicy}` : 'MISSING'}
              </span>
            </div>

            {emailSecurity.dmarcRecord ? (
              <div className="p-2.5 rounded bg-slate-900 border border-slate-800 overflow-x-auto">
                <code className="text-xs font-mono text-slate-200 break-all whitespace-pre-wrap">
                  {emailSecurity.dmarcRecord}
                </code>
              </div>
            ) : (
              <p className="text-xs text-slate-500 italic font-serif">
                No TXT record found at _dmarc.{hostname}.
              </p>
            )}

            <div className="text-[11px] text-slate-400 pt-1 font-serif">
              {emailSecurity.dmarcReportEmail && (
                <span>Reporting aggregate errors to: <span className="font-mono text-slate-200">{emailSecurity.dmarcReportEmail}</span></span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* DNS Records Explorer */}
      <div className="space-y-3">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-slate-400" />
            <h4 className="text-sm font-semibold text-white">DNS Zone Records</h4>
          </div>

          {/* Tab selector for record types */}
          <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg overflow-x-auto">
            {(['A', 'AAAA', 'MX', 'TXT', 'NS', 'CAA'] as const).map((type) => {
              const count =
                type === 'A'
                  ? dns.aRecords.length
                  : type === 'AAAA'
                  ? dns.aaaaRecords.length
                  : type === 'MX'
                  ? dns.mxRecords.length
                  : type === 'TXT'
                  ? dns.txtRecords.length
                  : type === 'NS'
                  ? dns.nsRecords.length
                  : dns.caaRecords.length;

              const isActive = activeDnsTab === type;
              return (
                <button
                  key={type}
                  onClick={() => setActiveDnsTab(type)}
                  className={`px-3 py-1 text-xs font-serif font-medium rounded-md font-mono flex items-center gap-1.5 transition-colors ${
                    isActive ? 'bg-slate-800 text-white font-bold' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <span>{type}</span>
                  <span className="text-[11px] text-slate-500 font-mono">({count})</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* DNS Table Content */}
        <div className="rounded-xl border border-slate-800 bg-slate-900 overflow-hidden">
          {activeDnsTab === 'A' && (
            <div className="p-4 space-y-2">
              <span className="text-xs text-slate-400 block mb-2 font-serif">IPv4 Address Records</span>
              {dns.aRecords.length > 0 ? (
                <div className="space-y-1.5">
                  {dns.aRecords.map((ip, i) => (
                    <div key={i} className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950 font-mono text-xs border border-slate-800">
                      <span className="text-white font-medium">{ip}</span>
                      <button
                        onClick={() => handleCopy(ip, `a-${i}`)}
                        className="p-1 text-slate-400 hover:text-white"
                        title="Copy IP"
                      >
                        {copiedRecord === `a-${i}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-slate-500 italic font-serif">No IPv4 (A) records resolved.</p>
              )}
            </div>
          )}

          {activeDnsTab === 'AAAA' && (
            <div className="p-4 space-y-2">
              <span className="text-xs text-slate-400 block mb-2 font-serif">IPv6 Address Records</span>
              {dns.aaaaRecords.length > 0 ? (
                <div className="space-y-1.5">
                  {dns.aaaaRecords.map((ip6, i) => (
                    <div key={i} className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950 font-mono text-xs border border-slate-800">
                      <span className="text-white font-medium break-all">{ip6}</span>
                      <button
                        onClick={() => handleCopy(ip6, `aaaa-${i}`)}
                        className="p-1 text-slate-400 hover:text-white"
                      >
                        {copiedRecord === `aaaa-${i}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-slate-500 italic font-serif">No IPv6 (AAAA) records resolved.</p>
              )}
            </div>
          )}

          {activeDnsTab === 'MX' && (
            <div className="p-4 space-y-2">
              <span className="text-xs text-slate-400 block mb-2 font-serif">Mail Exchange (MX) Servers</span>
              {dns.mxRecords.length > 0 ? (
                <div className="space-y-1.5">
                  {dns.mxRecords.map((mx, i) => (
                    <div key={i} className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950 font-mono text-xs border border-slate-800">
                      <div className="flex items-center gap-3">
                        <span className="text-slate-300 font-semibold text-[11px]">Priority {mx.priority}</span>
                        <span className="text-white">{mx.exchange}</span>
                      </div>
                      <button
                        onClick={() => handleCopy(mx.exchange, `mx-${i}`)}
                        className="p-1 text-slate-400 hover:text-white"
                      >
                        {copiedRecord === `mx-${i}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-slate-500 italic font-serif">No MX records configured.</p>
              )}
            </div>
          )}

          {activeDnsTab === 'TXT' && (
            <div className="p-4 space-y-2">
              <span className="text-xs text-slate-400 block mb-2 font-serif">Text (TXT) Verification Records</span>
              {dns.txtRecords.length > 0 ? (
                <div className="space-y-2">
                  {dns.txtRecords.map((txt, i) => (
                    <div key={i} className="p-2.5 rounded-lg bg-slate-950 font-mono text-xs border border-slate-800 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] text-slate-500">Record #{i + 1}</span>
                        <button
                          onClick={() => handleCopy(txt, `txt-${i}`)}
                          className="p-1 text-slate-400 hover:text-white"
                        >
                          {copiedRecord === `txt-${i}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        </button>
                      </div>
                      <div className="text-slate-200 break-all whitespace-pre-wrap">{txt}</div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-slate-500 italic font-serif">No TXT records configured.</p>
              )}
            </div>
          )}

          {activeDnsTab === 'NS' && (
            <div className="p-4 space-y-2">
              <span className="text-xs text-slate-400 block mb-2 font-serif">Authoritative Nameservers</span>
              {dns.nsRecords.length > 0 ? (
                <div className="space-y-1.5">
                  {dns.nsRecords.map((ns, i) => (
                    <div key={i} className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950 font-mono text-xs border border-slate-800">
                      <span className="text-white">{ns}</span>
                      <button
                        onClick={() => handleCopy(ns, `ns-${i}`)}
                        className="p-1 text-slate-400 hover:text-white"
                      >
                        {copiedRecord === `ns-${i}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-slate-500 italic font-serif">No NS records returned.</p>
              )}
            </div>
          )}

          {activeDnsTab === 'CAA' && (
            <div className="p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-400 block font-serif">Certificate Authority Authorization (CAA)</span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${dns.caaPresent ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30' : 'text-amber-400 bg-amber-500/10 border-amber-500/30'}`}>
                  {dns.caaPresent ? 'CAA ACTIVE' : 'NO CAA RECORD'}
                </span>
              </div>
              {dns.caaRecords.length > 0 ? (
                <div className="space-y-1.5">
                  {dns.caaRecords.map((caa, i) => (
                    <div key={i} className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950 font-mono text-xs border border-slate-800">
                      <div className="flex items-center gap-3">
                        <span className="text-slate-300 font-semibold">{caa.tag}</span>
                        <span className="text-white">{caa.value}</span>
                      </div>
                      <button
                        onClick={() => handleCopy(`${caa.tag} ${caa.value}`, `caa-${i}`)}
                        className="p-1 text-slate-400 hover:text-white"
                      >
                        {copiedRecord === `caa-${i}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400 space-y-1 font-serif">
                  <p>No CAA record defined. Without CAA records, any public CA may issue certificates for this domain.</p>
                  <p className="text-[11px] text-slate-500">Recommended fix: Specify authorized CAs in DNS (e.g., letsencrypt.org, digicert.com).</p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
