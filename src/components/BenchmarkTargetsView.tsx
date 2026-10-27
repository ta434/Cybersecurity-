import React from 'react';
import { ArrowRight } from 'lucide-react';

interface BenchmarkTargetsViewProps {
  onSelectDomain: (domain: string) => void;
}

const TARGET_PROFILES = [
  {
    domain: 'cloudflare.com',
    name: 'Cloudflare Edge CDN',
    grade: 'A+',
    tags: ['HSTS Preloaded', 'Strict CSP', 'Modern TLS 1.3', 'CAA Configured'],
    desc: 'Exemplary enterprise edge security posture with preloaded HSTS, multi-layered CSP, and strict email authentication.',
  },
  {
    domain: 'github.com',
    name: 'GitHub Platform',
    grade: 'A',
    tags: ['Strong TLS', 'Frame Ancestors', 'DMARC Quarantine', 'Subresource Integrity'],
    desc: 'Hardened developer platform with rigorous origin isolation, strict transport security, and authenticated email routing.',
  },
  {
    domain: 'google.com',
    name: 'Google Infrastructure',
    grade: 'A+',
    tags: ['Custom TLS', 'HSTS Enforced', 'High Email Reputation', 'Anycast Network'],
    desc: 'High-assurance global infrastructure with rigorous identity verification, DNSSEC, and global anycast distribution.',
  },
  {
    domain: 'wikipedia.org',
    name: 'Wikimedia Foundation',
    grade: 'A',
    tags: ['Strict HTTPS', 'Clean Cookie Surface', 'DMARC Configured', 'Fastly CDN'],
    desc: 'Robust content delivery architecture ensuring encrypted transport and open knowledge delivery with minimal tracking.',
  },
  {
    domain: 'httpbin.org',
    name: 'HTTP Testbed',
    grade: 'B',
    tags: ['Permissive Headers', 'Missing DMARC', 'Standard TLS', 'API Testing'],
    desc: 'Useful developer sandbox demonstrating standard baseline security headers without strict CSP or DMARC enforcement.',
  },
  {
    domain: 'expired.badssl.com',
    name: 'BadSSL Expired Cert Suite',
    grade: 'F',
    tags: ['Expired X.509', 'Browser Warning Alert', 'Failure Demonstration'],
    desc: 'Public security testing endpoint intentionally presenting an expired TLS certificate to verify certificate validation engines.',
  },
];

export const BenchmarkTargetsView: React.FC<BenchmarkTargetsViewProps> = ({ onSelectDomain }) => {
  return (
    <div className="space-y-6 max-w-5xl mx-auto font-serif">
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800">
        <h3 className="text-base font-semibold text-white">Target Security Benchmarks</h3>
        <p className="text-xs text-slate-400 mt-1 font-serif">
          Select standard target domains to compare different security architectures, from hardened A+ edge networks to deliberate failure testbeds.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {TARGET_PROFILES.map((profile) => (
          <div
            key={profile.domain}
            className="p-5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition-all space-y-3 flex flex-col justify-between"
          >
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="text-sm font-bold text-white font-mono">{profile.domain}</h4>
                  <span className="text-xs text-slate-400 font-serif">{profile.name}</span>
                </div>
                <span
                  className={`text-lg font-bold font-serif px-2.5 py-0.5 rounded border ${
                    profile.grade === 'A+' || profile.grade === 'A'
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                      : profile.grade === 'B'
                      ? 'bg-sky-500/10 text-sky-400 border-sky-500/30'
                      : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                  }`}
                >
                  {profile.grade}
                </span>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed font-serif">
                {profile.desc}
              </p>

              <div className="flex flex-wrap gap-1.5 pt-1">
                {profile.tags.map((t) => (
                  <span
                    key={t}
                    className="px-2 py-0.5 rounded bg-slate-950 text-[11px] font-mono text-slate-400 border border-slate-800"
                  >
                    {t}
                  </span>
                ))}
              </div>
            </div>

            <div className="pt-2 border-t border-slate-800/80 flex items-center justify-end">
              <button
                onClick={() => onSelectDomain(profile.domain)}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-serif font-bold text-slate-950 bg-white hover:bg-slate-200 rounded-lg transition-colors shadow-xs"
              >
                <span>Audit {profile.domain}</span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-950" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
