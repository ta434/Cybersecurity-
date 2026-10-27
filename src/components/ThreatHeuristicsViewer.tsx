import React from 'react';
import { HeuristicAnalysisData } from '../types/security';
import { CheckCircle2, AlertTriangle, Fingerprint, Hash, AlertOctagon } from 'lucide-react';

interface ThreatHeuristicsViewerProps {
  heuristics: HeuristicAnalysisData;
}

export const ThreatHeuristicsViewer: React.FC<ThreatHeuristicsViewerProps> = ({ heuristics }) => {
  const getRiskTheme = (risk: HeuristicAnalysisData['riskAssessment']) => {
    switch (risk) {
      case 'High Risk':
        return {
          textColor: 'text-rose-400',
          borderColor: 'border-rose-500/30',
          bgColor: 'bg-rose-500/10',
          label: 'HIGH THREAT SUSPICION',
          icon: AlertOctagon,
        };
      case 'Suspicious':
        return {
          textColor: 'text-amber-400',
          borderColor: 'border-amber-500/30',
          bgColor: 'bg-amber-500/10',
          label: 'SUSPICIOUS INDICATORS',
          icon: AlertTriangle,
        };
      case 'Low Risk':
        return {
          textColor: 'text-sky-400',
          borderColor: 'border-sky-500/30',
          bgColor: 'bg-sky-500/10',
          label: 'LOW SUSPICION',
          icon: CheckCircle2,
        };
      case 'Clean':
      default:
        return {
          textColor: 'text-emerald-400',
          borderColor: 'border-emerald-500/30',
          bgColor: 'bg-emerald-500/10',
          label: 'NOMINAL / BENIGN PROFILE',
          icon: CheckCircle2,
        };
    }
  };

  const theme = getRiskTheme(heuristics.riskAssessment);
  const RiskIcon = theme.icon;

  return (
    <div className="space-y-6 font-serif">
      {/* Risk Assessment Banner */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center shrink-0">
            <Fingerprint className="w-5 h-5 text-slate-300" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-semibold text-white">Domain & URL Threat Heuristics</h3>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${theme.bgColor} ${theme.textColor} ${theme.borderColor}`}>
                {theme.label}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5 font-serif">
              Evaluating IDN homographs, Shannon randomness entropy, deceptive keyword mimicry, and TLD reputation.
            </p>
          </div>
        </div>
      </div>

      {/* Grid of Heuristics Indicators */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Entropy Card */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-400 font-serif">
            <span>Shannon Entropy</span>
            <Hash className="w-3.5 h-3.5 text-slate-400" />
          </div>
          <div className="text-xl font-bold font-mono text-white tabular-nums">
            {heuristics.entropy} <span className="text-xs font-serif text-slate-400 font-normal">bits</span>
          </div>
          <p className="text-[11px] text-slate-500 font-serif">
            {heuristics.entropy > 4.2
              ? 'High randomness (potential DGA botnet algorithm)'
              : 'Typical natural language domain entropy'}
          </p>
        </div>

        {/* Punycode / Homograph */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-400 font-serif">
            <span>Punycode / Homograph</span>
            <RiskIcon className="w-3.5 h-3.5 text-slate-400" />
          </div>
          <div className={`text-xl font-bold font-mono ${heuristics.isPunycode ? 'text-rose-400' : 'text-emerald-400'}`}>
            {heuristics.isPunycode ? 'DETECTED' : 'CLEAN'}
          </div>
          <p className="text-[11px] text-slate-500 font-serif">
            {heuristics.isPunycode
              ? `Decodes to: ${heuristics.punycodeDecoded} (Cyrillic/Greek spoof risk)`
              : 'Standard ASCII character set'}
          </p>
        </div>

        {/* Subdomain Depth */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-400 font-serif">
            <span>Subdomain Depth</span>
            <span className="text-xs font-mono text-slate-500">Tier</span>
          </div>
          <div className="text-xl font-bold font-mono text-white tabular-nums">
            {heuristics.subdomainDepth}
          </div>
          <p className="text-[11px] text-slate-500 font-serif">
            {heuristics.subdomainDepth >= 3
              ? 'Deep subdomain nesting frequently used in phishing redirects'
              : 'Standard shallow domain hierarchy'}
          </p>
        </div>

        {/* TLD Risk Level */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-400 font-serif">
            <span>TLD Risk Tier</span>
            <span className="text-xs font-mono text-slate-500">.{heuristics.tld}</span>
          </div>
          <div
            className={`text-xl font-bold font-mono capitalize ${
              heuristics.tldRiskLevel === 'high'
                ? 'text-rose-400'
                : heuristics.tldRiskLevel === 'medium'
                ? 'text-amber-400'
                : 'text-emerald-400'
            }`}
          >
            {heuristics.tldRiskLevel} Risk
          </div>
          <p className="text-[11px] text-slate-500 font-serif">
            Evaluation based on global spam, phishing, and registration governance.
          </p>
        </div>
      </div>

      {/* Deceptive Keywords Trigger */}
      {heuristics.suspiciousKeywordsFound.length > 0 && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 space-y-2">
          <div className="flex items-center gap-2 text-rose-300 font-semibold text-xs font-serif">
            <AlertTriangle className="w-4 h-4 text-rose-400" />
            <span>Target Impersonation Keywords Detected</span>
          </div>
          <p className="text-xs text-slate-300 font-serif">
            The domain contains high-frequency credential harvesting and authentication terms:{' '}
            <span className="font-mono text-rose-200 font-semibold">
              {heuristics.suspiciousKeywordsFound.join(', ')}
            </span>
          </p>
        </div>
      )}
    </div>
  );
};
