import React, { useState, useEffect } from 'react';
import {
  Globe,
  ShieldCheck,
  ShieldAlert,
  Key,
  Check,
  AlertTriangle,
  Play,
  Loader2,
  Copy,
  ExternalLink
} from 'lucide-react';
import { DASTTarget } from '../types';
import {
  fetchDastTargets,
  createDastChallenge,
  verifyDastTarget,
  runDastScan
} from '../api/client';

export const DastView: React.FC = () => {
  const [targets, setTargets] = useState<DASTTarget[]>([]);
  const [targetUrl, setTargetUrl] = useState('http://localhost:3000');
  const [challenge, setChallenge] = useState<any | null>(null);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    loadTargets();
  }, []);

  const loadTargets = async () => {
    try {
      const data = await fetchDastTargets();
      setTargets(data);
    } catch (err) {
      console.error(err);
    }
  };

  const handleGenerateChallenge = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl) return;
    setLoading(true);
    try {
      const res = await createDastChallenge(targetUrl);
      setChallenge(res);
      await loadTargets();
    } catch (err) {
      console.error(err);
      alert('Failed to generate challenge: ' + String(err));
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async (url: string) => {
    setLoading(true);
    try {
      const res = await verifyDastTarget(url);
      alert(res.message);
      await loadTargets();
    } catch (err) {
      console.error(err);
      alert('Verification error: ' + String(err));
    } finally {
      setLoading(false);
    }
  };

  const handleScan = async (url: string) => {
    setScanning(true);
    try {
      const res = await runDastScan(url);
      alert(`DAST Scan Completed! Identified ${res.findings_count} findings.`);
      await loadTargets();
    } catch (err) {
      console.error(err);
      alert('DAST scan failed: ' + String(err));
    } finally {
      setScanning(false);
    }
  };

  const copyToken = () => {
    if (!challenge) return;
    navigator.clipboard.writeText(challenge.verification_token);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-150">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20 mb-2">
            DAST &amp; OWASP ZAP Integration
          </div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Globe className="w-5 h-5 text-rose-400" />
            <span>Dynamic Application Security Testing (DAST)</span>
          </h2>
          <p className="text-xs text-slate-400">
            Automated baseline DAST scanning with strict HTTP Well-Known domain ownership verification
          </p>
        </div>
      </div>

      {/* Legal & Security Risk Warning Banner */}
      <div className="p-4 rounded-2xl bg-amber-950/20 border border-amber-500/30 flex items-start gap-3 text-xs text-amber-200">
        <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <strong className="font-semibold text-amber-300">Target Ownership Protection:</strong>
          <p className="text-amber-200/80 leading-relaxed">
            DAST against arbitrary web properties without authorization carries legal liability. Guardstack enforces HTTP token verification to ensure you own or control the staging domain before scanning. (Localhost and 127.0.0.1 are automatically approved for local testing).
          </p>
        </div>
      </div>

      {/* Target Setup Card */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <Key className="w-4 h-4 text-indigo-400" />
          <span>Register Target &amp; Generate Ownership Challenge</span>
        </h3>

        <form onSubmit={handleGenerateChallenge} className="flex flex-col sm:flex-row items-center gap-3">
          <input
            type="url"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="http://localhost:3000 or https://staging.myapp.com"
            className="flex-1 w-full px-4 py-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-indigo-500"
            required
          />
          <button
            type="submit"
            disabled={loading}
            className="w-full sm:w-auto px-5 py-2 bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-400 hover:to-purple-500 disabled:opacity-50 text-white text-xs font-semibold rounded-xl transition-all shadow-md flex items-center justify-center gap-2"
          >
            {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Key className="w-3.5 h-3.5" />}
            <span>Generate Challenge Token</span>
          </button>
        </form>

        {challenge && (
          <div className="p-4 rounded-xl bg-[#090d16] border border-slate-800 space-y-3 mt-4 text-xs">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-200">Verification Challenge Token:</span>
              <button
                onClick={copyToken}
                className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px]"
              >
                {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copied ? 'Copied' : 'Copy Token'}</span>
              </button>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-950 font-mono text-indigo-300 text-xs select-all">
              {challenge.verification_token}
            </div>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              {challenge.instructions}
            </p>
          </div>
        )}
      </div>

      {/* Target Management Table */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400">
          Target Domains &amp; Verification Status
        </h3>

        {targets.length === 0 ? (
          <div className="glass-panel p-8 text-center text-slate-500 rounded-2xl text-xs">
            No DAST targets registered yet. Register a domain above to begin.
          </div>
        ) : (
          <div className="glass-panel rounded-2xl border border-slate-800 overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800 font-medium">
                <tr>
                  <th className="py-3 px-4">Target URL</th>
                  <th className="py-3 px-4">Ownership Status</th>
                  <th className="py-3 px-4">Verification Token</th>
                  <th className="py-3 px-4">Last Scanned</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {targets.map((t) => (
                  <tr key={t.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-4 font-mono font-medium text-white">{t.url}</td>
                    <td className="py-3 px-4">
                      {t.verified ? (
                        <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                          <ShieldCheck className="w-3 h-3" />
                          Verified
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
                          <AlertTriangle className="w-3 h-3" />
                          Unverified
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 font-mono text-[11px] text-slate-400">
                      {t.verification_token.slice(0, 16)}...
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {t.last_scanned_at ? new Date(t.last_scanned_at).toLocaleString() : 'Never'}
                    </td>
                    <td className="py-3 px-4 text-right space-x-2">
                      {!t.verified && (
                        <button
                          onClick={() => handleVerify(t.url)}
                          disabled={loading}
                          className="px-2.5 py-1 rounded-lg bg-indigo-600/30 hover:bg-indigo-600/50 text-indigo-300 text-[11px] font-medium transition-colors"
                        >
                          Verify Ownership
                        </button>
                      )}
                      <button
                        onClick={() => handleScan(t.url)}
                        disabled={scanning}
                        className="px-3 py-1 rounded-lg bg-gradient-to-r from-rose-500 to-pink-600 hover:from-rose-400 hover:to-pink-500 disabled:opacity-50 text-white text-[11px] font-semibold transition-all shadow-sm"
                      >
                        {scanning ? 'Scanning...' : 'Launch ZAP DAST'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
