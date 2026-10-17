import React, { useState, useEffect } from 'react';
import {
  Settings as SettingsIcon,
  Cpu,
  GitBranch,
  Key,
  ShieldCheck,
  Check,
  Save,
  Server,
  Info
} from 'lucide-react';
import { AppSettings } from '../types';
import { fetchSettings, updateSettings } from '../api/client';

export const SettingsView: React.FC = () => {
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [provider, setProvider] = useState('heuristic');
  const [geminiKey, setGeminiKey] = useState('');
  const [openaiKey, setOpenaiKey] = useState('');
  const [anthropicKey, setAnthropicKey] = useState('');
  const [ollamaUrl, setOllamaUrl] = useState('http://localhost:11434');
  const [ollamaModel, setOllamaModel] = useState('llama3.2');
  const [githubAppId, setGithubAppId] = useState('');
  const [githubSecret, setGithubSecret] = useState('');
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      const data = await fetchSettings();
      setSettings(data);
      setProvider(data.llm_provider || 'heuristic');
      setOllamaUrl(data.ollama_base_url || 'http://localhost:11434');
      setOllamaModel(data.ollama_model || 'llama3.2');
      setGithubAppId(data.github_app_id || '');
    } catch (err) {
      console.error(err);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      const payload: any = {
        llm_provider: provider,
        ollama_base_url: ollamaUrl,
        ollama_model: ollamaModel,
        github_app_id: githubAppId,
      };
      if (geminiKey) payload.gemini_api_key = geminiKey;
      if (openaiKey) payload.openai_api_key = openaiKey;
      if (anthropicKey) payload.anthropic_api_key = anthropicKey;
      if (githubSecret) payload.github_webhook_secret = githubSecret;

      const updated = await updateSettings(payload);
      setSettings(updated);
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    } catch (err) {
      console.error(err);
      alert('Failed to save settings: ' + String(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-8 max-w-4xl animate-in fade-in duration-150">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <SettingsIcon className="w-5 h-5 text-indigo-400" />
          <span>Platform &amp; AI Engine Settings</span>
        </h2>
        <p className="text-xs text-slate-400">
          Configure vulnerability explanation providers, API keys, and GitHub App credentials
        </p>
      </div>

      <form onSubmit={handleSave} className="space-y-6">
        {/* AI Analysis Provider */}
        <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Cpu className="w-4 h-4 text-indigo-400" />
              <span>AI Vulnerability Analysis &amp; Patch Provider</span>
            </h3>
            <span className="text-xs text-slate-400 capitalize">Active: {provider}</span>
          </div>

          <p className="text-xs text-slate-300 leading-relaxed">
            Select the LLM provider used to generate plain-language explanations, attack scenarios, and remediation diffs. All suggested patches are verified by the re-scan fix validator regardless of the model chosen.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {[
              { id: 'heuristic', name: 'Built-in Security Engine', desc: 'Zero API keys required. Offline deterministic rules & AST diffs.' },
              { id: 'gemini', name: 'Google Gemini', desc: 'Gemini 2.0 Flash / Pro with native structured output.' },
              { id: 'openai', name: 'OpenAI GPT-4o', desc: 'GPT-4o structured JSON response mode.' },
              { id: 'ollama', name: 'Local Ollama', desc: 'Local open-weights (Llama 3 / Mistral) with zero code leakage.' },
            ].map((opt) => (
              <label
                key={opt.id}
                className={`p-4 rounded-xl border cursor-pointer transition-all flex flex-col justify-between ${
                  provider === opt.id
                    ? 'bg-indigo-950/40 border-indigo-500/50 shadow-md shadow-indigo-500/10'
                    : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white">{opt.name}</span>
                    <input
                      type="radio"
                      name="llm_provider"
                      value={opt.id}
                      checked={provider === opt.id}
                      onChange={(e) => setProvider(e.target.value)}
                      className="text-indigo-600 focus:ring-0"
                    />
                  </div>
                  <p className="text-[11px] text-slate-400">{opt.desc}</p>
                </div>
              </label>
            ))}
          </div>

          {/* Conditional Provider Inputs */}
          {provider === 'gemini' && (
            <div className="space-y-1.5 pt-2">
              <label className="text-xs font-medium text-slate-300">Gemini API Key</label>
              <input
                type="password"
                placeholder={settings?.has_gemini_key ? '••••••••••••••••' : 'AIzaSy...'}
                value={geminiKey}
                onChange={(e) => setGeminiKey(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-indigo-500 font-mono"
              />
            </div>
          )}

          {provider === 'openai' && (
            <div className="space-y-1.5 pt-2">
              <label className="text-xs font-medium text-slate-300">OpenAI API Key</label>
              <input
                type="password"
                placeholder={settings?.has_openai_key ? '••••••••••••••••' : 'sk-...'}
                value={openaiKey}
                onChange={(e) => setOpenaiKey(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-indigo-500 font-mono"
              />
            </div>
          )}

          {provider === 'ollama' && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">Ollama Base URL</label>
                <input
                  type="text"
                  value={ollamaUrl}
                  onChange={(e) => setOllamaUrl(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-indigo-500 font-mono"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">Model Name</label>
                <input
                  type="text"
                  value={ollamaModel}
                  onChange={(e) => setOllamaModel(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-indigo-500 font-mono"
                />
              </div>
            </div>
          )}
        </div>

        {/* GitHub App Credentials */}
        <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <GitBranch className="w-4 h-4 text-purple-400" />
              <span>GitHub App Integration</span>
            </h3>
            {settings?.has_github_app ? (
              <span className="text-[10px] font-semibold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                Configured
              </span>
            ) : (
              <span className="text-[10px] text-slate-400 bg-slate-800 px-2 py-0.5 rounded">
                Simulation Mode
              </span>
            )}
          </div>

          <p className="text-xs text-slate-300 leading-relaxed">
            Configure your GitHub App to receive live webhook payloads on push or pull requests and comment directly on PR threads. (You can also use the built-in Webhook Simulator in the Scans tab to demo without setting up a real GitHub App).
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-slate-300">GitHub App ID</label>
              <input
                type="text"
                value={githubAppId}
                onChange={(e) => setGithubAppId(e.target.value)}
                placeholder="e.g. 123456"
                className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-slate-300">GitHub Webhook Secret</label>
              <input
                type="password"
                value={githubSecret}
                onChange={(e) => setGithubSecret(e.target.value)}
                placeholder="HMAC secret token"
                className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-indigo-500"
              />
            </div>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 text-xs text-slate-400 space-y-1">
            <div className="font-semibold text-slate-300">Webhook Receiver URL:</div>
            <code className="text-indigo-400 font-mono text-[11px] block bg-slate-950 p-2 rounded">
              http://your-server-or-ngrok-url/api/webhooks/github
            </code>
          </div>
        </div>

        {/* Threat Feeds Status */}
        <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-3">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Server className="w-4 h-4 text-emerald-400" />
            <span>Threat Intelligence Feeds</span>
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center justify-between">
              <div>
                <strong className="text-white block">FIRST.org EPSS Feed</strong>
                <span className="text-[11px] text-slate-400">Live 30-day exploit probabilities</span>
              </div>
              <span className="text-emerald-400 font-semibold text-[11px]">Online (24h Cache)</span>
            </div>
            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center justify-between">
              <div>
                <strong className="text-white block">CISA KEV Catalog</strong>
                <span className="text-[11px] text-slate-400">Known Exploited Vulnerabilities</span>
              </div>
              <span className="text-emerald-400 font-semibold text-[11px]">Active (Pre-Seeded)</span>
            </div>
          </div>
        </div>

        {/* Save Button */}
        <div className="flex items-center justify-end gap-3 pt-2">
          {saved && (
            <span className="flex items-center gap-1.5 text-xs text-emerald-400 font-semibold animate-in fade-in">
              <Check className="w-4 h-4" />
              Settings Saved Successfully
            </span>
          )}
          <button
            type="submit"
            disabled={saving}
            className="flex items-center gap-2 px-6 py-2.5 bg-gradient-to-r from-indigo-500 to-purple-600 hover:from-indigo-400 hover:to-purple-500 text-white text-xs font-bold rounded-xl shadow-lg shadow-indigo-500/25 transition-all"
          >
            <Save className="w-4 h-4" />
            <span>{saving ? 'Saving...' : 'Save Configuration'}</span>
          </button>
        </div>
      </form>
    </div>
  );
};
