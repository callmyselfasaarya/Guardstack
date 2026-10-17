import React, { useState, useEffect } from 'react';
import { X, Copy, Check, GitPullRequest, Bot, ExternalLink } from 'lucide-react';
import { fetchPRCommentPreview } from '../api/client';

interface PRCommentModalProps {
  findingId: string | null;
  onClose: () => void;
}

export const PRCommentModal: React.FC<PRCommentModalProps> = ({ findingId, onClose }) => {
  const [markdown, setMarkdown] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [copied, setCopied] = useState<boolean>(false);

  useEffect(() => {
    if (!findingId) return;
    setLoading(true);
    fetchPRCommentPreview(findingId)
      .then((res) => setMarkdown(res.markdown))
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  }, [findingId]);

  if (!findingId) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(markdown);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="bg-[#0e1626] border border-slate-700/80 w-full max-w-3xl rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900/60">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-indigo-500/20 text-indigo-400 flex items-center justify-center border border-indigo-500/30">
              <GitPullRequest className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-white">GitHub PR Review Bot Simulation</h2>
              <p className="text-xs text-slate-400">Preview of the review comment posted back to GitHub Pull Request threads</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* GitHub Comment Bubble Simulation */}
        <div className="p-6 overflow-y-auto space-y-4">
          <div className="flex items-start gap-3">
            <div className="w-10 h-10 rounded-full bg-gradient-to-tr from-indigo-600 to-purple-600 flex items-center justify-center text-white shrink-0 shadow-md">
              <Bot className="w-5 h-5" />
            </div>
            <div className="flex-1 rounded-2xl border border-slate-700/80 bg-slate-900/90 overflow-hidden shadow-lg">
              {/* Comment Header */}
              <div className="px-4 py-2.5 bg-slate-800/80 border-b border-slate-700/60 flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-white">guardstack-bot</span>
                  <span className="px-1.5 py-0.5 rounded text-[10px] uppercase font-bold bg-slate-700 text-slate-300">
                    bot
                  </span>
                  <span className="text-slate-400">• commented on commit c3a4f89d</span>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleCopy}
                    className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-700 hover:bg-slate-600 text-slate-200 transition-colors text-[11px]"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copied ? 'Copied' : 'Copy Raw Markdown'}</span>
                  </button>
                </div>
              </div>

              {/* Comment Body */}
              <div className="p-5 font-mono text-xs text-slate-300 leading-relaxed whitespace-pre-wrap select-text bg-[#0b101c]">
                {loading ? (
                  <div className="py-12 text-center text-slate-500 font-sans">
                    Generating PR review comment preview...
                  </div>
                ) : (
                  markdown
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3 bg-slate-900/90 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <span>Formatted according to GitHub Octokit review comment standards</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
