import React, { useState } from 'react';
import { Copy, Check, FileCode } from 'lucide-react';

interface DiffViewerProps {
  diff: string;
  filePath?: string;
}

export const DiffViewer: React.FC<DiffViewerProps> = ({ diff, filePath }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(diff);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const lines = diff ? diff.split('\n') : [];

  return (
    <div className="rounded-xl border border-slate-800 bg-[#0d131f] overflow-hidden text-xs">
      {/* Diff Header */}
      <div className="flex items-center justify-between px-4 py-2 bg-slate-900/80 border-b border-slate-800">
        <div className="flex items-center gap-2 text-slate-300 font-mono">
          <FileCode className="w-3.5 h-3.5 text-indigo-400" />
          <span>{filePath || 'proposed_fix.patch'}</span>
        </div>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors text-[11px]"
        >
          {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          <span>{copied ? 'Copied' : 'Copy Diff'}</span>
        </button>
      </div>

      {/* Diff Content */}
      <div className="p-2 overflow-x-auto font-mono text-[11px] leading-relaxed max-h-72 select-text">
        {lines.length === 0 ? (
          <div className="p-4 text-center text-slate-500">No patch available</div>
        ) : (
          lines.map((line, idx) => {
            const isAdd = line.startsWith('+ ') && !line.startsWith('+++ ');
            const isDel = line.startsWith('- ') && !line.startsWith('--- ');
            const isHunk = line.startsWith('@@');
            const isFile = line.startsWith('---') || line.startsWith('+++');

            let lineStyle = 'text-slate-300';
            let bgStyle = 'hover:bg-slate-800/40';

            if (isAdd) {
              lineStyle = 'text-emerald-300';
              bgStyle = 'bg-emerald-950/30 hover:bg-emerald-950/50';
            } else if (isDel) {
              lineStyle = 'text-rose-300';
              bgStyle = 'bg-rose-950/30 hover:bg-rose-950/50';
            } else if (isHunk) {
              lineStyle = 'text-indigo-400 font-semibold';
              bgStyle = 'bg-indigo-950/20';
            } else if (isFile) {
              lineStyle = 'text-slate-400 font-semibold';
            }

            return (
              <div key={idx} className={`flex px-2 py-0.5 rounded ${bgStyle} ${lineStyle}`}>
                <span className="w-8 select-none text-slate-600 text-right pr-3 font-mono text-[10px]">
                  {idx + 1}
                </span>
                <span className="whitespace-pre flex-1">{line}</span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
