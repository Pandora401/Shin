import React, { useEffect, useRef } from 'react';
import { Terminal } from 'lucide-react';

const ScanConsole = ({ logs }) => {
    const bottomRef = useRef(null);

    useEffect(() => {
        bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [logs]);

    if (!logs || logs.length === 0) return null;

    return (
        <div className="border-t border-gray-800 bg-black p-2 font-mono text-xs h-32 overflow-y-auto">
            <div className="flex items-center gap-2 text-gray-500 mb-1 sticky top-0 bg-black pb-1 border-b border-gray-900">
                <Terminal size={12} /> SYSTEM LOG
            </div>
            <div className="space-y-1">
                {logs.map((log, i) => (
                    <div key={i} className="text-gray-400">
                        <span className="text-green-900 mr-2">[{new Date().toLocaleTimeString()}]</span>
                        {log}
                    </div>
                ))}
                <div ref={bottomRef} />
            </div>
        </div>
    );
};

export default ScanConsole;
