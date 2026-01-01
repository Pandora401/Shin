import React, { useState, useEffect } from 'react';
import { Globe, AlertTriangle, Search } from 'lucide-react';

const ShodanPanel = () => {
    const [ip, setIp] = useState('');
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    const handleSearch = async () => {
        if (!ip) return;
        setLoading(true);
        setError(null);
        setData(null);
        try {
            const res = await fetch(`http://localhost:8000/api/shodan/${ip}`);
            const json = await res.json();
            if (json.error) throw new Error(json.error);
            setData(json);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="panel h-full flex flex-col">
            <div className="panel-header flex items-center gap-2">
                <Globe size={18} /> Global Threat Intel (Shodan)
            </div>

            <div className="flex gap-2 my-4">
                <input
                    type="text"
                    value={ip}
                    onChange={(e) => setIp(e.target.value)}
                    placeholder="ENTER PUBLIC IP..."
                    className="bg-black border border-gray-700 p-2 text-primary font-mono w-full focus:outline-none focus:border-primary"
                />
                <button
                    onClick={handleSearch}
                    disabled={loading}
                    className="border border-primary text-primary px-3 hover:bg-primary hover:text-black transition-colors"
                >
                    <Search size={16} />
                </button>
            </div>

            <div className="flex-1 overflow-y-auto">
                {loading && <div className="text-center animate-pulse text-secondary">ACCESSING GLOBAL DB...</div>}
                {error && <div className="text-alert border border-alert p-2">{error}</div>}

                {data && (
                    <div className="space-y-4">
                        <div className="flex justify-between items-start border-b border-gray-800 pb-2">
                            <div>
                                <div className="text-xl font-bold text-white">{data.ip}</div>
                                <div className="text-secondary">{data.org}</div>
                            </div>
                            <div className="text-right text-gray-500">{data.os}</div>
                        </div>

                        {data.vulns && data.vulns.length > 0 && (
                            <div>
                                <div className="text-alert font-bold flex items-center gap-2 mb-1">
                                    <AlertTriangle size={14} /> VULNERABILITIES DETECTED
                                </div>
                                <div className="bg-red-900/10 p-2 border border-red-900/50">
                                    {data.vulns.map(v => (
                                        <span key={v} className="inline-block bg-red-900/50 text-red-200 text-xs px-1 rounded mr-1 mb-1">{v}</span>
                                    ))}
                                </div>
                            </div>
                        )}

                        <div>
                            <div className="text-secondary font-bold mb-1">OPEN PORTS</div>
                            <div className="grid grid-cols-4 gap-2">
                                {data.ports && data.ports.map(p => (
                                    <div key={p} className="text-center border border-gray-700 p-1 text-sm bg-gray-900">{p}</div>
                                ))}
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default ShodanPanel;
