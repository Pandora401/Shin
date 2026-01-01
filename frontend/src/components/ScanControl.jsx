import React, { useState, useEffect } from 'react';
import { Timer, Radio, Play, AlertCircle } from 'lucide-react';

const ScanControl = ({ onScanStart, isScanning, lastScanTime }) => {
    const [timeLeft, setTimeLeft] = useState(300); // 5 minutes in seconds

    useEffect(() => {
        const timer = setInterval(() => {
            setTimeLeft((prev) => {
                if (prev <= 1) {
                    // Trigger automatic scan logic if handled here, or just reset
                    // Ideally backend triggers scan, frontend just polls or reacts.
                    // But req says "countdown ... that runs full network enumeration".
                    // If backend runs it periodically, we just sync to it? 
                    // For now, let's just reset timer and let backend loop handle it, 
                    // or we can trigger it from frontend. Backend loop is robust.
                    // We will sync reset on successful scan update.
                    return 300;
                }
                return prev - 1;
            });
        }, 1000);
        return () => clearInterval(timer);
    }, []);

    // Reset timer when a new scan completes
    useEffect(() => {
        if (lastScanTime) {
            setTimeLeft(300);
        }
    }, [lastScanTime]);

    const formatTime = (seconds) => {
        const m = Math.floor(seconds / 60);
        const s = seconds % 60;
        return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
    };

    return (
        <div className="panel flex flex-col gap-4">
            <div className="panel-header flex items-center justify-between">
                <span className="flex items-center gap-2">
                    <Radio size={18} /> Surveillance Control
                </span>
                {isScanning && <span className="text-alert animate-pulse">SCANNING...</span>}
            </div>

            <div className="flex items-center justify-between mt-2">
                <div className="text-center">
                    <div className="text-xs text-secondary mb-1">NEXT AUTO-SCAN</div>
                    <div className="text-3xl font-mono text-primary flex items-center gap-2">
                        <Timer size={24} />
                        {formatTime(timeLeft)}
                    </div>
                </div>

                <button
                    onClick={onScanStart}
                    disabled={isScanning}
                    className="scan-btn flex items-center gap-2"
                >
                    <Play size={16} /> INITIATE SWEEP
                </button>
            </div>

            <div className="text-xs text-gray-500 mt-2">
                LAST SWEEP: {lastScanTime ? new Date(lastScanTime).toLocaleTimeString() : 'UNKNOWN'}
            </div>
        </div>
    );
};

export default ScanControl;
