import React, { useEffect, useState, useRef } from 'react';
import { Activity, Wifi } from 'lucide-react';

const LiveFeed = () => {
    const [packets, setPackets] = useState([]);
    const bottomRef = useRef(null);
    const maxPackets = 50;

    useEffect(() => {
        const ws = new WebSocket('ws://localhost:8000/ws/traffic');

        ws.onmessage = (event) => {
            const pkt = JSON.parse(event.data);
            setPackets((prev) => {
                const newPackets = [...prev, pkt];
                if (newPackets.length > maxPackets) {
                    return newPackets.slice(newPackets.length - maxPackets);
                }
                return newPackets;
            });
        };

        ws.onclose = () => console.log("WS Disconnected");

        return () => ws.close();
    }, []);

    useEffect(() => {
        bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [packets]);

    return (
        <div className="panel flex flex-col h-full">
            <div className="panel-header flex items-center gap-2">
                <Activity size={18} /> Live Traffic Feed
                <div className="ml-auto flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span>
                    <span className="text-xs">LIVE</span>
                </div>
            </div>

            <div className="flex-1 overflow-y-auto font-mono text-xs space-y-1 p-2 bg-black/50">
                {packets.map((pkt, i) => (
                    <div key={i} className="grid grid-cols-[80px_120px_120px_50px_1fr] gap-2 border-b border-gray-900 pb-1 hover:bg-green-900/10">
                        <span className="text-gray-500">{new Date(pkt.timestamp).toLocaleTimeString()}</span>
                        <span className="text-blue-400">{pkt.src}</span>
                        <span className="text-orange-400">{pkt.dst}</span>
                        <span className={`font-bold ${pkt.protocol === 'TCP' ? 'text-green-500' : 'text-yellow-500'}`}>
                            {pkt.protocol}
                        </span>
                        <span className="text-gray-300 truncate">{pkt.info}</span>
                    </div>
                ))}
                <div ref={bottomRef} />
            </div>
        </div>
    );
};

export default LiveFeed;
