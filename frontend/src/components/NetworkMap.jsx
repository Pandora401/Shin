import React from 'react';
import { Monitor, Server, Smartphone, Globe, Shield } from 'lucide-react';

const DeviceIcon = ({ type }) => {
    if (type.toLowerCase().includes('windows')) return <Monitor className="text-blue-400" />;
    if (type.toLowerCase().includes('linux')) return <Server className="text-orange-400" />;
    if (type.toLowerCase().includes('phone')) return <Smartphone className="text-green-400" />;
    return <Globe className="text-gray-400" />;
};

const NetworkMap = ({ devices, onDeviceClick }) => {
    return (
        <div className="panel flex flex-col h-full">
            <div className="panel-header flex items-center justify-between">
                <span className="flex items-center gap-2">
                    <Shield size={18} /> Network Topology
                </span>
                <span className="text-xs text-gray-500">{devices.length} ASSETS DETECTED</span>
            </div>

            <div className="flex-1 overflow-y-auto space-y-2 mt-2">
                {devices.map((device, idx) => (
                    <div
                        key={idx}
                        onClick={() => onDeviceClick(device)}
                        className="p-3 border border-gray-800 bg-gray-900/50 hover:bg-green-900/20 cursor-pointer transition-all flex items-center justify-between group"
                    >
                        <div className="flex items-center gap-3">
                            <DeviceIcon type={device.os || 'unknown'} />
                            <div>
                                <div className="font-bold text-lg text-primary group-hover:text-white transition-colors">
                                    {device.ip}
                                </div>
                                <div className="text-xs text-gray-400 flex flex-col">
                                    <span>{device.hostname || 'UNKNOWN HOST'}</span>
                                    <span>{device.mac}</span>
                                </div>
                            </div>
                        </div>

                        <div className="text-right">
                            <div className="text-xs text-secondary">{device.os}</div>
                            <div className="text-xs text-gray-500">{device.ports.length} PORTS OPEN</div>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default NetworkMap;
