import React, { useState, useEffect, useRef } from 'react';
import ScanControl from './components/ScanControl';
import LiveFeed from './components/LiveFeed';
import NetworkMap from './components/NetworkMap';
import ShodanPanel from './components/ShodanPanel';
import ScanConsole from './components/ScanConsole';

function App() {
  const [devices, setDevices] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [lastScanTime, setLastScanTime] = useState(null);
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [scanLogs, setScanLogs] = useState([]);
  const wsRef = useRef(null);

  // Initial load
  useEffect(() => {
    fetch('/api/scan/last') // Relative path works for both 8000 and 44444
      .then(res => res.json())
      .then(data => {
        if (data.hosts) {
          setDevices(data.hosts);
          if (data.timestamp) setLastScanTime(data.timestamp);
        }
      })
      .catch(e => console.error("Poll error", e));
  }, []);

  const startScan = () => {
    if (isScanning) return;
    setIsScanning(true);
    setScanLogs(prev => [...prev, "Initiating socket connection for sweep..."]);

    // Determine WS protocol and host
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host; // e.g., 127.0.0.1:44444 or localhost:5173
    // Note: If running npm run dev (5173), backend is on 8000 or 44444. 
    // We need to know where backend is. 
    // If in Desktop App -> window.location.host is correct (44444).
    // If in Dev -> logic might fail if proxy isn't set.
    // Let's assume consistent port or relative if served.
    let wsUrl = `${protocol}//${host}/ws/scan`;

    // Hardcode fallback for dev mode if host is 5173
    if (host.includes('5173')) {
      wsUrl = 'ws://localhost:8000/ws/scan'; // Or 44444 if using launcher
    }

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      ws.send("START_SCAN");
      setScanLogs([]); // Clear previous logs
    };

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.type === 'log') {
        setScanLogs(prev => [...prev, msg.message]);
        // Check if complete
        if (msg.message === "All tasks finished." || msg.message === "Scan complete.") {
          setIsScanning(false);
          ws.close();
          setLastScanTime(new Date().toISOString());
        }
      }
      else if (msg.type === 'host_found') {
        // Optional: Add placeholder to list
        setScanLogs(prev => [...prev, `>> Discovered: ${msg.ip}`]);
      }
      else if (msg.type === 'result') {
        // Update device list incrementally
        setDevices(prev => {
          // Remove existing if present (update)
          const others = prev.filter(d => d.ip !== msg.host.ip);
          return [...others, msg.host].sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }));
        });
      }
    };

    ws.onerror = (e) => {
      console.error("WS Error", e);
      setScanLogs(prev => [...prev, "Error: WebSocket connection failed."]);
      setIsScanning(false);
    };

    ws.onclose = () => {
      if (isScanning) { // Unexpected close
        setIsScanning(false);
      }
    };
  };

  return (
    <div className="dashboard-grid h-screen w-screen bg-black text-green-500 overflow-hidden">
      {/* Left Column: Controls & Feed */}
      <div className="flex flex-col gap-4 h-full">
        <div className="flex-none">
          <ScanControl
            onScanStart={startScan}
            isScanning={isScanning}
            lastScanTime={lastScanTime}
          />
        </div>
        <div className="flex-1 overflow-hidden flex flex-col">
          <div className="flex-1 overflow-hidden">
            <LiveFeed />
          </div>
          {/* Console Overlay or integrated? Let's integrated it below feed */}
          {isScanning && <div className="h-32 flex-none"><ScanConsole logs={scanLogs} /></div>}
        </div>
      </div>

      {/* Middle Column: Visual Map */}
      <div className="h-full overflow-hidden">
        <NetworkMap
          devices={devices}
          onDeviceClick={setSelectedDevice}
        />
      </div>

      {/* Right Column: Intel & Details */}
      <div className="flex flex-col gap-4 h-full">
        <div className="h-1/2 overflow-hidden">
          <ShodanPanel />
        </div>
        <div className="h-1/2 panel">
          <div className="panel-header">Device Detail</div>
          {selectedDevice ? (
            <div className="space-y-2">
              <div className="text-2xl font-bold">{selectedDevice.ip}</div>
              <div>Hostname: {selectedDevice.hostname}</div>
              <div>MAC: {selectedDevice.mac}</div>
              <div>OS: {selectedDevice.os}</div>
              <div className="mt-4">
                <div className="font-bold border-b border-gray-700 mb-2">SERVICES</div>
                <div className="h-40 overflow-y-auto text-sm space-y-1">
                  {selectedDevice.ports.map((p, i) => (
                    <div key={i} className="flex justify-between">
                      <span className="text-white">{p.port}/{p.protocol}</span>
                      <span className="text-secondary">{p.service}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="text-center text-gray-500 mt-10">SELECT A DEVICE TO INSPECT</div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
