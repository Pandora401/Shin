import nmap
import asyncio
import json
import os
from datetime import datetime

class NetworkScanner:
    def __init__(self):
        # Auto-detect Nmap in common Windows locations
        nmap_paths = [
            r"C:\Program Files (x86)\Nmap",
            r"C:\Program Files\Nmap"
        ]
        
        path_updated = False
        for path in nmap_paths:
            if os.path.exists(os.path.join(path, "nmap.exe")):
                if path not in os.environ['PATH']:
                     os.environ['PATH'] += ";" + path
                     path_updated = True
                break
        
        self.mock_mode = False
        try:
            self.nm = nmap.PortScanner()
        except (nmap.PortScannerError, FileNotFoundError):
            print("WARNING: Nmap not found. Running in SIMULATION MODE.")
            self.mock_mode = True
            self.nm = None
            
        self.last_scan_result = {}
        self.is_scanning = False

    async def scan_network(self, network_range="192.168.1.0/24"):
        if self.is_scanning:
            return {"status": "busy", "message": "Scan already in progress"}
        
        self.is_scanning = True
        try:
            if self.mock_mode:
                # Simulate scan time
                await asyncio.sleep(2)
                return self._generate_mock_data()

            # Run scan in a separate thread to avoid blocking asyncio loop
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self.nm.scan, network_range, '22-443', '-sV -O')
            
            scan_data = []
            for host in self.nm.all_hosts():
                host_info = {
                    "ip": host,
                    "hostname": self.nm[host].hostname(),
                    "state": self.nm[host].state(),
                    "mac": self.nm[host]['addresses'].get('mac', 'Unknown'),
                    "os": self.nm[host].get('osmatch', [{'name': 'Unknown'}])[0]['name'],
                    "ports": []
                }
                
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        service = self.nm[host][proto][port]
                        host_info["ports"].append({
                            "port": port,
                            "protocol": proto,
                            "state": service['state'],
                            "service": service['name'],
                            "version": service['version']
                        })
                scan_data.append(host_info)

            self.last_scan_result = {
                "timestamp": datetime.now().isoformat(),
                "hosts": scan_data
            }
            return self.last_scan_result

        except Exception as e:
            return {"status": "error", "message": str(e)}
        finally:
            self.is_scanning = False

    def _generate_mock_data(self):
        self.last_scan_result = {
            "timestamp": datetime.now().isoformat(),
            "hosts": [
                {
                    "ip": "192.168.1.1", "hostname": "gateway", "state": "up", "mac": "AA:BB:CC:DD:EE:01", "os": "Linux 4.x", 
                    "ports": [{"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "nginx"}]
                },
                {
                    "ip": "192.168.1.105", "hostname": "shin-workstation", "state": "up", "mac": "AA:BB:CC:DD:EE:05", "os": "Windows 10", 
                    "ports": [{"port": 445, "protocol": "tcp", "state": "open", "service": "microsoft-ds", "version": ""}]
                },
                {
                    "ip": "192.168.1.200", "hostname": "iot-camera", "state": "up", "mac": "AA:BB:CC:DD:EE:99", "os": "Embedded Linux", 
                    "ports": [{"port": 554, "protocol": "tcp", "state": "open", "service": "rtsp", "version": ""}]
                }
            ]
        }
        return self.last_scan_result

    async def stream_scan_network(self, network_range="192.168.1.0/24"):
        """
        Yields events:
        {"type": "log", "message": "..."}
        {"type": "host_found", "ip": "..."}
        {"type": "result", "host": {...}}
        """
        if self.is_scanning:
            yield {"type": "log", "message": "Scan already in progress. Please wait."}
            return

        self.is_scanning = True
        yield {"type": "log", "message": f"Starting scan on {network_range}..."}

        try:
            if self.mock_mode:
                yield {"type": "log", "message": "Running in SIMULATION MODE (No Nmap found)"}
                await asyncio.sleep(1)
                yield {"type": "log", "message": "Simulating Ping Sweep..."}
                await asyncio.sleep(1)
                
                ips = ["192.168.1.1", "192.168.1.105", "192.168.1.200"]
                for ip in ips:
                    yield {"type": "host_found", "ip": ip}
                
                yield {"type": "log", "message": f"Host discovery complete. Found {len(ips)} hosts."}
                
                scan_data = [] # Keep accumulation for legacy 'last_result'
                
                for i, ip in enumerate(ips):
                    yield {"type": "log", "message": f"Deep scanning {ip} ({i+1}/{len(ips)})..."}
                    await asyncio.sleep(1.5)
                    
                    # Generate mock host data
                    host_info = {
                        "ip": ip,
                        "hostname": f"simulated-{ip.split('.')[-1]}",
                        "state": "up",
                        "mac": f"AA:BB:CC:DD:EE:{ip.split('.')[-1]}",
                        "os": "Windows" if "105" in ip else "Linux",
                        "ports": [{"port": 80, "protocol": "tcp", "service": "http", "state": "open", "version": "fake-1.0"}]
                    }
                    
                    yield {"type": "result", "host": host_info}
                    scan_data.append(host_info)

                self.last_scan_result = { "timestamp": datetime.now().isoformat(), "hosts": scan_data }
                yield {"type": "log", "message": "Scan complete."}
                return

            # --- Real Nmap Logic ---
            
            # Phase 1: Discovery (Ping Scan)
            yield {"type": "log", "message": "Phase 1: Discovery (Ping Scan)..."}
            loop = asyncio.get_event_loop()
            
            # We use a new PortScanner instance for thread safety if needed, or reuse self.nm carefully
            nm_ping = nmap.PortScanner()
            await loop.run_in_executor(None, nm_ping.scan, network_range, None, '-sn')
            
            active_hosts = nm_ping.all_hosts()
            if not active_hosts:
                yield {"type": "log", "message": "No hosts found."}
                self.is_scanning = False
                return

            yield {"type": "log", "message": f"Discovery complete. Found {len(active_hosts)} active hosts."}
            for h in active_hosts:
                 yield {"type": "host_found", "ip": h}

            # Phase 2: Deep Scan (Sequential)
            scan_data = []
            
            for i, ip in enumerate(active_hosts):
                yield {"type": "log", "message": f"Scanning {ip} ({i+1}/{len(active_hosts)})..."}
                
                # Scan individual host
                nm_detail = nmap.PortScanner()
                await loop.run_in_executor(None, nm_detail.scan, ip, '22-1000', '-sV -O --version-light') 
                
                if ip not in nm_detail.all_hosts():
                    yield {"type": "log", "message": f"Could not get details for {ip}"}
                    continue
                    
                host = nm_detail[ip]
                host_info = {
                    "ip": ip,
                    "hostname": host.hostname(),
                    "state": host.state(),
                    "mac": host['addresses'].get('mac', 'Unknown'),
                    "os": host.get('osmatch')[0]['name'] if host.get('osmatch') else 'Unknown',
                    "ports": []
                }
                
                for proto in host.all_protocols():
                    ports = host[proto].keys()
                    for port in ports:
                        service = host[proto][port]
                        host_info["ports"].append({
                            "port": port,
                            "protocol": proto,
                            "state": service['state'],
                            "service": service['name'],
                            "version": service['version']
                        })
                
                # Yield result immediately
                yield {"type": "result", "host": host_info}
                scan_data.append(host_info)
            
            # Update last result for legacy pollers
            self.last_scan_result = {
                "timestamp": datetime.now().isoformat(),
                "hosts": scan_data
            }
            yield {"type": "log", "message": "All tasks finished."}

        except Exception as e:
            yield {"type": "log", "message": f"Error: {e}"}
        finally:
            self.is_scanning = False

    def get_last_result(self):
        return self.last_scan_result

scanner = NetworkScanner()
