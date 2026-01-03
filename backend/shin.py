import customtkinter as ctk
import threading
import asyncio
import queue
import os
import random
import time
import webbrowser
import subprocess
import platform
from datetime import datetime

# Dependencies
import nmap
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import shodan

# --- Aesthetic Config ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")

# --- ICONS / ASSETS (Unicode placeholders for simplicity) ---
ICON_PC = "💻"
ICON_SERVER = "🖥️"
ICON_MOBILE = "📱"
ICON_IOT = "📹"
ICON_UNKNOWN = "❓"

def get_icon_for_os(os_name):
    os_name = os_name.lower()
    if "windows" in os_name: return ICON_PC
    if "linux" in os_name: return ICON_SERVER
    if "android" in os_name or "ios" in os_name: return ICON_MOBILE
    if "embedded" in os_name: return ICON_IOT
    return ICON_UNKNOWN

def normalize_os(os_string):
    if not os_string: return "Unknown"
    s = os_string.lower()
    if "windows 10" in s: return "Windows 10"
    if "windows 11" in s: return "Windows 11"
    if "windows server" in s: return "Windows Server"
    if "linux" in s and "kernel" in s: return "Linux"
    if "android" in s: return "Android"
    return os_string[:20] + "..." if len(os_string) > 20 else os_string

# --- MODULE: INTEL (Shodan) ---
class IntelService:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("SHODAN_API_KEY")
        self.api = shodan.Shodan(self.api_key) if self.api_key else None

    def check_ip(self, ip_address):
        if not self.api:
            return {"error": "Shodan API key not configured"}
        try:
            host = self.api.host(ip_address)
            return host
        except shodan.APIError as e:
            return {"error": str(e)}

# --- MODULE: SNIFFER (Scapy) ---
class PacketSniffer:
    def __init__(self):
        self.running = False
        self.packet_queue = queue.Queue()
        
    def process_packet(self, packet):
        if not self.running: return
        try:
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                len_pkt = len(packet)
                proto_num = packet[IP].proto
                proto_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
                proto = proto_map.get(proto_num, str(proto_num))
                
                info = "Unknown"
                if TCP in packet:
                    info = f"{packet[TCP].sport} -> {packet[TCP].dport} [TCP]"
                elif UDP in packet:
                    info = f"{packet[UDP].sport} -> {packet[UDP].dport} [UDP]"
                else:
                    info = packet.summary()

                self.packet_queue.put({
                    "src": src, "dst": dst, "protocol": proto,
                    "length": len_pkt, "info": info,
                    "timestamp": datetime.now().strftime("%H:%M:%S")
                })
        except Exception:
            pass

    def start_sniffing(self):
        self.running = True
        t = threading.Thread(target=self._run_sniff, daemon=True)
        t.start()

    def _run_sniff(self):
        try:
            sniff(prn=self.process_packet, store=0)
        except Exception as e:
            print(f"Sniffer Error: {e}. Switching to Mock.")
            self._run_mock_sniff()

    def _run_mock_sniff(self):
        while self.running:
            self.packet_queue.put({
                "src": f"192.168.1.{random.randint(2,254)}",
                "dst": f"10.0.0.{random.randint(2,254)}",
                "protocol": random.choice(["TCP", "UDP"]),
                "length": random.randint(64, 1500),
                "info": f"Simulated traffic {random.randint(1024,65535)} -> {random.choice([80,443,22,445])}",
                "timestamp": datetime.now().strftime("%H:%M:%S")
            })
            time.sleep(random.uniform(0.1, 0.5))

    def stop_sniffing(self):
        self.running = False

# --- MODULE: SCANNER (Nmap) ---
class NetworkScanner:
    def __init__(self):
        # Auto-detect Nmap in common Windows locations
        nmap_paths = [r"C:\Program Files (x86)\Nmap", r"C:\Program Files\Nmap"]
        for p in nmap_paths:
            if os.path.exists(os.path.join(p, "nmap.exe")) and p not in os.environ['PATH']:
                os.environ['PATH'] += ";" + p

        self.mock_mode = False
        try:
            self.nm = nmap.PortScanner()
        except:
            self.mock_mode = True
            self.nm = None
        self.is_scanning = False

    async def stream_scan_network(self, network_range="192.168.1.0/24"):
        if self.is_scanning:
            yield {"type": "log", "message": "Busy."}
            return
        self.is_scanning = True
        yield {"type": "log", "message": f"Initializing sweep on {network_range}..."}

        if self.mock_mode:
            # Enhanced Mock Data
            yield {"type": "log", "message": "[SIMULATION] Running in Mock Mode (Nmap not found)."}
            await asyncio.sleep(1)
            mock_hosts = [
                {"ip": "192.168.1.1", "name": "Gateway", "os": "Linux (Router)", "mac": "00:11:22:33:44:01", 
                 "ports": [{"port": 80, "service": "http", "ver": "nginx"}, {"port": 443, "service": "https", "ver": ""}]},
                {"ip": "192.168.1.50", "name": "LivingRoom-TV", "os": "Android TV", "mac": "AA:BB:CC:00:11:22", 
                 "ports": [{"port": 8008, "service": "http", "ver": "Chromecast"}, {"port": 5555, "service": "adb", "ver": ""}]},
                {"ip": "192.168.1.100", "name": "DESKTOP-MAIN", "os": "Windows 11 Pro", "mac": "DD:EE:FF:00:11:22", 
                 "ports": [{"port": 135, "service": "msrpc", "ver": ""}, {"port": 445, "service": "microsoft-ds", "ver": ""}, {"port": 3389, "service": "ms-wbt-server", "ver": ""}]},
                {"ip": "192.168.1.105", "name": "ubuntu-server", "os": "Linux 5.4", "mac": "11:22:33:44:55:66", 
                 "ports": [{"port": 22, "service": "ssh", "ver": "OpenSSH 8.2"}, {"port": 8080, "service": "http-proxy", "ver": ""}]}
            ]
            for h in mock_hosts:
                yield {"type": "host_found", "ip": h['ip']}
            
            yield {"type": "log", "message": f"Discovery: Found {len(mock_hosts)} hosts."}
            
            for h in mock_hosts:
                yield {"type": "log", "message": f"Fingerprinting {h['ip']}..."}
                await asyncio.sleep(0.8)
                h_norm = h.copy()
                h_norm['os'] = normalize_os(h_norm['os'])
                yield {"type": "result", "host": h_norm}
            
            yield {"type": "log", "message": "Mock Scan Complete."}
            self.is_scanning = False
            return

        # Real Scan
        try:
            loop = asyncio.get_event_loop()
            yield {"type": "log", "message": "Phase 1: Ping Sweep (Discovery)..."}
            nm = nmap.PortScanner()
            await loop.run_in_executor(None, nm.scan, network_range, None, '-sn')
            hosts = nm.all_hosts()
            yield {"type": "log", "message": f"Discovery: Found {len(hosts)} active hosts."}
            
            for h in hosts: yield {"type": "host_found", "ip": h}

            for i, ip in enumerate(hosts):
                yield {"type": "log", "message": f"Fingerprinting {ip} ({i+1}/{len(hosts)})..."}
                nm_det = nmap.PortScanner()
                # -O for OS, -sV for versions
                await loop.run_in_executor(None, nm_det.scan, ip, '1-1000', '-sV -O --version-light')
                
                if ip not in nm_det.all_hosts(): continue
                
                data = nm_det[ip]
                # Normalize OS
                # Normalize OS
                os_matches = data.get('osmatch')
                if os_matches and len(os_matches) > 0:
                    raw_os = os_matches[0]['name']
                else:
                    raw_os = 'Unknown'
                
                # Normalize Ports
                ports = []
                for proto in data.all_protocols():
                   for p in data[proto].keys():
                       svc = data[proto][p]
                       ports.append({
                           "port": p, "service": svc['name'], "ver": svc['version']
                       })

                yield {"type": "result", "host": {
                    "ip": ip,
                    "name": data.hostname(),
                    "mac": data['addresses'].get('mac', 'Unknown'),
                    "os": normalize_os(raw_os),
                    "ports": ports
                }}
            
            yield {"type": "log", "message": "Scan Complete."}
        
        except Exception as e:
            yield {"type": "log", "message": f"Error: {e}"}
        finally:
            self.is_scanning = False

# --- GUI ---
class ScanThread(threading.Thread):
    def __init__(self, scanner, cb):
        super().__init__(daemon=True)
        self.scanner, self.cb = scanner, cb
    def run(self):
        asyncio.run(self._pipeline())
    async def _pipeline(self):
        async for evt in self.scanner.stream_scan_network():
            self.cb(evt)

class ShinApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.scanner = NetworkScanner()
        self.sniffer = PacketSniffer()
        self.intel = IntelService()
        self.setup_ui()
        
    def setup_ui(self):
        self.title("SHIN DEFENSE - TACTICAL DASHBOARD")
        self.geometry("1400x900")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # 1. Sidebar (Controls)
        self.sidebar = ctk.CTkFrame(self, width=280, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(3, weight=1)
        
        ctk.CTkLabel(self.sidebar, text="SHIN DEFENSE", font=("Roboto", 22, "bold")).grid(row=0, column=0, pady=(30,10))
        ctk.CTkLabel(self.sidebar, text="V2.0 NATIVE", text_color="gray").grid(row=1, column=0, pady=(0,20))
        
        self.btn_scan = ctk.CTkButton(self.sidebar, text="INITIATE SWEEP", command=self.run_scan, height=40, font=("Roboto", 14, "bold"))
        self.btn_scan.grid(row=2, column=0, padx=20, pady=10, sticky="ew")
        
        self.log_box = ctk.CTkTextbox(self.sidebar, font=("Consolas", 11), text_color="#00ff00")
        self.log_box.grid(row=3, column=0, padx=10, pady=10, sticky="nsew")
        self.log(">> SYSTEM READY.")

        # 2. Main Area (Device List)
        self.main_area = ctk.CTkFrame(self, fg_color="transparent")
        self.main_area.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_area.grid_rowconfigure(1, weight=1)
        self.main_area.grid_columnconfigure(0, weight=1)
        
        ctk.CTkLabel(self.main_area, text="NETWORK TOPOLOGY", font=("Roboto", 18, "bold")).grid(row=0, column=0, sticky="w", pady=(0,10))
        self.device_list = ctk.CTkScrollableFrame(self.main_area, label_text="DETECTED ASSETS")
        self.device_list.grid(row=1, column=0, sticky="nsew")
        self.device_list.grid_columnconfigure(0, weight=1)

        # 3. Right Panel (Details & Sniffer)
        self.right_panel = ctk.CTkFrame(self, width=400, corner_radius=0)
        self.right_panel.grid(row=0, column=2, sticky="nsew")
        self.right_panel.grid_rowconfigure(1, weight=1) # Sniffer expands
        
        # Details Header
        self.details_frame = ctk.CTkFrame(self.right_panel, fg_color="transparent")
        self.details_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=20)
        ctk.CTkLabel(self.details_frame, text="TARGET DETAILS", font=("Roboto", 16, "bold")).pack(pady=5)
        
        self.details_scroll = ctk.CTkScrollableFrame(self.right_panel, height=300, label_text="SELECT TARGET")
        self.details_scroll.grid(row=1, column=0, sticky="ew", padx=10, pady=5)
        
        # Sniffer
        ctk.CTkLabel(self.right_panel, text="LIVE TRAFFIC CAPTURE", font=("Roboto", 16, "bold")).grid(row=2, column=0, pady=(20,5))
        self.sniffer_box = ctk.CTkTextbox(self.right_panel, font=("Consolas", 10), height=300)
        self.sniffer_box.grid(row=3, column=0, padx=10, pady=10, sticky="nsew")
        
        # Start Sniffer
        self.sniffer.start_sniffing()
        self.after(100, self.update_sniffer)

    def log(self, msg):
        self.log_box.insert("end", f"> {msg}\n")
        self.log_box.see("end")

    def run_scan(self):
        self.btn_scan.configure(state="disabled", text="SCANNING...")
        # Clear UI list
        for widget in self.device_list.winfo_children(): widget.destroy()
        
        ScanThread(self.scanner, self.handle_scan_event).start()

    def handle_scan_event(self, evt):
        self.after(0, self._process_evt, evt)

    def _process_evt(self, evt):
        if evt['type'] == 'log':
            self.log(evt['message'])
            if "Complete" in evt['message']:
                self.btn_scan.configure(state="normal", text="INITIATE SWEEP")
        elif evt['type'] == 'result':
            self.render_device_card(evt['host'])

    def render_device_card(self, host):
        card = ctk.CTkFrame(self.device_list)
        card.pack(fill="x", padx=5, pady=5)
        
        icon = get_icon_for_os(host['os'])
        
        # Icon
        ctk.CTkLabel(card, text=icon, font=("Arial", 30)).pack(side="left", padx=15, pady=10)
        
        # Text Info
        info_frame = ctk.CTkFrame(card, fg_color="transparent")
        info_frame.pack(side="left", fill="both", expand=True)
        
        ctk.CTkLabel(info_frame, text=host['ip'], font=("Roboto", 14, "bold"), anchor="w").pack(fill="x")
        ctk.CTkLabel(info_frame, text=f"{host['name']} | {host['os']}", text_color="gray", anchor="w").pack(fill="x")
        
        # Select Button (Invisible, making entire card clickable is harder in CTk, so using explicit button or binding)
        # Binding acts weird on frames sometimes. Let's add a "INSPECT" button on right.
        btn = ctk.CTkButton(card, text="INSPECT", width=80, command=lambda h=host: self.show_details(h))
        btn.pack(side="right", padx=15)
    
    def show_details(self, host):
        # Clear details
        for w in self.details_scroll.winfo_children(): w.destroy()
        
        # Header Info
        ctk.CTkLabel(self.details_scroll, text=f"{host['ip']}", font=("Roboto", 20, "bold")).pack(anchor="w", pady=5)
        ctk.CTkLabel(self.details_scroll, text=f"MAC: {host['mac']}\nOS: {host['os']}", justify="left", text_color="gray").pack(anchor="w", pady=5)
        
        ctk.CTkLabel(self.details_scroll, text="OPEN PORTS & ACTIONS", font=("Roboto", 14, "bold"), text_color="#00ff00").pack(anchor="w", pady=(15,5))
        
        for p in host['ports']:
            row = ctk.CTkFrame(self.details_scroll, fg_color="#1a1a1a")
            row.pack(fill="x", pady=2)
            
            txt = f"{p['port']}/{p['service']} ({p.get('ver','')})"
            ctk.CTkLabel(row, text=txt, anchor="w").pack(side="left", padx=10, pady=5)
            
            # Action Button based on service
            cmd = self.get_action_for_port(host['ip'], p['port'], p['service'])
            if cmd:
                ctk.CTkButton(row, text="OPEN", width=60, height=25, command=cmd).pack(side="right", padx=5)

    def get_action_for_port(self, ip, port, service):
        port = int(port)
        svc = service.lower()
        
        if port in [80, 8080, 8000, 8008] or "http" in svc:
            return lambda: webbrowser.open(f"http://{ip}:{port}")
        
        if port in [443, 8443] or "https" in svc:
            return lambda: webbrowser.open(f"https://{ip}:{port}")
            
        if port == 22 or "ssh" in svc:
            return lambda: self.open_terminal(f"ssh anonymous@{ip}")
            
        if port == 21 or "ftp" in svc:
            return lambda: self.open_explorer(f"ftp://{ip}")
            
        if port == 3389 or "ms-wbt" in svc:
             # RDP (Windows only usually)
             return lambda: subprocess.Popen(f"mstsc /v:{ip}", shell=True)

        return None

    def open_terminal(self, cmd):
        # Platform specific terminal opener
        if platform.system() == "Windows":
             subprocess.Popen(f"start cmd /k {cmd}", shell=True)
        else:
             # Linux logic could go here
             pass

    def open_explorer(self, path):
         if platform.system() == "Windows":
             os.startfile(path)

    def update_sniffer(self):
        try:
            while True:
                pkt = self.sniffer.packet_queue.get_nowait()
                self.sniffer_box.insert("0.0", f"[{pkt['protocol']}] {pkt['src']} > {pkt['dst']}\n")
                if float(self.sniffer_box.index("end")) > 500:
                    self.sniffer_box.delete("500.0", "end")
        except: pass
        self.after(200, self.update_sniffer)

if __name__ == "__main__":
    app = ShinApp()
    app.mainloop()
