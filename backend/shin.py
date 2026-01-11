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
import ipaddress
import json
from datetime import datetime
from tkinter import filedialog

# Dependencies
import nmap
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import shodan

# --- Theme Config ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green") # We will override specific colors manually

COLOR_BG_MAIN = "#050510"    # Deep Dark Navy
COLOR_WIN_BG  = "#0F0F2D"    # Navy
COLOR_WIN_BAR = "#C0C0C0"    # Light Grey
COLOR_TEXT_BAR = "#000000"   # Black for contrast on grey
COLOR_ACCENT  = "#00ff00"    # Matrix Green

# --- Helpers ---
def get_icon_for_os(os_name):
    os_name = os_name.lower()
    if "windows" in os_name: return "💻"
    if "linux" in os_name: return "🖥️"
    if "android" in os_name or "ios" in os_name: return "📱"
    if "embedded" in os_name: return "📹"
    return "❓"

def normalize_os(os_string):
    if not os_string: return "Unknown"
    s = os_string.lower()
    if "windows 10" in s: return "Windows 10"
    if "windows 11" in s: return "Windows 11"
    if "windows server" in s: return "Windows Server"
    if "linux" in s and "kernel" in s: return "Linux"
    return os_string[:25] + "..." if len(os_string) > 25 else os_string

# --- CORE LOGIC CLASSES (Same as V2, minimal changes) ---

class IntelService:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("SHODAN_API_KEY")
        self.api = shodan.Shodan(self.api_key) if self.api_key else None
    def check_ip(self, ip_address):
        if not self.api: return {"error": "No API Key"}
        try: return self.api.host(ip_address)
        except Exception as e: return {"error": str(e)}

class PacketSniffer:
    def __init__(self):
        self.running = False
        self.packet_queue = queue.Queue()
        self.stats = {
            "total_packets": 0, "external_requests": 0, "ip_traffic": {},
            "internal_nets": [ipaddress.ip_network(n) for n in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]]
        }
    def is_internal(self, ip_str):
        try:
            addr = ipaddress.ip_address(ip_str)
            for net in self.stats["internal_nets"]:
                if addr in net: return True
            return False
        except: return False
    def process_packet(self, packet):
        if not self.running: return
        try:
            if IP in packet:
                src, dst = packet[IP].src, packet[IP].dst
                proto = {6:'TCP', 17:'UDP', 1:'ICMP'}.get(packet[IP].proto, str(packet[IP].proto))
                self.stats["total_packets"] += 1
                now = datetime.now().strftime("%H:%M:%S")
                for ip in [src, dst]:
                    if ip not in self.stats["ip_traffic"]:
                        self.stats["ip_traffic"][ip] = {"in": 0, "out": 0, "protocols": set(), "last_seen": now}
                    self.stats["ip_traffic"][ip]["protocols"].add(proto)
                    self.stats["ip_traffic"][ip]["last_seen"] = now
                self.stats["ip_traffic"][src]["out"] += 1
                self.stats["ip_traffic"][dst]["in"] += 1
                is_ext = self.is_internal(src) and not self.is_internal(dst)
                if is_ext: self.stats["external_requests"] += 1
                
                info = f"{packet[TCP].sport}->{packet[TCP].dport}" if TCP in packet else packet.summary()
                self.packet_queue.put({
                    "src": src, "dst": dst, "proto": proto, "info": info, "time": now, "ext": is_ext
                })
        except: pass
    def start(self):
        self.running = True
        threading.Thread(target=self._run, daemon=True).start()
    def _run(self):
        try: sniff(prn=self.process_packet, store=0)
        except: self._mock()
    def _mock(self):
        while self.running:
            src = f"192.168.1.{random.randint(2,254)}"
            dst = random.choice([f"10.0.0.{random.randint(1,50)}", "8.8.8.8"])
            self.process_packet(IP(src=src, dst=dst)/TCP(sport=random.randint(1024,65535), dport=80))
            time.sleep(random.uniform(0.1, 0.5))

class NetworkScanner:
    def __init__(self):
        self.mock = True
        try:
            nmap_paths = [r"C:\Program Files (x86)\Nmap", r"C:\Program Files\Nmap"]
            for p in nmap_paths:
                if os.path.exists(os.path.join(p, "nmap.exe")) and p not in os.environ['PATH']:
                     os.environ['PATH'] += ";" + p
            self.nm = nmap.PortScanner()
            self.mock = False
        except: pass
    
    async def scan(self, target):
        yield {"type": "log", "msg": f"Starting scan on {target}..."}
        if self.mock:
            await asyncio.sleep(1)
            hosts = [
                {"ip": "192.168.1.1", "name": "Gateway", "os": "Linux", "mac": "00:11:22:33:44:01", "ports": [{"port": 80, "svc": "http"}]},
                {"ip": "192.168.1.100", "name": "PC-Admin", "os": "Windows 11", "mac": "AA:BB:CC:DD:EE:FF", "ports": [{"port": 3389, "svc": "rdp"}, {"port": 445, "svc": "smb"}]},
                {"ip": "192.168.1.105", "name": "Server-Dev", "os": "Linux Ubuntu", "mac": "11:22:33:44:55:66", "ports": [{"port": 22, "svc": "ssh"}, {"port": 8080, "svc": "http-alt"}]}
            ]
            for h in hosts:
                yield {"type": "host", "data": h}
                yield {"type": "log", "msg": f"Found {h['ip']} ({h['name']})"}
                await asyncio.sleep(0.5)
            yield {"type": "log", "msg": "Scan Complete."}
            return

        loop = asyncio.get_event_loop()
        nm = nmap.PortScanner()
        await loop.run_in_executor(None, nm.scan, target, None, '-sn') # Ping stats
        live = nm.all_hosts()
        for h in live: yield {"type": "log", "msg": f"Host active: {h}"}

        for host in live:
            nm_det = nmap.PortScanner()
            await loop.run_in_executor(None, nm_det.scan, host, '1-1000', '-sV -O --version-light')
            if host not in nm_det.all_hosts(): continue
            d = nm_det[host]
            os_match = d.get('osmatch', [])
            os_name = os_match[0]['name'] if os_match else "Unknown"
            ports = []
            for proto in d.all_protocols():
                for p in d[proto]:
                    ports.append({"port": p, "svc": d[proto][p]['name']})
            
            yield {"type": "host", "data": {
                "ip": host, "name": d.hostname(), "mac": d['addresses'].get('mac', ''),
                "os": normalize_os(os_name), "ports": ports
            }}
        yield {"type": "log", "msg": "Scan Complete."}

# --- GUI: Draggable Windows ---

class DraggableWindow(ctk.CTkFrame):
    def __init__(self, parent, title, x, y, width, height):
        super().__init__(parent, width=width, height=height, corner_radius=0, fg_color=COLOR_WIN_BG, border_width=1, border_color="#333")
        self.place(x=x, y=y)
        
        # Header Bar
        self.header = ctk.CTkFrame(self, height=30, corner_radius=0, fg_color=COLOR_WIN_BAR)
        self.header.pack(fill="x", side="top")
        
        self.label = ctk.CTkLabel(self.header, text=title, text_color=COLOR_TEXT_BAR, font=("Roboto", 12, "bold"))
        self.label.pack(side="left", padx=10)
        
        # Fake Controls
        ctk.CTkLabel(self.header, text="✖", text_color="red").pack(side="right", padx=10)
        ctk.CTkLabel(self.header, text="🗖", text_color="#333").pack(side="right", padx=5)
        ctk.CTkLabel(self.header, text="🗕", text_color="#333").pack(side="right", padx=5)

        # Drag Logic
        self.header.bind("<Button-1>", self.start_drag)
        self.header.bind("<B1-Motion>", self.do_drag)
        self.label.bind("<Button-1>", self.start_drag)
        self.label.bind("<B1-Motion>", self.do_drag)
        
        self.content = ctk.CTkFrame(self, fg_color="transparent")
        self.content.pack(fill="both", expand=True, padx=5, pady=5)

    def start_drag(self, event):
        self.x = event.x
        self.y = event.y

    def do_drag(self, event):
        dx = event.x - self.x
        dy = event.y - self.y
        new_x = self.winfo_x() + dx
        new_y = self.winfo_y() + dy
        self.place(x=new_x, y=new_y)
        self.lift() # Bring to front

class ShinDesktop(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SHIN DEFENSE OS")
        self.geometry("1600x900")
        self.configure(fg_color=COLOR_BG_MAIN)
        
        self.scanner = NetworkScanner()
        self.sniffer = PacketSniffer()
        self.sniffer.start()
        
        self.scan_results = [] # Store for saving

        # --- WINDOW 1: COMMAND CENTER (Scanner) ---
        self.win_cmd = DraggableWindow(self, "COMMAND CENTER", 50, 50, 400, 600)
        
        self.btn_scan = ctk.CTkButton(self.win_cmd.content, text="INITIATE SWEEP", command=self.run_scan, fg_color="green", hover_color="darkgreen")
        self.btn_scan.pack(fill="x", pady=5)
        
        self.btn_save = ctk.CTkButton(self.win_cmd.content, text="SAVE SWEEP", command=self.save_sweep, fg_color="#444", hover_color="#555")
        self.btn_save.pack(fill="x", pady=5)

        self.console = ctk.CTkTextbox(self.win_cmd.content, height=100, font=("Consolas", 10), text_color="#00ff00")
        self.console.pack(fill="x", pady=5)
        self.log("System Ready.")
        
        self.device_list = ctk.CTkScrollableFrame(self.win_cmd.content, label_text="ASSETS DETECTED")
        self.device_list.pack(fill="both", expand=True)

        # --- WINDOW 2: TRAFFIC MONITOR ---
        self.win_sniff = DraggableWindow(self, "TRAFFIC MONITOR", 500, 50, 500, 400)
        
        self.stats_lbl = ctk.CTkLabel(self.win_sniff.content, text="PKTS: 0 | EXT: 0", font=("Consolas", 12, "bold"))
        self.stats_lbl.pack(pady=5)
        
        self.sniff_box = ctk.CTkTextbox(self.win_sniff.content, font=("Consolas", 10))
        self.sniff_box.pack(fill="both", expand=True)

        # --- WINDOW 3: INSPECTOR ---
        self.win_insp = DraggableWindow(self, "ASSET INSPECTOR", 500, 480, 500, 300)
        self.insp_lbl = ctk.CTkLabel(self.win_insp.content, text="SELECT ASSET", font=("Roboto", 16))
        self.insp_lbl.pack(pady=10)
        self.insp_detail = ctk.CTkScrollableFrame(self.win_insp.content)
        self.insp_detail.pack(fill="both", expand=True)

        self.update_loops()

    def log(self, msg):
        self.console.insert("end", f"> {msg}\n")
        self.console.see("end")

    def run_scan(self):
        self.btn_scan.configure(state="disabled")
        self.log("Scanning...")
        for w in self.device_list.winfo_children(): w.destroy()
        self.scan_results = []
        threading.Thread(target=self._scan_thread, daemon=True).start()

    def _scan_thread(self):
        asyncio.run(self._scan_async())

    async def _scan_async(self):
        async for evt in self.scanner.scan("192.168.1.0/24"):
            self.after(0, self.handle_evt, evt)

    def handle_evt(self, evt):
        if evt['type'] == 'log':
            self.log(evt['msg'])
            if "Complete" in evt['msg']: self.btn_scan.configure(state="normal")
        elif evt['type'] == 'host':
            self.render_host(evt['data'])
            self.scan_results.append(evt['data'])

    def render_host(self, h):
        f = ctk.CTkFrame(self.device_list, fg_color="#222")
        f.pack(fill="x", pady=2)
        btn = ctk.CTkButton(f, text="🔍", width=30, command=lambda: self.inspect(h))
        btn.pack(side="right", padx=5)
        ctk.CTkLabel(f, text=f"{get_icon_for_os(h['os'])} {h['ip']}", font=("Consolas", 12, "bold")).pack(side="left", padx=5)
        ctk.CTkLabel(f, text=h['os'], text_color="gray", font=("Arial", 10)).pack(side="left", padx=5)

    def inspect(self, h):
        self.insp_lbl.configure(text=f"{h['ip']} ({h['name']})")
        for w in self.insp_detail.winfo_children(): w.destroy()
        
        # Profile
        stats = self.sniffer.stats["ip_traffic"].get(h['ip'], {})
        if stats:
             ctk.CTkLabel(self.insp_detail, text=f"TRAFFIC: {stats.get('in',0)} IN / {stats.get('out',0)} OUT", text_color="cyan").pack(anchor="w")
        
        # Ports
        for p in h['ports']:
            row = ctk.CTkFrame(self.insp_detail, fg_color="transparent")
            row.pack(fill="x")
            ctk.CTkLabel(row, text=f"{p['port']}/{p['svc']}", anchor="w").pack(side="left")
            cmd = self.get_cmd(h['ip'], p['port'], p['svc'])
            if cmd: ctk.CTkButton(row, text="OPEN", width=50, height=20, command=cmd).pack(side="right")

    def get_cmd(self, ip, port, svc):
        if port in [80, 443] or "http" in svc: return lambda: webbrowser.open(f"http://{ip}:{port}")
        if port == 22 or "ssh" in svc: return lambda: subprocess.Popen(f"start cmd /k ssh anonymous@{ip}", shell=True)
        if port == 3389: return lambda: subprocess.Popen(f"mstsc /v:{ip}", shell=True)
        return None

    def save_sweep(self):
        if not self.scan_results: return self.log("No data to save.")
        try:
            os.makedirs("saved_sweeps", exist_ok=True)
            fname = f"saved_sweeps/sweep_{int(time.time())}.json"
            with open(fname, "w") as f: json.dump(self.scan_results, f, indent=2)
            self.log(f"Saved to {fname}")
        except Exception as e: self.log(f"Save failed: {e}")

    def update_loops(self):
        # Sniffer UI
        try:
            while True:
                pkt = self.sniffer.packet_queue.get_nowait()
                self.sniff_box.insert("0.0", f"[{pkt['proto']}] {pkt['src']}->{pkt['dst']}\n")
                if float(self.sniff_box.index("end")) > 100: self.sniff_box.delete("100.0", "end")
        except: pass
        
        s = self.sniffer.stats
        self.stats_lbl.configure(text=f"PKTS: {s['total_packets']} | EXT: {s['external_requests']}")
        
        self.after(200, self.update_loops)

if __name__ == "__main__":
    ShinDesktop().mainloop()
