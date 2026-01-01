from fastapi import FastAPI, WebSocket, BackgroundTasks, HTTPException, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from scanner import scanner
from sniffer import sniffer
from intel import intel_service
import asyncio
import json

from fastapi.staticfiles import StaticFiles
import os

app = FastAPI(title="Shin Network Defense")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files from frontend/dist
frontend_dist_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend", "dist")
if os.path.exists(frontend_dist_path):
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dist_path, "assets")), name="assets")
    # We will serve index.html at root, but capturing other paths is tricky with SPA.
    # Often easier to mount root to StaticFiles using html=True if API is separate router.
    # Let's keep API routes and mount static at root as fallback?
    # Or just Serve index.html explicitly at root.
    
    @app.get("/")
    async def serve_spa():
        return FileResponse(os.path.join(frontend_dist_path, "index.html"))
    
    # Catch-all for React Router but we don't really use it?
else:
    print(f"WARNING: Frontend build not found at {frontend_dist_path}")

# Background task for periodic scanning
async def periodic_scan():
    while True:
        await asyncio.sleep(300) # 5 minutes
        print("Starting periodic scan...")
        await scanner.scan_network()

@app.on_event("startup")
async def startup_event():
    loop = asyncio.get_event_loop()
    # Start sniffer
    sniffer.start_sniffing(loop)
    # Start periodic scan loop
    asyncio.create_task(periodic_scan())

@app.on_event("shutdown")
def shutdown_event():
    sniffer.stop_sniffing()

# @app.get("/")
# def read_root():
#     return {"status": "Shin Backend Active"}

@app.post("/api/scan")
async def run_scan(background_tasks: BackgroundTasks):
    if scanner.is_scanning:
        return {"status": "busy", "message": "Scan in progress"}
    
    # Run scan in background to return immediate response
    background_tasks.add_task(scanner.scan_network)
    return {"status": "accepted", "message": "Scan started"}

@app.get("/api/scan/last")
def get_last_scan():
    return scanner.get_last_result()

@app.websocket("/ws/scan")
async def scan_websocket(websocket: WebSocket):
    await websocket.accept()
    try:
        # Wait for "START" command? Or just start immediately?
        # Let's wait for a message to kick it off, so multiple clients don't trigger multiple scans by just connecting.
        data = await websocket.receive_text()
        if data == "START_SCAN":
            async for event in scanner.stream_scan_network():
                await websocket.send_json(event)
        else:
             await websocket.send_json({"type": "log", "message": "Invalid command"})
    except WebSocketDisconnect:
        print("Scan Client disconnected")
    except Exception as e:
        print(f"WS Scan Error: {e}")


@app.get("/api/shodan/{ip}")
def check_ip(ip: str):
    return intel_service.check_ip(ip)

@app.websocket("/ws/traffic")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            # Get packet from sniffer queue
            pkt = await sniffer.packet_queue.get()
            await websocket.send_json(pkt)
    except WebSocketDisconnect:
        print("Client disconnected")
    except Exception as e:
        print(f"WS Error: {e}")
