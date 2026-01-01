import webview
import threading
import uvicorn
import sys
import os
from main import app

def start_server():
    # Run uvicorn programmatically
    uvicorn.run(app, host="127.0.0.1", port=44444, log_level="error")

if __name__ == '__main__':
    # Verify frontend exists
    frontend_dist = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend", "dist")
    if not os.path.exists(frontend_dist):
        print("ERROR: Frontend build not found! Run 'npm run build' in frontend/ first.")
        sys.exit(1)

    # Start backend in a thread
    t = threading.Thread(target=start_server)
    t.daemon = True
    t.start()
    
    # Create windows
    window = webview.create_window('Shin Network Defense', 'http://127.0.0.1:44444', 
                                   width=1200, height=800, background_color='#050505')
    
    webview.start()
