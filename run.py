"""
TraceGuard Launcher Script
Run this script to start the TraceGuard web server and access the platform.
"""
import uvicorn
import webbrowser
import threading
import time

def open_browser():
    time.sleep(1.2)
    webbrowser.open("http://127.0.0.1:8000")

if __name__ == "__main__":
    print("=" * 70)
    print("  TRACEGUARD - Web Attack Path Reconstruction System")
    print("  Server starting at: http://127.0.0.1:8000")
    print("  Press Ctrl+C to terminate.")
    print("=" * 70)
    
    # Optional auto-open browser in background thread
    threading.Thread(target=open_browser, daemon=True).start()
    
    uvicorn.run("backend.app:app", host="127.0.0.1", port=8000, reload=False, log_level="info")
