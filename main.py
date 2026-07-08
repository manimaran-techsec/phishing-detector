import threading
from app.dashboard import create_app
from app.modules.scanner import run_monitor

app = create_app()

if __name__ == "__main__":
    # Start email monitor in background thread
    monitor_thread = threading.Thread(
        target=run_monitor,
        args=(app,),
        kwargs={"interval": 60},
        daemon=True
    )
    monitor_thread.start()

    # Start Flask dashboard
    app.run(host="0.0.0.0", port=5000, debug=False)
