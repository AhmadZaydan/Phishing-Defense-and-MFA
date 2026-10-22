"""Start both fictional websites. Run from this folder with: python run_demo.py."""
import threading
from werkzeug.serving import make_server
from app import create_app
from fake_app import create_fake_app


def main():
    servers = []
    try:
        servers.append(make_server("127.0.0.1", 5000, create_app(), threaded=True))
        servers.append(make_server("127.0.0.1", 5001, create_fake_app(), threaded=True))
        threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
        for thread in threads:
            thread.start()
        print("\nCampus Lab is ready:")
        print("  Start / guide:       http://localhost:5000")
        print("  Legitimate login:    http://localhost:5000/login")
        print("  Simulated inbox:     http://localhost:5000/inbox")
        print("  Fictional fake page: http://127.0.0.1:5001/login")
        print("\nUse only student / DemoPassword!2026. Press Ctrl+C to stop.\n", flush=True)
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        print("\nStopping the local lab...")
    finally:
        # shutdown() is only needed for servers with a running serve_forever.
        for server in servers:
            if 'threads' in locals():
                server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
