import subprocess
import os
import time
import sys
import signal


scripts = ['quic_server.py', 'vio_server.py']


def run_script(script_name):
    # Use sys.executable to run with the same Python interpreter (venv)
    os.system(f"pkill -f {script_name}")
    time.sleep(0.5)
    p = subprocess.Popen([sys.executable, script_name])
    return p


processes = []
def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    for p in processes:
        print("terminated:",p)
        p.terminate()
    sys.exit(0)


if __name__ == "__main__":
    p1 = run_script(scripts[0])
    time.sleep(1)
    p2 = run_script(scripts[1])
    processes.extend([p1, p2])  # Modify global list, don't shadow it
    signal.signal(signal.SIGINT, signal_handler)
    p1.wait()
    p2.wait()
    print("All subprocesses have completed.")
