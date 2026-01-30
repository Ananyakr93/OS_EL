from flask import Flask, render_template, request, jsonify
import subprocess
import os
import re
import json
import time

app = Flask(__name__)

# Config
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
ENCFS_BIN = os.path.join(ROOT_DIR, 'encfs')
CIPHER_DIR = os.path.join(ROOT_DIR, 'ciphertext')
MOUNT_POINT = os.path.join(ROOT_DIR, 'mnt')
PERF_LOG = os.path.join(ROOT_DIR, 'encfs_perf.log')

# Ensure directories exist
os.makedirs(CIPHER_DIR, exist_ok=True)
os.makedirs(MOUNT_POINT, exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def status():
    # Check if mounted
    mounted = False
    try:
        # Linux method
        with open('/proc/mounts', 'r') as f:
            for line in f:
                if MOUNT_POINT in line:
                    mounted = True
                    break
    except FileNotFoundError:
        # Windows/other - check if mount point dir has contents
        try:
            if os.path.isdir(MOUNT_POINT) and os.listdir(MOUNT_POINT):
                mounted = True  # Assume mounted if non-empty
        except:
            pass
    return jsonify({'mounted': mounted, 'mount_point': MOUNT_POINT})

@app.route('/api/mount', methods=['POST'])
def mount():
    data = request.json
    passphrase = data.get('passphrase', 'test')
    mode = data.get('mode', 'secure')
    
    cmd = [ENCFS_BIN, CIPHER_DIR, MOUNT_POINT, '-o', f'passphrase={passphrase},mode={mode}']
    try:
        # Run in background? FUSE runs in foreground unless -f not passed?
        # Our encfs code calls fuse_main. fuse_main usually forks unless -f.
        # So subprocess.run should return quickly if it forks?
        # Wait, if it fails, we want to know.
        # Ideally, we add '&' in shell or Popen.
        subprocess.Popen(cmd)
        time.sleep(1) # Wait for init
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/unmount', methods=['POST'])
def unmount():
    try:
        subprocess.run(['fusermount', '-u', MOUNT_POINT], check=True)
        return jsonify({'success': True})
    except subprocess.CalledProcessError as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/files')
def list_files():
    try:
        files = []
        for entry in os.scandir(MOUNT_POINT):
            stats = entry.stat()
            file_info = {
                'name': entry.name,
                'path': entry.path,
                'is_dir': entry.is_dir(),
                'size': stats.st_size,
                'policy': 'Unknown'
            }
            # Try get policy if file
            if entry.is_file():
                try:
                    res = subprocess.run(['getfattr', '-n', 'user.enc_policy', '--only-values', entry.path], 
                                         capture_output=True, text=True)
                    if res.returncode == 0:
                        file_info['policy'] = res.stdout.strip()
                    else:
                        file_info['policy'] = 'Default (ALL)'
                except:
                    pass
            files.append(file_info)
        return jsonify(files)
    except OSError:
        return jsonify([])

@app.route('/api/policy', methods=['POST'])
def set_policy():
    data = request.json
    filename = data.get('filename')
    policy = data.get('policy')
    path = os.path.join(MOUNT_POINT, filename)
    
    try:
        subprocess.run(['setfattr', '-n', 'user.enc_policy', '-v', policy, path], check=True)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/perf')
def get_perf():
    # Read last N lines of log
    data = []
    if os.path.exists(PERF_LOG):
        with open(PERF_LOG, 'r') as f:
            lines = f.readlines()[-50:] # last 50
            for line in lines:
                # Op: read, Latency: 0.000123 s, UserCPU: ...
                m = re.search(r'Op: (\w+), Latency: ([\d.]+) s', line)
                if m:
                    data.append({
                        'op': m.group(1),
                        'latency': float(m.group(2)) * 1000 # to ms
                    })
    return jsonify(data)

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')
