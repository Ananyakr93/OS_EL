import os
import subprocess
import shutil
import time
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify

app = Flask(__name__)
app.secret_key = 'super-secret-encfs-key'  # Needed for flashing messages

# Configuration
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
ENCFS_BIN = os.path.join(ROOT_DIR, 'encfs')
CIPHER_DIR = os.path.join(ROOT_DIR, 'cipher')
MOUNT_POINT = os.path.join(ROOT_DIR, 'mnt')
PERF_LOG = os.path.join(ROOT_DIR, 'encfs_perf.log')
BENCH_SCRIPT = os.path.join(ROOT_DIR, 'tests', 'performance_benchmark.sh')
GRAPH_SCRIPT = os.path.join(ROOT_DIR, 'tests', 'generate_perf_graphs.py')
GRAPH_DIR = os.path.join(ROOT_DIR, 'benchmark_results', 'graphs')
# Configurable sudo usage via environment variable
USE_SUDO = os.environ.get('USE_SUDO', '0') == '1'

# Ensure directories exist
os.makedirs(CIPHER_DIR, exist_ok=True)
os.makedirs(MOUNT_POINT, exist_ok=True)
os.makedirs(os.path.dirname(PERF_LOG), exist_ok=True)

def is_mounted():
    """Check if file system is mounted using os.path.ismount or /proc/mounts."""
    if os.path.ismount(MOUNT_POINT):
        return True
    
    # Fallback/Double-check for some FUSE setups (especially in Docker/WSL where ismount might be picky)
    try:
        with open('/proc/mounts', 'r') as f:
            for line in f:
                if MOUNT_POINT in line:
                    return True
    except FileNotFoundError:
        pass
    return False

@app.route('/')
def index():
    return render_template('home.html', mounted=is_mounted(), mount_point=MOUNT_POINT, active_page='home')

@app.route('/explorer')
def explorer():
    files = []
    if is_mounted():
        try:
            for entry in os.scandir(MOUNT_POINT):
                policy = "Unknown"
                if entry.is_file():
                    try:
                        # Attempt to get policy; requires no sudo if user_allow_other is set, or running as root
                        cmd = ['getfattr', '-n', 'user.enc_policy', '--only-values', entry.path]
                        res = subprocess.run(cmd, capture_output=True, text=True) 
                        if res.returncode == 0:
                            policy = res.stdout.strip()
                        else:
                            policy = "Default"
                    except:
                        pass
                
                size_str = f"{entry.stat().st_size} B"
                if entry.stat().st_size > 1024:
                    size_str = f"{entry.stat().st_size / 1024:.1f} KB"
                
                files.append({
                    'name': entry.name,
                    'is_dir': entry.is_dir(),
                    'size': size_str,
                    'policy': policy
                })
        except PermissionError:
             flash('Permission denied accessing mount point.', 'danger')
        except Exception as e:
             flash(f'Error listing files: {str(e)}', 'danger')
    return render_template('explorer.html', files=files, mounted=is_mounted(), active_page='explorer')

@app.route('/benchmarks')
def benchmarks():
    return render_template('benchmarks.html', active_page='benchmarks')

@app.route('/logs')
def logs():
    log_lines = []
    if os.path.exists(PERF_LOG):
        try:
            with open(PERF_LOG, 'r') as f:
                log_lines = f.readlines()[-100:]
        except Exception as e:
            log_lines = [f"Error reading log: {str(e)}"]
    else:
        log_lines = ["Log file not found."]
    return render_template('logs.html', logs=log_lines, active_page='logs')

@app.route('/action/mount', methods=['POST'])
def mount_fs():
    passphrase = request.form.get('passphrase')
    mode = request.form.get('mode')
    
    cmd = [ENCFS_BIN, CIPHER_DIR, MOUNT_POINT, '-o', f'passphrase={passphrase},mode={mode}']
    
    try:
        # Popen allows us to capture startup errors without blocking forever
        proc = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            outs, errs = proc.communicate(timeout=2)
            if proc.returncode != 0:
               flash(f'Mount failed: {errs if errs else "Unknown error (check logs)"}', 'danger')
               return redirect(url_for('index'))
        except subprocess.TimeoutExpired:
            # Timeout usually means success for FUSE (it daemonized)
            pass
        
        time.sleep(1) # Allow slight delay for mount to register
        if is_mounted():
            flash('Filesystem mounted successfully.', 'success')
        else:
            flash('Mount command executed but filesystem is not detected as mounted. Check permissions or logs.', 'warning')
            
    except Exception as e:
        flash(f'Error mounting: {str(e)}', 'danger')
        
    return redirect(url_for('index'))

@app.route('/action/unmount', methods=['POST'])
def unmount_fs():
    lazy = request.form.get('lazy') == 'true'
    try:
        cmd = ['fusermount', '-u']
        if lazy:
            cmd.append('-z') # Lazy unmount
        cmd.append(MOUNT_POINT)
        
        if USE_SUDO:
            cmd = ['sudo'] + cmd
            
        res = subprocess.run(cmd, capture_output=True, text=True)
        
        if res.returncode == 0:
            flash('Filesystem unmounted successfully.', 'success')
        else:
            error_msg = res.stderr.strip() if res.stderr else "Unknown error"
            flash(f'Unmount failed: {error_msg}. Try using Force Unmount if busy.', 'danger')
            
    except Exception as e:
        flash(f'Error executing unmount: {str(e)}', 'danger')
    return redirect(url_for('index'))

@app.route('/action/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('explorer'))
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('explorer'))
    
    if file:
        filename = file.filename
        try:
            file.save(os.path.join(MOUNT_POINT, filename))
            flash(f'File {filename} uploaded successfully.', 'success')
        except Exception as e:
            flash(f'Error uploading file: {str(e)}', 'danger')
            
    return redirect(url_for('explorer'))

@app.route('/action/delete', methods=['POST'])
def delete_file():
    filename = request.form.get('filename')
    path = os.path.join(MOUNT_POINT, filename)
    try:
        if os.path.exists(path):
            os.remove(path)
            flash(f'File {filename} deleted.', 'success')
        else:
            flash('File not found.', 'warning')
    except Exception as e:
        flash(f'Error deleting file: {str(e)}', 'danger')
    return redirect(url_for('explorer'))

@app.route('/action/policy', methods=['POST'])
def set_policy():
    filename = request.form.get('filename')
    policy = request.form.get('policy')
    path = os.path.join(MOUNT_POINT, filename)
    
    try:
        subprocess.run(['setfattr', '-n', 'user.enc_policy', '-v', policy, path], check=True, capture_output=True)
        flash(f'Policy set to {policy} for {filename}.', 'success')
    except subprocess.CalledProcessError as e:
        flash(f'Failed to set policy: {e.stderr.decode() if e.stderr else str(e)}', 'danger')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        
    return redirect(url_for('explorer'))

@app.route('/api/proof')
def get_proof():
    filename = request.args.get('filename')
    path = os.path.join(MOUNT_POINT, filename)
    try:
        res = subprocess.run(['getfattr', '-n', 'user.zk_proof', '--only-values', path], capture_output=True, text=True)
        if res.returncode == 0:
            return jsonify({'proof': res.stdout.strip()})
        else:
            return jsonify({'error': 'Could not fetch proof'})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/action/benchmark', methods=['POST'])
def run_benchmark():
    try:
        cmd = [BENCH_SCRIPT]
        if USE_SUDO:
            cmd = ['sudo'] + cmd
            
        subprocess.Popen(cmd) # Run in background
        flash('Benchmark started in background. Check logs for progress.', 'info')
    except Exception as e:
        flash(f'Error starting benchmark: {str(e)}', 'danger')
    return redirect(url_for('benchmarks'))

@app.route('/action/graphs', methods=['POST'])
def generate_graphs():
    try:
        subprocess.run(['python3', GRAPH_SCRIPT], check=True)
        flash('Graphs generated successfully.', 'success')
    except Exception as e:
        flash(f'Error generating graphs: {str(e)}', 'danger')
    return redirect(url_for('benchmarks'))

@app.route('/graphs/<filename>')
def get_graph(filename):
    return send_file(os.path.join(GRAPH_DIR, filename))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
