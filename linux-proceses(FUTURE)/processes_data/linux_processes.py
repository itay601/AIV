import psutil
import datetime
import json
from pathlib import Path

def get_process_details():
    """
    Uses psutil to extract detailed information about running processes.
    Returns both a list for printing and a list for JSON export.
    """
    processes = []
    processes_json = []
    
    for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'create_time']):
        try:
            # Get basic process info
            proc_info = proc.info
            
            # Get detailed information
            with proc.oneshot():  # More efficient collection of multiple info
                # Memory information
                mem_info = proc.memory_info()
                mem_percent = proc.memory_percent()
                
                # CPU information
                cpu_percent = proc.cpu_percent(interval=0.1)
                
                # Additional details
                num_threads = proc.num_threads()
                num_fds = proc.num_fds() if hasattr(proc, 'num_fds') else None
                
                # Get open files
                try:
                    open_files = [f.path for f in proc.open_files()]
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    open_files = []
                
                # Get network connections
                try:
                    connections = [{
                        "family": str(conn.family),
                        "type": str(conn.type),
                        "laddr": str(conn.laddr),
                        "raddr": str(conn.raddr) if conn.raddr else None,
                        "status": conn.status
                    } for conn in proc.net_connections()]
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    connections = []
                
                # Get parent process info
                try:
                    parent = proc.parent().name() if proc.parent() else None
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    parent = None
                
                # Create detailed process info dictionary
                detailed_info = {
                    'pid': proc_info['pid'],
                    'name': proc_info['name'],
                    'username': proc_info['username'],
                    'status': proc_info['status'],
                    'created_time': datetime.datetime.fromtimestamp(proc_info['create_time']).strftime('%Y-%m-%d %H:%M:%S'),
                    'cpu_percent': cpu_percent,
                    'memory_percent': round(mem_percent, 2),
                    'memory_rss': mem_info.rss,
                    'memory_vms': mem_info.vms,
                    'num_threads': num_threads,
                    'num_file_descriptors': num_fds,
                    'parent_process': parent,
                    'open_files': open_files,
                    'connections': connections
                }
                
                processes.append(detailed_info)
                processes_json.append(detailed_info)
                
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            continue
            
    return processes, processes_json

def print_processes(processes):
    """Print process information in a readable format"""
    print("\n=== Process Details ===\n")
    for proc in processes:
        print(f"PID: {proc['pid']}")
        print(f"Name: {proc['name']}")
        print(f"User: {proc['username']}")
        print(f"Status: {proc['status']}")
        print(f"Creation Time: {proc['created_time']}")
        print(f"CPU %: {proc['cpu_percent']}")
        print(f"Memory %: {proc['memory_percent']}")
        print(f"Memory (RSS): {proc['memory_rss'] / (1024*1024):.2f} MB")
        print(f"Memory (VMS): {proc['memory_vms'] / (1024*1024):.2f} MB")
        print(f"Threads: {proc['num_threads']}")
        print(f"File Descriptors: {proc['num_file_descriptors']}")
        print(f"Parent Process: {proc['parent_process']}")
        print(f"Open Files: {proc['open_files']}")
        print(f"Network Connections: {proc['connections']}")
        print("-" * 50)

def save_to_json(processes, filename='process_data.json'):
    """Save process information to a JSON file"""
    with open(filename, 'w') as f:
        json.dump(processes, f, indent=2)
    print(f"Data saved to {filename}")

if __name__ == "__main__":
    # Get process information
    processes, processes_json = get_process_details()
    
    # Print detailed information
    print_processes(processes)
    
    # Save to JSON file
    save_to_json(processes_json)