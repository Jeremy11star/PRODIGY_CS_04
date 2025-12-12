import psutil

# Define a list of common suspicious keylogger or malware process names
SUSPICIOUS_NAMES = [
    "keylogger", 
    "logger", 
    "spy", 
    "monitor", 
    "capture",
    "svchost" 
]

def analyze_process(pid):
    """Fetches key information and checks for suspicious activity for a single process."""
    try:
        proc = psutil.Process(pid)
        
        # Fetch necessary attributes
        name = proc.name()
        
        # Get resource usage (CPU and Memory)
        cpu_percent = proc.cpu_percent(interval=None) # Non-blocking call
        mem_percent = proc.memory_percent()
        
        
        # Check 1: Suspicious Name
        is_suspicious_name = False
        for s_name in SUSPICIOUS_NAMES:
            # Check if any suspicious name is part of the process name
            if s_name.lower() in name.lower():
                is_suspicious_name = True
                break
        
        # Check 2: High Resource Usage (simulated threshold)
        # We use a simulated high threshold for demonstration
        is_high_usage = cpu_percent > 10.0 or mem_percent > 10.0
        
        # Return all data
        return {
            'pid': pid,
            'name': name,
            'cpu': cpu_percent,
            'mem': mem_percent,
            'suspicious_name': is_suspicious_name,
            'high_usage': is_high_usage
        }

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        # Handle cases where the process is gone or access is denied
        return None

def detect_keyloggers():
    """Main function to iterate through all processes and look for threats."""
    print("\n--- Prodigy InfoTech Task 04: Keylogger Detector ---")
    print("--- Scanning System Processes for Suspicious Activity ---\n")
    
    suspicious_processes = []
    
    # Iterate over all Process IDs (PIDs)
    for pid in psutil.pids():
        result = analyze_process(pid)
        
        if result:
            # Check for suspicious name OR high resource usage
            if result['suspicious_name'] or result['high_usage']:
                suspicious_processes.append(result)

    # Report results
    if suspicious_processes:
        print("🔴 ALERT! Suspicious processes detected:\n")
        print(f"{'PID':<6} | {'NAME':<30} | {'CPU %':<7} | {'MEM %':<7} | {'REASON':<15}")
        print("-" * 69)
        
        for proc in suspicious_processes:
            reason = []
            if proc['suspicious_name']:
                reason.append("Suspicious Name")
            if proc['high_usage']:
                reason.append("High Usage")
            
            # Print the process info, truncated name if necessary
            print(f"{proc['pid']:<6} | {proc['name'][:30]:<30} | {proc['cpu']:<7.2f} | {proc['mem']:<7.2f} | {', '.join(reason)}")
        
        print("\nACTION: Investigate these processes immediately. You may need to terminate them.")
    else:
        print("🟢 No highly suspicious processes detected based on current criteria.")


# Run the detection
if __name__ == "__main__":
    detect_keyloggers()