import subprocess
import ipaddress
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional

# Hardcoded port specification
PORT_SPEC = "1-1024,8080"
EXECUTABLE = "tcp_sweep.py"
TCP_SWEEP_PATH = "/root/volumes/tcp_sweep.py"

# Type alias: (returncode, stdout, stderr, error_message)
ScanResult = Tuple[int, str, str, Optional[str]]

def _validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def _build_command(ip: str) -> List[str]:
    return [sys.executable, TCP_SWEEP_PATH, ip, PORT_SPEC]

def run_port_scan_for_ips(
    ips: List[str],
    timeout: Optional[float] = None,
    max_workers: int = 1
) -> Dict[str, ScanResult]:
    cleaned_ips = []
    for ip in ips:
        if not _validate_ip(ip):
            raise ValueError(f"Invalid IP address: {ip}")
        cleaned_ips.append(ip)

    results: Dict[str, ScanResult] = {}

    def _run_single(ip: str) -> Tuple[str, ScanResult]:
        cmd = _build_command(ip)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return (ip, (proc.returncode, proc.stdout, proc.stderr, None))
        except subprocess.TimeoutExpired:
            return (ip, (-1, "", "", f"timeout after {timeout} seconds"))
        except FileNotFoundError:
            return (ip, (-1, "", "", f"executable not found: {EXECUTABLE}"))
        except Exception as e:
            return (ip, (-1, "", "", f"exception: {e}"))

    # Sequential or parallel
    if max_workers <= 1:
        for ip in cleaned_ips:
            ip_key, result = _run_single(ip)
            results[ip_key] = result
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as exe:
            futures = {exe.submit(_run_single, ip): ip for ip in cleaned_ips}
            for fut in as_completed(futures):
                ip_key, result = fut.result()
                results[ip_key] = result

    return results


if __name__ == "__main__":
    # Example usage:
    #input: ips_to_Scan should be the return of the ips available
    ips_to_scan = ["172.17.0.1"]
    results = run_port_scan_for_ips(ips_to_scan, timeout=30, max_workers=2)
    for ip, (rc, out, err, err_msg) in results.items():
        print(f"\n--- {ip} (rc={rc}) ---")
        if err_msg:
            print("ERROR:", err_msg)
        if out.strip():
            print("STDOUT:\n", out.strip())
        if err.strip():
            print("STDERR:\n", err.strip())
