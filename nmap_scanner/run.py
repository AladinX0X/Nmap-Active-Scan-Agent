import time
import json
import os
from datetime import datetime
from typing import List, Dict, Optional, Any
from nmap_agent import run_nmap_script, parse_nmap_xml_file, save_results_to_json, cleanup_old_xml_files
from logger import logger

base_dir = os.getcwd()

def load_config(config_path: str) -> Dict[str, Any]:
    """
    Loads configuration from a JSON file.

    Args:
        config_path (str): Path to the configuration JSON file.

    Returns:
        dict: Loaded configuration data.
    """
    with open(config_path, 'r') as config_file:
        return json.load(config_file)

def ensure_results_directory() -> str:
    """
    Ensures that the results directory exists.

    Returns:
        str: Path to the results directory.
    """
    results_dir = os.path.join(base_dir, 'results')
    os.makedirs(results_dir, exist_ok=True)
    return results_dir

def execute_scan(ip: str, target_port: int, script_name: str, results_dir: str) -> Optional[Dict[str, Any]]:
    """
    Executes a scan for a given IP, port, and script, and parses the results.

    Args:
        ip (str): IP address to scan.
        target_port (int): Port to target in the scan.
        script_name (str): Nmap/NSE script to use.
        results_dir (str): Directory where to save the XML results.

    Returns:
        Optional[Dict[str, Any]]: Parsed scan results or None if scan failed.
    """
    xml_output_file = os.path.join(results_dir, f'{ip}_{script_name}.xml')
    logger.info(f"Scanning IP: {ip}, Port: {target_port}, Script: {script_name}")
    try:
        xml_file = run_nmap_script(ip, target_port, script_name, xml_output_file)
        if xml_file:
            parsed_results = parse_nmap_xml_file(xml_file)
            return {
                "target_ip": ip,
                "target_port": target_port,
                "script_name": script_name,
                "results": parsed_results
            }
        else:
            logger.error(f"Scan failed for IP: {ip}, Script: {script_name}")
    except Exception as e:
        logger.error(f"Error during scan for IP {ip}, Script {script_name}: {e}")
    return None

def perform_all_scans(scans: List[Dict[str, Any]], results_dir: str) -> List[Dict[str, Any]]:
    """
    Iterates over all scans and executes them.

    Args:
        scans (list): List of scan configurations.
        results_dir (str): Directory to store scan results.

    Returns:
        list: Aggregated scan results.
    """
    all_results = []
    successful_scans = 0
    failed_scans = 0

    for scan in scans:
        ip_list = scan['target_ip']
        target_port = scan['target_port']
        script_names = scan['script_name']

        for ip in ip_list:
            for script_name in script_names:
                result = execute_scan(ip, target_port, script_name, results_dir)
                if result:
                    all_results.append(result)
                    successful_scans += 1
                else:
                    failed_scans += 1

    logger.info(f"Scan completed: {successful_scans} successful scans, {failed_scans} failed scans.")
    return all_results

def save_scan_results(config: Dict[str, Any], all_results: List[Dict[str, Any]], results_dir: str) -> None:
    """
    Saves all scan results to a JSON file.

    Args:
        config (dict): Configuration data.
        all_results (list): List of all scan results.
        results_dir (str): Directory where to store the JSON output.
    """
    current_time = datetime.now().isoformat().replace(":", "_")
    json_output_file = os.path.join(results_dir, f'scan_results_{current_time}.json')
    save_results_to_json(config, all_results, json_output_file)
    logger.info(f"All scan results saved to {json_output_file}")

    cleanup_old_xml_files(results_dir, keep_count=0)

def countdown(minutes: int) -> None:
    """
    Displays a countdown timer in the terminal for the specified number of minutes.

    Args:
        minutes (int): Duration of the countdown in minutes.
    """
    total_seconds = minutes * 60
    while total_seconds:
        mins, secs = divmod(total_seconds, 60)
        time_left = f"{mins:02d}:{secs:02d} remaining"
        print(time_left, end='\r')
        time.sleep(1)
        total_seconds -= 1
    print("00:00 remaining")

def start_scan_loop(config: Dict[str, Any]) -> None:
    """
    Manages the scan loop based on the provided configuration.

    Args:
        config (dict): Configuration data for scanning.
    """
    wait_time_minutes = config['wait_time_minutes']
    scans = config['scans']
    results_dir = ensure_results_directory()

    while True:
        logger.info("Starting scans based on configuration.")
        all_results = perform_all_scans(scans, results_dir)
        save_scan_results(config, all_results, results_dir)
        logger.info(f"Waiting for {wait_time_minutes} minutes before the next scan...")
        countdown(wait_time_minutes)

if __name__ == "__main__":
    config_file_path = os.path.join(base_dir, 'config.json')
    config = load_config(config_file_path)
    start_scan_loop(config)
