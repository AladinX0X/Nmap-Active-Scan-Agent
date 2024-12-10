# Nmap Active Scan Agent

## Project Overview

This tool provides a modular and extensible way to perform network scanning using Nmap. It can:
- Execute Nmap scans on specific IP addresses and ports at regular intervals.
- Parse the Nmap XML output to extract host, port, and detailed hardware information (like "Module", "Version", "Serial Number", etc.).
- Save the parsed results in JSON format with filenames based on the current timestamp.
- Display the scan results in a formatted manner on the console and log scan progress and errors using the `loguru` logging library.

## Directory Structure

```
Nmap Active Scan Agent
|__ nse_scripts/
|    |__ script1
|    |__ script2
|    |__ ...
|__ results/
|    |__ parsed_scan_results_<timestamp>.json
|    |__ scan_results_<ip>_<script_name>.xml
|__ nmap_agent.py
|__ run.py
|__ logger.py                
|__ config.json
|__ README.md
|__ requirements.txt
```

- `nse_scripts/`: Directory for storing various Nmap scripts.
- `results/`: Directory for storing XML and JSON scan results.
- `nmap_agent.py` and `run.py`: Main scripts handling scan logic and configurations.
- `logger.py`: Configures the centralized `loguru` logger for consistent logging.
- `config.json`: Config file to easily adjust scan parameters (target IP, port, script name, and scan interval).

## Installation

### Prerequisites

- **Python 3.10+**: Ensure Python is installed on your system.
- **Nmap**: The Nmap tool must be installed and accessible via the command line.
- **Python Libraries**: Install the required Python libraries by running:

    ```bash
    pip install -r requirements.txt
    ```

### Config.json File

The `config.json` file in the root directory contains parameters for the scan:

```json
{
    "wait_time_minutes": 5,
    "scans": [
        {
            "target_ip": ["192.168.0.1", "192.168.0.121"],
            "target_port": 102,
            "script_name": ["enip-info"]
        },
        {
            "target_ip": ["192.168.0.1", "192.168.0.121"],
            "target_port": 102,
            "script_name": ["s7-info"]
        },
        {
            "target_ip": ["192.168.0.1", "192.168.0.121"],
            "target_port": 102,
            "script_name": ["pn-discovery"]
        }
    ]
}
```

You can modify this file to change the target IP, port, Nmap script, and scan interval.

## Usage

1. **Configure the scan parameters**:
   - Modify the `config.json` file with the desired target IP, port, script, and scan interval.

2. **Run the scan**:
   
   Navigate to the project root directory and run the main script:

   ```bash
   python run.py
   ```

   The scan will run continuously based on the interval specified in `config.json`.

3. **View Results**:
    - The XML results are stored in the `results/` directory with filenames like `scan_results_<ip>_<script_name>.xml`.
    - The parsed JSON results are also saved in the `results/` directory with filenames based on the scan's timestamp.
    - Results will display in the terminal for each scan.
    - Logs for each scan (including any errors) are also displayed in the terminal and saved in `nmap_scan.log`.

## Configuration

- You can configure the Nmap scan by modifying the `config.json` file. This file allows you to change the `target_ip`, `target_port`, `script_name`, and `wait_time_minutes` to customize the scan.

## Logging and Error Handling

- The project uses `loguru` for logging and error handling. Logs are output to the console and saved to `nmap_scan.log`, showing scan progress, errors, and detailed results.

## How It Works

1. **Initialization**: The `run_nmap_script` function builds and runs the Nmap command.
2. **Execution**: It executes the Nmap command and writes the output to an XML file.
3. **Parsing**: The `parse_nmap_xml_file` function parses the XML file to extract details about hosts, ports, and other network information.
4. **Saving Results**: The parsed results are saved in JSON format using the `save_results_to_json` function.
5. **Continuous Scanning**: The `start_scan_loop` function runs in a loop, scanning at intervals based on the configuration file.
6. **Cleanup**: The `cleanup_old_xml_files` function ensures only the latest XML files are retained, automatically deleting older files after a specified number of scans.

## Example JSON Output

The scan results are saved in JSON format with detailed information extracted from the Nmap scan:

```json
{
    "wait_time_minutes": 5,
    "scans": [
        {
            "target_ip": "192.168.0.1",
            "target_port": 101,
            "script_name": "enip-info",
            "results": [
                {
                    "ip_address": "192.168.0.1",
                    "mac_address": "28:63:36:AD:79:0C",
                    "vendor": "Siemens AG",
                    "hostnames": [],
                    "ports": [
                        {
                            "port_id": "101",
                            "protocol": "tcp",
                            "state": "closed",
                            "service": "hostname"
                        }
                    ],
                    "Module": "N/A",
                    "Basic Hardware": "N/A",
                    "Version": "N/A",
                    "System Name": "N/A",
                    "Module Type": "N/A",
                    "Serial Number": "N/A",
                    "Plant Identification": "N/A",
                    "Copyright": "N/A"
                }
            ]
        },
        ...
    ]
}
```

## Testing

- **Mocking Subprocess Calls**: For unit testing, you can mock the `subprocess.run` function using `unittest.mock` to simulate different Nmap outputs without needing to run actual scans.

## Type Checking

- The codebase includes type hints, which can be validated using `mypy` for improved type checking and safety:

    ```bash
    mypy nmap_agent/
    ```
