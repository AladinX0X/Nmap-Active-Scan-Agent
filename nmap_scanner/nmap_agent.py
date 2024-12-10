import subprocess
import xml.etree.ElementTree as ET
import json
import os
import glob
from typing import List, Dict, Any, Optional
from logger import logger

base_dir = os.getcwd()

def run_nmap_script(ip_address: str, port: int, script_name: str, xml_output_file: str) -> Optional[str]:
    """
    Executes the Nmap script against the specified IP address and port.

    Args:
        ip_address (str): Target IP address for the scan.
        port (int): Target port for the scan.
        script_name (str): Name of the Nmap script to execute.
        xml_output_file (str): Path for saving XML scan results.

    Returns:
        Optional[str]: Path to the XML output file if successful, otherwise None.
    """
    try:
        if not ip_address or not script_name:
            raise ValueError("IP address or script name is not specified.")
        
        xml_output_path = os.path.join(base_dir, xml_output_file)
        command = ['nmap', '--script', script_name, '-p', str(port), ip_address, '-oX', xml_output_path]
        logger.info(f"Running command: {' '.join(command)}")

        subprocess.run(command, capture_output=True, text=True, check=True)
        logger.info(f"Nmap scan completed. Output saved to {xml_output_path}")
        return xml_output_path

    except ValueError as ve:
        logger.error(f"Input error: {ve}")
    except FileNotFoundError as fe:
        logger.error(f"File not found: {fe}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Nmap command failed: {e.stderr}")
    except Exception as e:
        logger.error(f"Unexpected error during scan: {e}")
    return None

def parse_nmap_xml_file(xml_file: str) -> List[Dict[str, Any]]:
    """
    Parses the Nmap XML file to extract scan results.

    Args:
        xml_file (str): Path to the XML file.

    Returns:
        List[Dict[str, Any]]: List of parsed host details.
    """
    try:
        xml_file_path = os.path.join(base_dir, xml_file)
        if not os.path.exists(xml_file_path) or os.path.getsize(xml_file_path) == 0:
            logger.error(f"XML output file '{xml_file_path}' does not exist or is empty.")
            return []

        tree = ET.parse(xml_file_path)
        root = tree.getroot()
        hosts = root.findall('host')
        if not hosts:
            logger.info(f"No results found in the XML file '{xml_file_path}'.")
            return []

        return [parse_host(host) for host in hosts]
    except ET.ParseError as e:
        logger.error(f"Failed to parse XML file '{xml_file}': {e}")
    except Exception as e:
        logger.error(f"Unexpected error during XML parsing: {e}")
    return []

def save_results_to_json(config: dict, results: List[Dict[str, Any]], filename: str) -> None:
    """
    Saves scan results to a JSON file in the specified format.

    Args:
        config (dict): Configuration parameters for the scan.
        results (List[Dict[str, Any]]): Scan results data.
        filename (str): Path for saving the JSON output.
    """
    output_data = {
        "wait_time_minutes": config['wait_time_minutes'],
        "scans": results
    }
    json_file_path = os.path.join(base_dir, filename)
    try:
        with open(json_file_path, 'w') as json_file:
            json.dump(output_data, json_file, indent=4)
        logger.info(f"Results saved to {json_file_path}")
    except IOError as e:
        logger.error(f"Failed to write results to {json_file_path}: {e}")

def parse_host(host: ET.Element) -> Dict[str, Any]:
    """
    Parses a host element from the Nmap XML output.

    Args:
        host (ET.Element): XML element representing a host.

    Returns:
        Dict[str, Any]: Parsed host information.
    """
    result = {
        'ip_address': get_xml_text(host, "address[@addrtype='ipv4']", 'addr'),
        'mac_address': get_xml_text(host, "address[@addrtype='mac']", 'addr', 'N/A'),
        'vendor': get_xml_text(host, "address[@addrtype='mac']", 'vendor', 'N/A'),
        'hostnames': parse_hostnames(host),
        'ports': parse_ports(host),
    }

    result.update(extract_additional_info(host))
    return result

def get_xml_text(element: ET.Element, xpath: str, attribute: str, default: Optional[str] = None) -> Optional[str]:
    """
    Retrieves text from an XML element based on a given XPath and attribute.

    Args:
        element (ET.Element): XML element to search within.
        xpath (str): XPath to locate the node.
        attribute (str): Attribute to extract from the node.
        default (Optional[str]): Default value if the attribute is not found.

    Returns:
        Optional[str]: The attribute value or the default if not found.
    """
    node = element.find(xpath)
    return node.get(attribute) if node is not None else default

def parse_hostnames(host: ET.Element) -> List[str]:
    """
    Extracts hostnames from the host XML element.

    Args:
        host (ET.Element): XML element representing a host.

    Returns:
        List[str]: List of hostnames associated with the host.
    """
    hostnames = host.find('hostnames')
    return [hostname.get('name') for hostname in hostnames.findall('hostname')] if hostnames else []

def parse_ports(host: ET.Element) -> List[Dict[str, Any]]:
    """
    Extracts port information from the host XML element.

    Args:
        host (ET.Element): XML element representing a host.

    Returns:
        List[Dict[str, Any]]: List of ports and associated information.
    """
    ports = host.find('ports')
    return [parse_port(port) for port in ports.findall('port')] if ports else []

def parse_port(port: ET.Element) -> Dict[str, Any]:
    """
    Extracts details of a single port.

    Args:
        port (ET.Element): XML element representing a port.

    Returns:
        Dict[str, Any]: Details of the port.
    """
    return {
        'port_id': port.get('portid'),
        'protocol': port.get('protocol'),
        'state': get_xml_text(port, 'state', 'state', 'unknown'),
        'service': get_xml_text(port, 'service', 'name', 'N/A')
    }

def extract_additional_info(host: ET.Element) -> Dict[str, Any]:
    """
    Extracts additional NSE script information from the host XML element.

    Args:
        host (ET.Element): XML element representing a host.

    Returns:
        Dict[str, Any]: Dictionary of additional information.
    """
    additional_info = {
        "Module": extract_nse_field(host, "Module"),
        "Basic Hardware": extract_nse_field(host, "Basic Hardware"),
        "Version": extract_nse_field(host, "Version"),
        "System Name": extract_nse_field(host, "System Name"),
        "Module Type": extract_nse_field(host, "Module Type"),
        "Serial Number": extract_nse_field(host, "Serial Number"),
        "Plant Identification": extract_nse_field(host, "Plant Identification"),
        "Copyright": extract_nse_field(host, "Copyright")
    }
    return additional_info

def extract_nse_field(host: ET.Element, field_name: str) -> str:
    """
    Extracts a specific field from NSE script output in the XML.

    Args:
        host (ET.Element): XML element representing a host.
        field_name (str): The name of the NSE field to extract.

    Returns:
        str: Value of the NSE field, or 'N/A' if not found.
    """
    for elem in host.findall(".//elem[@key]"):
        if elem.get('key') == field_name:
            return elem.text or 'N/A'
    return 'N/A'

def cleanup_old_xml_files(results_dir: str, keep_count: int = 10) -> None:
    """
    Deletes XML files from the results directory, keeping only the latest 'keep_count' files.

    Args:
        results_dir (str): Directory containing XML files.
        keep_count (int): Number of files to retain. Older files are deleted.
    """
    xml_files = sorted(
        glob.glob(os.path.join(results_dir, "*.xml")),
        key=os.path.getmtime
    )

    files_to_delete = len(xml_files) - keep_count
    if files_to_delete > 0:
        for xml_file in xml_files[:files_to_delete]:
            try:
                os.remove(xml_file)
                logger.info(f"Deleted old XML file: {xml_file}")
            except Exception as e:
                logger.error(f"Failed to delete XML file {xml_file}: {e}")
