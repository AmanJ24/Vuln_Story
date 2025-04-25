#!/usr/bin/env python3
"""
Burp Suite XML Parser Module for Vulnerability Story Teller.
This module handles parsing of Burp Suite XML scan results.
"""

import os
import xmltodict
import logging
from typing import List, Dict, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

def parse_burp_xml(file_path: str) -> List[Dict[str, Any]]:
    """
    Parse a Burp Suite XML file and extract vulnerability information.
    
    Args:
        file_path (str): Path to the Burp Suite XML file
        
    Returns:
        List[Dict[str, Any]]: A list of dictionaries containing vulnerability information
        
    Raises:
        FileNotFoundError: If the file does not exist
        Exception: For any other parsing errors
    """
    try:
        # Check if file exists
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        # Open and read the XML file
        with open(file_path, 'r', encoding='utf-8') as f:
            logger.info(f"Parsing Burp Suite XML file: {file_path}")
            data = xmltodict.parse(f.read())
        
        # Handle the case where there are no issues
        if 'issues' not in data:
            logger.warning("No 'issues' section found in the XML file")
            return []
            
        # Handle the case where 'issue' might be missing
        if 'issue' not in data['issues']:
            logger.warning("No 'issue' entries found in the XML file")
            return []
            
        # Ensure 'issue' is always a list, even if there's only one issue
        issues_data = data['issues']['issue']
        if not isinstance(issues_data, list):
            issues_data = [issues_data]
            
        issues = []
        for issue in issues_data:
            # Extract issue details with safe gets
            host = issue.get('host', 'Unknown Host')
            path = issue.get('path', '')
            name = issue.get('name', 'Unknown Issue')
            severity = issue.get('severity', 'Information')
            issue_detail = issue.get('issueDetail', 'No details provided')
            param = issue.get('param', 'N/A')
            
            # Optional fields with default empty strings
            request = issue.get('request', '')
            response = issue.get('response', '')
            
            # Build structured issue data
            issue_data = {
                'host': host,
                'url': f"{host}{path}",
                'issue': name,
                'severity': severity,
                'description': issue_detail,
                'parameter': param,
                'request': request,
                'response': response
            }
            
            issues.append(issue_data)
            
        logger.info(f"Successfully parsed {len(issues)} vulnerability issues")
        return issues
        
    except FileNotFoundError as e:
        logger.error(f"File not found: {file_path}")
        raise
    except Exception as e:
        logger.error(f"Error parsing Burp Suite XML file: {str(e)}")
        raise

def save_parsed_data(data: List[Dict[str, Any]], output_file: str) -> bool:
    """
    Save parsed vulnerability data to a file for debugging purposes.
    
    Args:
        data (List[Dict[str, Any]]): The parsed vulnerability data
        output_file (str): Path to save the output file
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        import json
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Saved parsed data to {output_file}")
        return True
    except Exception as e:
        logger.error(f"Error saving parsed data: {str(e)}")
        return False


# Example usage if run directly
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python burp_parser.py <burp_xml_file>")
        sys.exit(1)
        
    try:
        xml_file = sys.argv[1]
        parsed_data = parse_burp_xml(xml_file)
        print(f"Successfully parsed {len(parsed_data)} vulnerability issues.")
        
        # Optionally save the parsed data
        if len(parsed_data) > 0:
            output_file = xml_file + ".json"
            if save_parsed_data(parsed_data, output_file):
                print(f"Parsed data saved to {output_file}")
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

