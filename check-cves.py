#!/usr/bin/env python

import csv
import requests
import pandas as pd
import urllib.parse
import json
import os

VERBOSE = False

# Function to query the CVE API
def query_cve_api(service):
    service = urllib.parse.quote_plus(service)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}"
     

    if VERBOSE:
        print(f"Querying: {url}")

    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def search_cves(input_file, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Read the CSV file
    services_df = pd.read_csv(input_file)

    # Create a list to store the results
    results = []

    # Iterate over each service entry
    for index, row in services_df.iterrows():
        ip = row['ip']
        port = row['port']
        service = row['service']
        
        # Query the CVE API
        cve_data = query_cve_api(service)
        
        if cve_data and 'vulnerabilities' in cve_data:
            results = []
            for item in cve_data['vulnerabilities']:
                cve_id = item['cve']['id']
                description = item['cve']['descriptions'][0]['value']
                to_store = {'ip': ip, 'port': port, 'service': service, 'cve_id': cve_id, 'description': description}
                results.append(to_store)
                if VERBOSE:
                    print(f"Found CVE for {service}: {cve_id} - {description}")

            # Create a JSON file for the current IP
            output_file = os.path.join(output_dir, f'{ip}.json')
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=4)


    # Convert the results to a DataFrame
    results_df = pd.DataFrame(results)

    # Save the results to a CSV file
    results_df.to_csv(output_file, index=False)

    print(f"Vulnerability scan completed. Results saved to {output_file}.")

if __name__ == "__main__":
    # Read 2 input parameters for file path
    import sys

    USAGE = """Usage: python check_cves.py -i <input_file_name.csv> -o <output_directory> [-v]"""
    if len(sys.argv) < 3:
        print(USAGE)
        sys.exit(1)

    input_file_path, output_file_path = None, None
    for arg in sys.argv:
        if arg == "-v":
            VERBOSE = True

        if arg == "-i":
            input_file_path = sys.argv[sys.argv.index(arg) + 1]
        
        if arg == "-o":
            output_file_path = sys.argv[sys.argv.index(arg) + 1]

    if not input_file_path:
        print(USAGE)
        sys.exit(1)
    
    if not output_file_path:
        output_file_path = 'out'

    search_cves(input_file_path, output_file_path)

