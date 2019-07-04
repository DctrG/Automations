import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path
import xml.etree.ElementTree as ET
import re
import pyshark
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from functools import reduce
import operator
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


pcaps_path = 'test-pcaps/'
# time_range = datetime.now() - timedelta(hours = period)
time_range = datetime.now() - timedelta(hours = 23)
threat_time = time_range.strftime('%Y/%m/%d %H:%M:%S')
NOW = datetime.now().strftime('%Y/%m/%d %H:%M:%S')
FIELDS = ['Cdn-Src-Ip','X-Forwarded-For','RealIp','X-Ser','Client-Ip']

def get_api_key():
    try:
        api_url = f"https://{fw_ip}/api/?type=keygen&user={user}&password={password}"
        # api_url = f"https://1.1.1.1/api/?type=keygen&user={user}&password={password}"

        get_api = requests.get(api_url, verify=False).content
        parsed = ET.fromstring(get_api)
        api_key = parsed[0][0].text
        return api_key

    except requests.exceptions.RequestException as e:
        return e

def download_pcaps(base_url, pcap_id, pcap_time):
    try:
        url = f'{base_url}&type=export&category=threat-pcap&pcap-id={pcap_id}&search-time={pcap_time}'
        res = requests.get(url, verify=False)
        res.raise_for_status()
        content = str(res.content)
        if 'error' not in content:
            file = Path(f'{pcaps_path}{pcap_id}.pcap')
            if file.exists() != True:
                with open(f'{pcaps_path}{pcap_id}.pcap', 'wb') as f:
                    f.write(res.content)
            return
    except requests.exceptions.RequestException as e:
        return e

def get_threat_logs(base_url):
    try:
        url = f"{base_url}&type=log&log-type=threat&query=(receive_time geq '{threat_time}')"
        res = requests.get(url, verify=False)
        root = ET.fromstring(res.content)
        job_id = root[0][1].text
        job_url = f'{base_url}&type=log&action=get&job-id={job_id}'
        res_job = requests.get(job_url, verify=False)
        logroot = ET.fromstring(res_job.content)
        pcaps_found = 0
        for child in logroot.findall('.//entry'):
            if child.tag != 'name':
                if child.find('flag-pcap') is not None:
                    pcaps_found += 1
                    if pcaps_found == 1:
                        print('*' * 55)
                        print('  Found some pcaps in threat logs, downloading...')
                        print('*' * 55)
                        import time
                    if child.find('flag-pcap').text == 'yes':
                        if child.find('pcap_id') is not None:
                            pcapid = child.find('pcap_id').text
                        if child.find('receive_time') is not None:
                            pcaptime = child.find('receive_time').text
                        download_pcaps(base_url, pcapid, pcaptime)
                        sys.stdout.write(f'\r{pcaps_found} pcaps downloaded ')
                        sys.stdout.flush()
        return pcaps_found
    except requests.exceptions.RequestException as e:
        return e
        
def find_real_src_ip(pcap):
    cap = pyshark.FileCapture(pcap)
    text = str(cap[0])
    result = []
    for field in FIELDS:
        pattern = re.search(f'{field}:\s(\d*.\d*.\d*.\d*)', text)
        cap.close()
        if pattern is not None:
            if pattern.group(1) not in result:
                result.append(pattern.group(1))
    if len(result) > 0:
        return result
    return

def find_pcap_files():
    path = Path(pcaps_path)
    pcap_files = [str(f) for f in path.glob("*.pcap")]
    results = []
    if pcap_files:
        for pcap in pcap_files:
            indicators = find_real_src_ip(pcap)
            if indicators is not None:
                for ip in indicators:
                    if ip not in results:
                        results.append(indicators)
        return results
    return False
        

def main(args):
    api_key = get_api_key()
    base_url = f'https://{fw_ip}/api/?&key={api_key}'
    pcaps_in_logs = get_threat_logs(base_url)
    if pcaps_in_logs > 0:
        print(f'from in Threat Logs between {threat_time} and {NOW}')
        print(f"Searching for possible hidden original attackers IP's...")
        indicators_in_pcaps = find_pcap_files()
        final_result = set(reduce(operator.concat, indicators_in_pcaps))
        if len(indicators_in_pcaps) > 0:
            print(f'Found real source ip addresses from offenders: ')
            print(', '.join(str(x) for x in final_result))
        else:
            print('No indicators found in the pcaps')
    else:
        print('No pcaps found in threat logs')

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("firewall_ip", nargs="?", default="192.168.1.120", help="Optional. If nothing entered '192.168.1.120' will be used")
    parser.add_argument("username", nargs="?", default="admin", help="Optional. If nothing entered 'admin' will be used")
    parser.add_argument("password", nargs="?", default="admin", help="Optional. If nothing entered 'admin' will be used")
    parser.add_argument("hours", nargs="?", default=1, help="Optional. Timeframe in hours. If nothing entered the last hour will be used")
    args = parser.parse_args()

    user = args.username
    password = args.password
    fw_ip = args.firewall_ip
    period = args.hours
    
    main(args)