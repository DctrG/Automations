import argparse
import requests
import re
from requests.exceptions import HTTPError, ConnectionError

##

result = []

def get_indicators_output(url):
    try:
        r = requests.get(url, timeout=(3.05, 5))
        r.raise_for_status()
        if r.status_code == 200:
            data = r.text
            return data

    except ConnectionError as conn_err:
        print('Connection error occurred: {}'.format(conn_err))

    except HTTPError as http_err:
        print('HTTP error occurred: {}'.format(http_err))

def get_match(indicator, url):
    try:
        data = get_indicators_output(url)
        match = re.search(indicator, data)
        if match:
            return result.append("'{}' found in MineMeld feed '{}'".format(indicator, url))
        else:
            return result.append("'{}' was NOT found in MineMeld feed '{}'".format(indicator, url))
    except:
        print("Something went wrong, please verify the MineMeld Instance and Output Node names")


def main(args):
        mm_url = f"https://{mm_instance}.paloaltonetworks-app.com/feeds/"
        url = f'{mm_url}{output_node}'
        print(url)
        get_match(ioc, url)
        print(", ".join(result))

if __name__ == "__main__":
        parser = argparse.ArgumentParser()
        parser.add_argument("instance", nargs="?", help="Unique ID of MineMeld instance")
        parser.add_argument("node", nargs="?", help="MineMeld output node name")
        parser.add_argument("ioc", nargs="?", help="Indicator to search for in MineMeld output node")   
        
        args = parser.parse_args()
        mm_instance = args.instance
        output_node = args.node
        ioc = args.ioc

        main(args)
