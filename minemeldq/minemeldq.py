import argparse
import requests
import re
from requests.exceptions import HTTPError, ConnectionError

result = []

def get_indicators_output(url):
    try:
        res = requests.get(url, timeout=(3.05, 5))
        res.raise_for_status()
        if res.status_code < 200 or res.status_code >= 300:
        if res.status_code == 401:
            return_error('Request Failed with status: 401 Unauthorized - Invalid Username or Password')
        elif res.status_code == 415:
           return_error('Request Failed with status: 415 - Invalid accept header or content type header')
        else:
            return_error('Request Failed with status: ' + str(res.status_code) + '. Reason is: ' + str(res.reason))
        data = res.text
        return res

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
