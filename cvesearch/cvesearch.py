''' IMPORTS '''
import requests

''' HELPER FUNCTIONS '''
def list_to_md(o, section):
    md = f'#### {section.capitalize()}\n'
    for k,v in o[section].items():
        md += f"- {k.capitalize()}: **{v.capitalize()}**\n"
    md += '\n'
    return md

@logger
def api_request(url):
    """
    Makes an API call with the supplied URL
    """
    LOG(f'running request with {url}')
    res = requests.get(url, timeout=(3.05, 5))
    if res.status_code < 200 or res.status_code >= 300:
        if res.status_code == 401:
            return_error('Request Failed with status: 401 Unauthorized - Invalid Username or Password')
        elif res.status_code == 415:
           return_error('Request Failed with status: 415 - Invalid accept header or content type header')
        else:
            return_error('Request Failed with status: ' + str(res.status_code) + '. Reason is: ' + str(res.reason))
    return res

''' FUNCTIONS '''

def cve_to_md(o):
    if o and o['id']:
        md = f"### Circl.lu {o['id']}\n"
        md += f"Summary: **{o['summary']}**\n"
        md += f"Published: **{o['Published']}**\n"
        md += f"Modified: **{o['Modified']}**\n"
        if o['cvss']:
            md += f"CVSS: **{o['cvss']}**\n"
        if o['references']:
            md += '#### References\n'
            for ref in o['references']:
                md += f"- [{ref}]({ref})\n"
            md += '\n'
        if "access" in o.keys():
            md += list_to_md(o, 'access')
        if 'impact' in o.keys():
            md += list_to_md(o, 'impact')
        if 'map_cve_hp' in o.keys():
            md += list_to_md(o, 'map_cve_hp')
        if 'map_cve_nessus' in o.keys():
            md += list_to_md(o, 'map_cve_nessus')
        if 'map_cve_ncip' in o.keys():
            md += list_to_md(o, 'map_cve_ncip')
        if 'ranking' in o.keys():
            md += '#### Ranking\n'
            for k,v in o['ranking'][0][0].items():
                md += f"- {k.capitalize()}: **{str(v)}**\n"
        if 'vulnerable_configuration' in o.keys() and len(o['vulnerable_configuration']) > 0:
            md += '#### Vulnerable Configurations\n'
            for item in o['vulnerable_configuration']:
                md += f"- **{item['title']}**\n"
        return md
    return 'No result found.'

def cve_to_context(o):
    if o and o['id']:
        return {
            'ID': o['id'],
            'CVSS': o['cvss'],
            'Published': o['Published'],
            'Modified': o['Modified'],
            'Description': o['summary']
        }
    return None

def get_cve():
    url = 'http://cve.circl.lu/api/cve/' + demisto.args()['cve_id'].upper()
    res = api_request(url)
    o = res.json();
    ec = {}
    ec[outputPaths['cve']] = cve_to_context(o);
    if ec[outputPaths['cve']]:
        return demisto.results({
            'Type': entryTypes['note'],
            'Contents': res.text,
            'ContentsFormat': formats['json'],
            'HumanReadable': cve_to_md(o),
            'EntryContext': ec[outputPaths['cve']]
        })
    return demisto.results({
        'Type': entryTypes['note'],
        'Contents': res.text,
        'ContentsFormat': formats['json'],
        'HumanReadable': cve_to_md(o),
        'EntryContext': {}
    })


def get_latest_cve():
    url = 'http://cve.circl.lu/api/last/' + demisto.args()['limit']
    res = api_request(url)
    o = res.json()
    md = '## Circl.lu Latest CVEs\n'
    context = {}
    ec = []
    if o and isinstance(o, list):
        for item in o:
            md += cve_to_md(item) + '\n'
            ecl = cve_to_context(item)
            if ecl:
                ec.append(ecl)
        if len(ec) > 0:
            context[outputPaths['cve']] = ec
    else:
        md += 'No result found.'
    return demisto.results({
        'Type': entryTypes['note'],
        'Contents': res.text,
        'ContentsFormat': formats['json'],
        'HumanReadable': md,
        'EntryContext': context
    })

''' EXECUTION '''
LOG(f'command is {demisto.command()}')

try:
    if demisto.command() == 'test-module':
        res = requests.get('http://cve.circl.lu/api/last/1')
        demisto.results('ok')
    if demisto.command() == 'Circl-cve-get-latest':
        get_latest_cve()
    if demisto.command() == 'Circl-cve-search':
        get_cve()
except Exception as e:
    return_error(e.message)