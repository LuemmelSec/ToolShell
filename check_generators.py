#!/usr/bin/env python3
"""Quick script to check ViewStateGenerator on multiple SharePoint pages"""

import requests
import re
import sys
import urllib3
urllib3.disable_warnings()

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <target_url>")
    print(f"Example: {sys.argv[0]} http://192.168.5.135")
    sys.exit(1)

target = sys.argv[1].rstrip('/')
pages = [
    '/_layouts/15/ToolPane.aspx?ToolPaneInfo=True',
    '/_layouts/15/settings.aspx',
    '/_layouts/15/viewlsts.aspx',
    '/_layouts/15/people.aspx',
    '/_layouts/15/addanapp.aspx',
    '/_layouts/15/user.aspx',
    '/_layouts/15/groups.aspx',
    '/_layouts/15/regionalsetng.aspx',
    '/_layouts/15/managefeatures.aspx',
    '/_layouts/15/listedit.aspx',
    '/_layouts/15/prjsetng.aspx',
    '/_layouts/15/start.aspx',
    '/default.aspx',
    '/SitePages/Home.aspx',
]

headers = {'Referer': f'{target}/_layouts/SignOut.aspx'}
session = requests.Session()

print(f'Checking ViewStateGenerator on {target}...\n')
print(f'{"Page":<50} Generator')
print('-' * 65)

for page in pages:
    try:
        url = f'{target}{page}'
        resp = session.get(url, headers=headers, timeout=10, verify=False)
        if resp.status_code == 200:
            match = re.search(r'name="__VIEWSTATEGENERATOR"[^>]*value="([^"]+)"', resp.text)
            if not match:
                match = re.search(r'value="([^"]+)"[^>]*name="__VIEWSTATEGENERATOR"', resp.text)
            gen = match.group(1) if match else 'N/A'
            print(f'{page:<50} {gen}')
        else:
            print(f'{page:<50} HTTP {resp.status_code}')
    except Exception as e:
        print(f'{page:<50} Error: {str(e)[:20]}')
