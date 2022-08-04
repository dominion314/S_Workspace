#!/usr/bin/env python3

import requests
import pprint as pp


SUBDOMAIN='shieldfc'
API_ACCESS_KEY='u+rX_GwQzuXo2earXw9w'
service_ids = [ 'P576L5A' ]

def get_incidents(service_ids=['P576L5A'], limit=1, offset=1):
    """
    This function takes a list of service id's, and returns pretty printed json for each incident that
    has a status of 'triggered'.

    get_incidents() could be called in a for loop which increments offset to scan through all incidents,
    returning a group of incidents based on the given limit.

    :param service_ids: defaults to a list of service id's containing only P576L5A.
    :param limit:   defaults to 1
    :param offset:  defaults to 1
    """
    headers = {
        'Authorization': f'Token token={API_ACCESS_KEY}',
        'Content-type': 'application/json',
    }
    
    payload = {
        'since':'2022-05-01',
        'until':'2022-05-16',
        'urgency':'high',
        'limit': limit,
        'offset': offset,
        'statuses[]': 'triggered',
        'service_ids[]': service_ids,
        'title[]': 'blackbox',
    }
   
    r = requests.get(
                    f'https://{SUBDOMAIN}.pagerduty.com/api/v1/incidents',
                    headers=headers,
                    params=payload,
    )
    
    #print(r.status_code)
    # pp.pprint(r.text)
    pp.pprint(r.json())
    # pp.pprint(r.request)


get_incidents()

for i in range(10):
    get_incidents(service_ids=['P576L5A'], limit=40, offset=i)
