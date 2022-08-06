import pandas as pd
import json

json_data = '''
[{
    "nlri": {
        "prefix": "2001:db8:1000::/48"
    },
    "age": 1645686155,
    "best": true,
    "attrs": [{
            "type": 1,
            "value": 0
        },
        {
            "type": 2,
            "as_paths": []
        },
        {
            "type": 5,
            "value": 100
        },
        {
            "type": 8,
            "communities": [
                1304503115
            ]
        },
        {
            "type": 14,
            "nexthop": "2001:db8::1",
            "afi": 2,
            "safi": 1,
            "value": [{
                "prefix": "2001:db8:1000::/48"
            }]
        }
    ],
    "stale": false,
    "source-id": "203.0.113.1",
    "neighbor-ip": "2001:db8::1"
},
{
    "nlri": {
        "prefix": "2001:db8:1000::/48"
    },
    "age": 1645686150,
    "attrs": [{
            "type": 1,
            "value": 0
        },
        {
            "type": 2,
            "as_paths": [64500]
        },
        {
            "type": 5,
            "value": 99
        },
        {
            "type": 8,
            "communities": [
                1304503105,
                4226809857
            ]
        },
        {
            "type": 14,
            "nexthop": "2001:db8::2",
            "afi": 2,
            "safi": 1,
            "value": [{
                "prefix": "2001:db8:1000::/48"
            }]
        }
    ],
    "stale": false,
    "source-id": "203.0.113.2",
    "neighbor-ip": "2001:db8::2"
}
] '''

table = json.loads(json_data)
df = pd.DataFrame(table)
print(df.T)