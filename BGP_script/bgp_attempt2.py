from IPython.display import display
import pandas as pd
  
# creating a DataFrame
dict = {'neighbor-ip' : ['2001:db8::1', '2001:db8::2'],
        'source-id' : ['203.0.113.1', '203.0.113.2'],
        'stale' : [False, False],
        'age' : ['1645686155', '1645686150'],
        'prefix' : ['2001:db8:1000::/48', '2001:db8:1000::/48'],
        'afi' : ['2', '2'],
        'safi' : ['1','1'],
        'source-id' : ['203.0.113.1', '203.0.113.2'],
        'nexthop': ['2001:db8::1', '2001:db8::2'],
        'communities1': ['1304503115', '0' ],
        'communities2': ['1304503105', '4226809857'],
}
df = pd.DataFrame(dict)
  
# displaying the DataFrame
display(df)