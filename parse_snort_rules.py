import os.path
import urllib.request
import tarfile
from snortparser.snortparser import Parser
import pandas as pd


TARFILE = "snort3-community-rules.tar.gz"
LINK = "https://www.snort.org/downloads/community/"+ TARFILE
DIR = "snort3-community-rules"
FILE = "snort3-community.rules"
CSVFILE = "rules_parsed.csv"
RULES = os.path.join(DIR, FILE)
COLUMNS = ['sid', 'action', 'proto', 'source', 'src_port', 'arrow', 'destination', 'dst_port', 'classtype', 'msg', 'reference']

# get the rules
if (not os.path.exists(RULES)):
    try:
    
        if (not os.path.isdir(DIR)): os.makedirs(DIR)
        urllib.request.urlretrieve(LINK, os.path.join(DIR, TARFILE))
        
        tar = tarfile.open(os.path.join(DIR, TARFILE), "r:gz")
        tar.extractall()
        tar.close()

    except Exception as e:
        print("Exception: "+ str(e))


# get the parsed data and return the rest of the array that starts with the given string
def get_option(parsed, string):
    for n in parsed.options:
        if (parsed.options[n][0].startswith(string)):
            return parsed.options[n]
    return None


# open output file for writing, not appending
with open(CSVFILE, 'w') as csv_rules:
    csv_rules.write(','.join(COLUMNS) + '\n')

    # open input file
    with open(RULES) as snort_rules:
        
        # for each line (rule)
        for rule in snort_rules:
           
            # try to parse the rule
            try:
                parsed = Parser(rule)      
                
                # Create a DataFrame with a single row of the parsed data
                df = pd.DataFrame([[
                    get_option(parsed, 'sid')[1],
                    parsed.header['action'],
                    parsed.header['proto'],
                    parsed.header['source'][1] if parsed.header['source'] else None,
                    parsed.header['src_port'][1] if parsed.header['src_port'] else None,
                    parsed.header['arrow'],
                    parsed.header['destination'][1] if parsed.header['destination'] else None,
                    parsed.header['dst_port'][1] if parsed.header['dst_port'] else None,
                    get_option(parsed, 'classtype')[1][0],
                    get_option(parsed, 'msg')[1][0],
                    get_option(parsed, 'reference')[1] if get_option(parsed, 'reference') else None
                    # TODO: reference
                ]], columns=COLUMNS)
                
                # TODO: add the inbound/outbound directions
                # TODO: add the TActics
                # TODO: add and check the Techniques

                # print the Pandas DataFrame to the output file
                # print(df)
                csv_rules.write(df.to_csv(index=False, header=False))
            
            # NOTE: If the snortparser is unable to parse the rule, it will return a ValueError with the invalid rule item.
            except Exception as e:
                print("Exception: "+ str(e))
                print(rule)

# Hooraay! We are done
print('There you are: '+ CSVFILE)
