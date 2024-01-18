import os.path
import urllib.request
import tarfile
from snortparser.snortparser import Parser

TARFILE = "snort3-community-rules.tar.gz"
LINK = "https://www.snort.org/downloads/community/"+ TARFILE
DIR = "snort3-community-rules"
FILE = "snort3-community.rules"
CSVFILE = "rules_parsed.csv"
RULES = os.path.join(DIR, FILE)

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



# open output file for writing, not appending
with open(CSVFILE, 'w') as csv_rules:

    # open input file
    with open(RULES) as snort_rules:
        
        # for each line (rule)
        for rule in snort_rules:
           
            # just try ...
            try:
                parsed = Parser(rule)            
    
                # get the fixed fields
                parsed_string = parsed.header['action'] + ';' \
                              + parsed.header['proto'] + ';'  \
                              + str(parsed.header['source']) + ';' \
                              + str(parsed.header['src_port']) + ';' \
                              + parsed.header['arrow'] + ';' \
                              + str(parsed.header['destination']) + ';' \
                              + str(parsed.header['dst_port']) + ';' \
                              +  '--------' + ';' \
                              + str(parsed.options[0][1]) + ';'
                
                # get the required options
                for parsed_option in parsed.options:
                    # print (parsed_option)    
                    parsed_string += str(parsed.options[parsed_option]) + ';'
                
                parsed_string += "\n"
                csv_rules.write(parsed_string)
                # print(parsed_string)
            
            # NOTE: If the snortparser is unable to parse the rule, it will return a ValueError with the invalid rule item.
            except Exception as e:
                print("Exception: "+ str(e))
                print(rule)


print('Job has been done; It\'s mess, but done...')
