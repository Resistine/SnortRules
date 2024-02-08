# SnortRules
Just a trivial script to download public Snort rules, pick a few fields and push them into .csv file.

The second step is to transform them into MITRE ATT&CK using https://attack.mitre.org/resources/attack-data-and-tools/ and some human effort, eventually some AI ;-)


### Dependencies

> pip install mitreattack-python

> git clone https://github.com/g-rd/snortparser.git

### Run

> python3 parse_snort_rules.py

Plese be patient, the first run may take a couple of minutes.

It downloads the latest MITRE ATT&CK matrix and creates the Excel files \
(delete the *enterprise-attack* directory to recreate it)

And the latest Snort Community Rules \
(delete the *snort3-community-rules* directory to recreate it)

### Check
The result will be in ***rules_parsed.csv*** file.

Note, it will fill in a few TActics and Techniques. \
If you don't know how to fill the rest, rather get the files from: \
https://drive.google.com/drive/folders/1lI6Cwr7iPys-W9ql29utBzgLsroJjSJZ?usp=drive_link 

Copyright (c) 2024 Resistine
