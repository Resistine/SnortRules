from snortparser import Parser

with open('csv_rules_parsed.csv', 'a') as csv_rules:
    with open("snort3-community.rules") as snort_rules:
        for rule in snort_rules:
            parsed = Parser(rule)
            
            #print("Type of data after going thru parser lib", type(parsed),"\n")
            
            try:
                parsed_string = parsed.header['action'] + ';'  + parsed.header['proto'] + ';' + str(parsed.header['source']) + ';' +  str(parsed.header['src_port']) + ';' + parsed.header['arrow'] + ';' +  str(parsed.header['destination']) + ';' +  str(parsed.header['dst_port']) + ';' +  '--------' + ';' +  str(parsed.options[0][1]) + ';' +  str(parsed.options[2]) +  str(parsed.options[3]) +  str(parsed.options[4]) +  str(parsed.options[5]) +  str(parsed.options[6]) +  str(parsed.options[7]) +  str(parsed.options[8]) + '\n'
                print('pass')
            except:
                parsed_string = parsed.header['action'] + ';'  + parsed.header['proto'] + ';' + str(parsed.header['source']) + ';' +  str(parsed.header['src_port']) + ';' + parsed.header['arrow'] + ';' +  str(parsed.header['destination']) + ';' +  str(parsed.header['dst_port']) + ';' +  '--------' + ';' +  str(parsed.options[0][1]) + '\n'
            
            print(parsed_string)
            csv_rules.write(parsed_string)
        
print('Neplecha ukoncena...')
