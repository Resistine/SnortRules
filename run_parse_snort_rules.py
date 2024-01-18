from snortparser import Parser

with open('csv_rules_parsed.csv', 'a') as csv_rules:
    with open("snort3-community.rules") as snort_rules:
        for rule in snort_rules:
            parsed = Parser(rule)            
            try:
                parsed_string = parsed.header['action'] + ';'  + parsed.header['proto'] + ';' + str(parsed.header['source']) + ';' +  str(parsed.header['src_port']) + ';' + parsed.header['arrow'] + ';' +  str(parsed.header['destination']) + ';' +  str(parsed.header['dst_port']) + ';' +  '--------' + ';' +  str(parsed.options[0][1]) + ';'
                
                counter = 1
                while True:
                    parsed_string += str(parsed.options[counter]) + ';'
                    counter += 1 
                
            except:
                parsed_string += "\n"
                print("I parsed " + str(counter) + " option fields.\n\n")
                print(parsed_string)
                csv_rules.write(parsed_string)
            parsed_string = ""            

print('Job has been done; It\'s mess, but done...')
