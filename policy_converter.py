import json
import sys

try:
    policyFile = sys.argv[1]
except:
    print("ERROR. Please provide policy in json format\n")
    raise
try:
    outputFile = sys.argv[2]
except:
    outputFile = str(policyFile).split(".")[0]+"_v2.json"

with open(policyFile, 'r') as file: 
    
    data = json.load(file)
    data['version'] = "V2"
    try:
        data['denylisted_images'] = data.pop('blacklisted_images')
    except KeyError as e:
        data['denylisted_images'] = []
    try:
        data['allowlisted_images'] = data.pop('whitelisted_images')
    except KeyError as e:
        data['allowlisted_images'] = []
    try:
        data['description'] = data.pop('comment')
    except KeyError as e:
        print(str(e) + " key not being used")
        data['description'] = ""
    try:
        data['allowlists'] = data.pop('whitelists')
    except KeyError as e:
        print(str(e) + " key not being used")
        data['allowlists'] = []
    try:
        for item in data['allowlists']:
            try:
                item['description'] = item.pop('comment')
            except:
                item['description'] = ""
            
            for i in item['items']:
                try:
                    i['description'] = i.pop('comment')
                except:
                    i['description'] = ""
                    continue
    except KeyError as e:
        print(str(e) + " key not being used")
        data['allowlists'] = []

    try: 
        for item in data['mappings']:
            try:
                item['allowlist_ids'] = item.pop('whitelist_ids')
            except:
                item['allowlist_ids'] = []
            try:
                item['rule_set_ids'] = [item.pop('policy_id')]
            except:
                item['rule_set_ids'] = []
          
    except KeyError as e:
        print("ERROR: Property " + str(e) + " is required field")
        data['mappings'] =[]
    try:
        data['rule_sets'] = data.pop('policies')
        for item in data['rule_sets']:
            try:
                item['description'] = item.pop('comment')
            except:
                item['description'] = ""
    except KeyError as e:
        print(str(e) + " key not being used")
        data['rule_sets'] = []
    try:
        for rules in data['rule_sets']:
            for rule in rules['rules']:
                rule['trigger'] = rule['trigger'].replace("black", "deny")
                rule['trigger'] = rule['trigger'].replace("white", "allow")
    except KeyError as e:
        print(str(e))

    newData = json.dumps(data, indent=4)

with open(outputFile, 'w') as file:
    file.write(newData)
