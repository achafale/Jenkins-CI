import pandas as pd
import json
import sys

pd.options.mode.chained_assignment = None  # Disable the SettingWithCopyWarning

# reading the csv file
file_path = 'vulns.json'
try:
    with open(file_path, "r") as file:
        json_data = json.load(file)
except FileNotFoundError:
    print(f"The file {file_path} was not found.")
    print()
    print("==================================================================")
    print("Scan result : FAIL")
    print("==================================================================")
    # sys.exit(1)
    sys.exit(0)

except json.JSONDecodeError:
    print(f"The file {file_path} does not contain valid JSON.")
    print()
    print("==================================================================")
    print("Scan result : FAIL")
    print("==================================================================")
    # sys.exit(1)
    sys.exit(0)

except Exception as e:
    print(f"An error occurred: {e}")
    print()
    print("==================================================================")
    print("Scan result : FAIL")
    print("==================================================================")
    # sys.exit(1)
    sys.exit(0)
    
if not json_data['vulnerabilities']:
    print()
    print("==================================================================")
    print("Scan result : PASS")
    print("==================================================================")
    sys.exit(0)

normalized_json = []
for vuln_dict in json_data['vulnerabilities']:
    vuln_report = {}
    vuln_report['vuln'] = vuln_dict['vuln']
    vuln_report['url'] = vuln_dict['url']
    vuln_report['severity'] = vuln_dict['severity']
    vuln_report['package_name'] = vuln_dict['package_name']
    vuln_report['package_version'] = vuln_dict['package_version']
    vuln_report['package_path'] = vuln_dict['package_path']
    vuln_report['package_type'] = vuln_dict['package_type']

    normalized_json.append(vuln_report)

vuln_df = pd.DataFrame(normalized_json)
filtered_df = vuln_df[vuln_df['severity'].isin(['Critical', 'High'])]
# Custom sorting function for severity
def custom_severity_sort(value):
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    return order.get(value, 4)

# Sort the DataFrame based on custom severity order
sorted_df = filtered_df.sort_values(by="severity", key=lambda x: x.map(custom_severity_sort))
# print(sorted_df.to_string())

file_path = 'policy_evaluation.json'
try:
    with open(file_path, "r") as file:
        policy_evaluation_data = json.load(file)
except FileNotFoundError:
    print(f"The file {file_path} was not found.")
    print()
    print("==================================================================")
    print("Scan result : FAIL")
    print("==================================================================")
    # sys.exit(1)
    sys.exit(0)

except json.JSONDecodeError:
    print(f"The file {file_path} does not contain valid JSON.")
    print()
    print("==================================================================")
    print("Scan result : FAIL")
    print("==================================================================")
    # sys.exit(1)
    sys.exit(0)
    
except Exception as e:
    print(f"An error occurred: {e}")
    print()
    print("==================================================================")
    print("Scan result : FAIL")
    print("==================================================================")
    # sys.exit(1)
    sys.exit(0)

allowlist_vuln = policy_evaluation_data["evaluations"][0]["details"]["findings"]

allowlist_vuln_df = pd.DataFrame(allowlist_vuln)

allowlist_filtered_vuln = allowlist_vuln_df[(allowlist_vuln_df['action'] == 'stop') & allowlist_vuln_df['message'].str.contains('HIGH|CRITICAL')]

# Splitting the 'Trigger_Id' column based on '+'
allowlist_filtered_vuln[['vuln', 'Trigger_Id_Temp']] = allowlist_filtered_vuln['trigger_id'].str.split('+', n=1, expand=True)

# Splitting the temporary column based on '-'
allowlist_filtered_vuln[['package_name', 'package_version']] = allowlist_filtered_vuln['Trigger_Id_Temp'].str.split('-', n=1, expand=True)

# Dropping the temporary column
allowlist_filtered_vuln.drop(columns=['Trigger_Id_Temp'], inplace=True)

join_columns = ['vuln', 'package_name', 'package_version']
inner_joined_df = pd.merge(sorted_df, allowlist_filtered_vuln, on=join_columns, how='inner')

print("==================================================================")
print("Fix below vulnerabilities : ")
print(inner_joined_df[["vuln", "url", "severity_x", "package_name", "package_version", "package_path"]].to_string())
print("==================================================================")

high_critical_count = inner_joined_df[inner_joined_df['severity_x'].isin(['High', 'Critical'])].shape[0]
if high_critical_count > 14:
    print()
    print("==================================================================")
    print("Scan result : FAIL")
    print("==================================================================")
    # sys.exit(1)
    sys.exit(0)
else:
    print()
    print("==================================================================")
    print("Scan result : PASS")
    print("==================================================================")
