import pandas as pd
import json
import sys

pd.options.mode.chained_assignment = None  # Disable the SettingWithCopyWarning

# reading the csv file
file_path = 'vulns.json'
with open(file_path, "r") as file:
    json_data = json.load(file)

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
with open(file_path, "r") as file:
    policy_evaluation_data = json.load(file)

image_id = policy_evaluation_data["detail"]["result"]["image_id"]
allowlist_vuln = policy_evaluation_data["detail"]["result"]["result"][image_id]["result"]

allowlist_vuln_df = pd.DataFrame(allowlist_vuln['rows'], columns=allowlist_vuln['header'])

allowlist_filtered_vuln = allowlist_vuln_df[(allowlist_vuln_df['Gate_Action'] == 'stop') & allowlist_vuln_df['Check_Output'].str.contains('HIGH|CRITICAL')]

# Splitting the 'Trigger_Id' column based on '+'
allowlist_filtered_vuln[['vuln', 'Trigger_Id_Temp']] = allowlist_filtered_vuln['Trigger_Id'].str.split('+', expand=True)

# Splitting the temporary column based on '-'
allowlist_filtered_vuln[['package_name', 'package_version']] = allowlist_filtered_vuln['Trigger_Id_Temp'].str.split('-', n=1, expand=True)

# Dropping the temporary column
allowlist_filtered_vuln.drop(columns=['Trigger_Id_Temp'], inplace=True)

join_columns = ['vuln', 'package_name', 'package_version']
inner_joined_df = pd.merge(sorted_df, allowlist_filtered_vuln, on=join_columns, how='inner')

print(inner_joined_df[["vuln", "url", "severity", "package_name", "package_version", "package_path"]].to_string())

high_critical_count = inner_joined_df[inner_joined_df['severity'].isin(['High', 'Critical'])].shape[0]
if high_critical_count > 4:
    print()
    print("==================================================================")
    print("Scan result : FAIL")
    print("==================================================================")
    sys.exit(1)

else:
    print()
    print("==================================================================")
    print("Scan result : PASS")
    print("==================================================================")