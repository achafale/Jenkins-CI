import pandas as pd
import json
import sys

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
print(sorted_df.to_string())

high_critical_count = sorted_df[sorted_df['severity'].isin(['High', 'Critical'])].shape[0]
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