import json
import sys
from html import escape

json_file = sys.argv[1]
html_file = sys.argv[2]

with open(json_file) as f:
    data = json.load(f)

rows = []
for result in data.get("Results", []):
    target = result.get("Target", "")
    for vuln in result.get("Vulnerabilities", []):
        if vuln["Severity"] in ["HIGH", "CRITICAL"]:
            rows.append(f"""
<tr>
  <td>{escape(target)}</td>
  <td>{escape(vuln.get("PkgName", ""))}</td>
  <td>{escape(vuln.get("InstalledVersion", ""))}</td>
  <td>{escape(vuln.get("FixedVersion", ""))}</td>
  <td>{escape(vuln.get("Severity", ""))}</td>
  <td>{escape(vuln.get("Title", ""))}</td>
  <td>{escape(vuln.get("Description", ""))}</td>
</tr>
""")

html = f"""<html><head><title>Trivy Report</title></head>
<body>
<h2>High & Critical Vulnerabilities</h2>
<table border="1" cellpadding="5" cellspacing="0">
<thead>
<tr>
  <th>Target</th>
  <th>PkgName</th>
  <th>InstalledVersion</th>
  <th>FixedVersion</th>
  <th>Severity</th>
  <th>Title</th>
  <th>Description</th>
</tr>
</thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
</body></html>
"""

with open(html_file, "w") as f:
    f.write(html)

