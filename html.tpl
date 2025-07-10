<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Trivy Vulnerability Report</title>
  <style>
    body { font-family: Arial, sans-serif; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; }
    th { background-color: #f2f2f2; }
    tr:nth-child(even) { background-color: #f9f9f9; }
    .critical { background-color: #f8d7da; }
    .high { background-color: #fff3cd; }
  </style>
</head>
<body>
  <h1>Trivy Vulnerability Report</h1>
  <p><strong>Target:</strong> {{ .Target }}</p>
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>Package</th>
        <th>Installed Version</th>
        <th>Fixed Version</th>
        <th>Severity</th>
      </tr>
    </thead>
    <tbody>
      {{ range .Vulnerabilities }}
        {{ if or (eq .Severity "HIGH") (eq .Severity "CRITICAL") }}
          {{ if .FixedVersion }}
            <tr class="{{ lower .Severity }}">
              <td>{{ .VulnerabilityID }}</td>
              <td>{{ .PkgName }}</td>
              <td>{{ .InstalledVersion }}</td>
              <td>{{ .FixedVersion }}</td>
              <td>{{ .Severity }}</td>
            </tr>
          {{ end }}
        {{ end }}
      {{ end }}
    </tbody>
  </table>
</body>
</html>
