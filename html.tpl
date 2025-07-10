{{- $vulns := list -}}
{{- range .Results }}
  {{- $target := .Target }}
  {{- range .Vulnerabilities }}
    {{- if or (eq .Severity "HIGH") (eq .Severity "CRITICAL") }}
      {{- $_ := set . "Target" $target -}}
      {{- $vulns = append $vulns . -}}
    {{- end }}
  {{- end }}
{{- end }}

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Trivy Vulnerability Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .critical { color: red; font-weight: bold; }
        .high { color: orange; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Trivy Report - HIGH/CRITICAL Vulnerabilities Only</h1>
    <p>Total vulnerabilities: {{ len $vulns }}</p>
    <table>
        <tr>
            <th>Target</th>
            <th>Vulnerability ID</th>
            <th>Package</th>
            <th>Installed Version</th>
            <th>Fixed Version</th>
            <th>Severity</th>
            <th>Title</th>
        </tr>
        {{- range $vulns }}
        <tr>
            <td>{{ .Target }}</td>
            <td>{{ .VulnerabilityID }}</td>
            <td>{{ .PkgName }}</td>
            <td>{{ .InstalledVersion }}</td>
            <td>{{ .FixedVersion }}</td>
            <td class="{{ lower .Severity }}">{{ .Severity }}</td>
            <td>{{ .Title }}</td>
        </tr>
        {{- end }}
    </table>
</body>
</html>
