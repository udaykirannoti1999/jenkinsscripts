pipeline {
    agent {
        docker {
            image 'jenkins-inbound-agent-custom'
            args '-v /var/run/docker.sock:/var/run/docker.sock --group-add 113'
        }
    }

    environment {
        IMAGE_NAME = "trivy-sample"
        IMAGE_TAG = "latest"
        IMAGE_FULL = "trivy-sample:latest"
        TRIVY_CACHE_DIR = "/tmp/trivy-cache"
        TRIVY_HTML_REPORT = "trivy-report.html"
        TRIVY_JSON_REPORT = "scan_result.json"
        S3_BUCKET = "new-static123"
    }

    stages {
        stage('Clone Repo') {
            steps {
                git branch: 'main', url: 'https://github.com/udaykirannoti1999/my-devopsproject.git'
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    buildDockerImage(env.IMAGE_NAME, env.IMAGE_TAG)
                }
            }
        }

        stage('Prepare HTML Template') {
            steps {
                script {
                    writeFile file: 'html.tpl', text: '''
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
'''
                }
            }
        }

        stage('Scan Image with Trivy') {
            steps {
                script {
                    def highVulns = scanDockerImage(env.IMAGE_FULL)
                    echo "Number of HIGH/CRITICAL vulnerabilities: ${highVulns}"
                    if (highVulns >= 4) {
                        error("❌ Build failed: ${highVulns} HIGH/CRITICAL vulnerabilities detected.")
                    }
                }
            }
        }

        stage('Upload Scan Reports to S3') {
            steps {
                script {
                    def s3KeyJson = "scan-reports/${IMAGE_NAME}-${IMAGE_TAG}-scan_result.json"
                    def s3KeyHtml = "scan-reports/${IMAGE_NAME}-${IMAGE_TAG}-trivy-report.html"

                    sh """
                        aws s3 cp ${TRIVY_JSON_REPORT} s3://${S3_BUCKET}/${s3KeyJson}
                        aws s3 cp ${TRIVY_HTML_REPORT} s3://${S3_BUCKET}/${s3KeyHtml}
                    """
                    echo "✅ Uploaded scan reports to S3"
                }
            }
        }

        stage('Push Image or Deploy (optional)') {
            when {
                expression {
                    return currentBuild.result == null || currentBuild.result == 'SUCCESS'
                }
            }
            steps {
                echo "✅ Image passed scan. Proceed to deployment or registry push."
            }
        }
    }

    post {
        always {
            script {
                sh "ls -l ${env.TRIVY_HTML_REPORT} || echo '⚠️ HTML report not found'"
                if (fileExists(env.TRIVY_HTML_REPORT)) {
                    publishHTML([
                        reportDir: '.',
                        reportFiles: env.TRIVY_HTML_REPORT,
                        reportName: 'Trivy Vulnerability Report',
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true
                    ])
                } else {
                    echo "⚠️ Trivy HTML report not found. Skipping publishing."
                }
            }
        }
    }
}

def buildDockerImage(imageName, imageTag) {
    sh """
        if docker images | grep -q ${imageName}; then
            docker rmi -f ${imageName}:${imageTag}
        fi
    """
    sh "docker build -t ${imageName}:${imageTag} ."
}

def scanDockerImage(imageFullName) {
    sh """
        mkdir -p ${env.TRIVY_CACHE_DIR}
        trivy image --cache-dir ${env.TRIVY_CACHE_DIR} --format json -o full_report.json ${imageFullName}

        jq '{
          Target,
          Vulnerabilities: [.Vulnerabilities[] | select((.Severity == "HIGH" or .Severity == "CRITICAL") and .FixedVersion != null)]
        }' full_report.json > ${env.TRIVY_JSON_REPORT}

        trivy image --cache-dir ${env.TRIVY_CACHE_DIR} --format template --template "@html.tpl" -o ${env.TRIVY_HTML_REPORT} ${imageFullName}
    """

    def result = readJSON file: env.TRIVY_JSON_REPORT
    return result.Vulnerabilities.size()
}
