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
        IMAGE_FULL = "${IMAGE_NAME}:${IMAGE_TAG}"
        TRIVY_CACHE_DIR = "/tmp/trivy-cache"
        TRIVY_HTML_REPORT = "trivy-report.html"
        TRIVY_JSON_REPORT = "scan_result.json"
        S3_BUCKET = "new-static123"
        VULN_THRESHOLD = 4
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

        stage('Scan Image with Trivy') {
            steps {
                script {
                    def highVulns = scanDockerImage(env.IMAGE_FULL)
                    echo "🔎 Number of HIGH/CRITICAL vulnerabilities: ${highVulns}"

                    if (highVulns >= env.VULN_THRESHOLD.toInteger()) {
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
                    echo "⚠️ Trivy HTML report not found. Skipping HTML publishing."
                }
            }
        }
    }
}

// ✅ Functions MUST go OUTSIDE the pipeline block 👇

def writePythonScript() {
    writeFile file: 'generate_html_report.py', text: '''import json
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
'''
}

def buildDockerImage(imageName, imageTag) {
    sh """
        if docker images | grep -q ${imageName}; then
            docker rmi -f ${imageName}:${imageTag}
        fi
        docker build -t ${imageName}:${imageTag} .
    """
}

def scanDockerImage(imageFullName) {
    writePythonScript() // ✅ Ensures script is written

    sh """
        mkdir -p ${env.TRIVY_CACHE_DIR}

        trivy image --cache-dir ${env.TRIVY_CACHE_DIR} \
                    --format json \
                    -o ${env.TRIVY_JSON_REPORT} \
                    ${imageFullName}

        python3 generate_html_report.py ${env.TRIVY_JSON_REPORT} ${env.TRIVY_HTML_REPORT}
    """

    def result = readJSON file: env.TRIVY_JSON_REPORT
    return result.Results.collectMany { it.Vulnerabilities ?: [] }
                         .count { it.Severity in ['HIGH', 'CRITICAL'] }
}
