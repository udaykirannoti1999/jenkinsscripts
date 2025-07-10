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

                    // Upload both JSON and HTML reports
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

def buildDockerImage(imageName, imageTag) {
    sh """
        if docker images | grep -q ${imageName}; then
            docker rmi -f ${imageName}:${imageTag}
        fi
    """
    sh "docker build -t ${imageName}:${imageTag} ."
}

def scanDockerImage(imageFullName) {
    // Generate JSON + HTML using local html.tpl
    sh """
        mkdir -p ${env.TRIVY_CACHE_DIR}
        trivy image --cache-dir ${env.TRIVY_CACHE_DIR} --format json -o ${env.TRIVY_JSON_REPORT} ${imageFullName}
        trivy image --cache-dir ${env.TRIVY_CACHE_DIR} --format template --template "@html.tpl" -o ${env.TRIVY_HTML_REPORT} ${imageFullName}
    """

    def result = readJSON file: env.TRIVY_JSON_REPORT
    return result.Results.collectMany { it.Vulnerabilities ?: [] }
                         .count { it.Severity in ['HIGH', 'CRITICAL'] }
}
