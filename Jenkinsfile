// Runs the checker on every build. If the script exits with 1, this stage fails
// and the build stops before anything ships. Same idea as adding
// `fossa analyze` and `fossa test` stages for a FOSSA customer.
pipeline {
    agent any
    stages {
        stage('Install') {
            steps {
                // A virtual environment keeps this project's libraries separate from the system's
                sh '''
                    python3 -m venv .venv
                    . .venv/bin/activate
                    pip install --quiet requests
                '''
            }
        }
        stage('OSS Policy Check') {
            steps {
                sh '''
                    . .venv/bin/activate
                    python3 oss_checker.py --file requirements.txt --fail-on-vulns
                '''
            }
        }
    }
    post {
        always {
            // Keep the CSV with the build so legal can download it later
            archiveArtifacts artifacts: 'oss_report.csv', allowEmptyArchive: true
        }
    }
}
