pipeline {
    agent any

    environment {
        CLIENT_ID = '123askjdb01'
        CLIENT_SECRET = ';slkfdvn32e'
        APPLICATION_ID = 's35deg4345'
        SCA_API_URL = 'https://acbhs.com/integrations/sca-scans'
        SAST_API_URL = 'https://acbhs.com/integrations/sast-scans'
    }

    stages {
        stage('Clean Up Old Files') {
            steps {
                script {
                    sh 'rm -rf venv'
                    sh 'rm -rf project.zip'
                    sh 'rm -rf *.json'
                    sh 'rm -rf *.csv'
                    sh 'rm -rf *.sh'
                }
            }
        }

        stage('Checkout Code') {
            steps {
                checkout scm
            }
        }

        stage('Create ZIP Files') {
            steps {
                script {
                    sh 'rm -rf project_folder'
                    sh 'mkdir project_folder'
                    sh 'find . -maxdepth 1 -not -name "." -not -name ".." -not -name ".git" -not -name "venv" -not -name "project_folder" -exec mv {} project_folder/ \\;'
                    sh 'zip -r project.zip project_folder'
                }
            }
        }

        stage('Perform SCA Scan') {
            steps {
                script {
                    def response = sh(script: """
                        #!/bin/bash
                        curl --http1.1 -s -X POST \
                        -H "Client-ID: ${CLIENT_ID}" \
                        -H "Client-Secret: ${CLIENT_SECRET}" \
                        -F "projectZipFile=@project.zip" \
                        -F "applicationId=${APPLICATION_ID}" \
                        -F "scanName=JavaScript SCA Scan from Jenkins Pipeline" \
                        -F "language=JavaScript" \
                        "${SCA_API_URL}" || echo '{"canProceed":false,"vulnsTable":"[ERROR] SCA API failed."}'
                    """, returnStdout: true).trim()

                    def jsonResponse = readJSON(text: response)
                    def canProceedSCA = jsonResponse.getOrDefault('canProceed', false)
                    def vulnsTable = jsonResponse.getOrDefault('vulnsTable', '[No vulnerabilities data]')

                    def cleanVulnsTable = vulnsTable.replaceAll(/\x1B\[[;0-9]*m/, '')

                    echo "Vulnerabilities found during SCA:"
                    echo "${cleanVulnsTable}"

                    env.CAN_PROCEED_SCA = canProceedSCA.toString()
                }
            }
        }

        stage('Check SCA Result') {
            when {
                expression { return env.CAN_PROCEED_SCA != 'true' }
            }
            steps {
                error "SCA scan failed. Deployment cancelled."
            }
        }

        stage('Perform SAST Scan') {
            when {
                expression { return env.CAN_PROCEED_SCA == 'true' }
            }
            steps {
                script {
                    def response = sh(script: """
                        #!/bin/bash
                        curl --http1.1 -s -X POST \
                        -H "Client-ID: ${CLIENT_ID}" \
                        -H "Client-Secret: ${CLIENT_SECRET}" \
                        -F "projectZipFile=@project.zip" \
                        -F "applicationId=${APPLICATION_ID}" \
                        -F "scanName=JavaScript SAST Scan from Jenkins Pipeline" \
                        -F "language=JavaScript" \
                        "${SAST_API_URL}" || echo '{"canProceed":false,"vulnsTable":"[ERROR] SAST API failed."}'
                    """, returnStdout: true).trim()

                    def jsonResponse = readJSON(text: response)
                    def canProceedSAST = jsonResponse.getOrDefault('canProceed', false)
                    def vulnsTable = jsonResponse.getOrDefault('vulnsTable', '[No vulnerabilities data]')

                    def cleanVulnsTable = vulnsTable.replaceAll(/\x1B\[[;0-9]*m/, '')

                    echo "Vulnerabilities found during SAST:"
                    echo "${cleanVulnsTable}"

                    env.CAN_PROCEED_SAST = canProceedSAST.toString()
                }
            }
        }

        stage('Check SAST Result') {
            when {
                expression { return env.CAN_PROCEED_SAST != 'true' }
            }
            steps {
                error "SAST scan failed. Deployment cancelled."
            }
        }

        // Additional stages (e.g., deploy) can be added here
    }
}
