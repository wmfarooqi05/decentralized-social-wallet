pipeline {
    agent none

    stages {
        stage ('docker-build') {
            agent any

            steps {
                echo 'Hello, '
                sh 'chmod +x ./docker-production.bash'
                sh './docker-production.bash'            
            }
        }
    }
}