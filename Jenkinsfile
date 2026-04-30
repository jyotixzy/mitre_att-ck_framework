pipeline {
    agent any
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        stage('Run Code') {
            steps {
                echo 'Running the application...'
                sh 'python3 main.py analyze /home/jyoti/Downloads/URL2.eml'
            }
        }
    }
    post {
        always {
            echo 'Pipeline execution finished successfully.'
        }
    }
}
