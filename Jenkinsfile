pipeline {
    agent any
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        stage('Build') {
            steps {
                echo 'Installing dependencies...'
                sh 'pip install -r requirements.txt' 
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
            echo 'Pipeline execution finished.'
        }
    }
}
