pipeline {
	agent any

	stages {
	    stage('Build') {
           steps {
               echo 'Building..'

           }
       }
       stage('Test') {
           steps {
               echo 'Testing...'

           }
       }

		stage('OWASP DependencyCheck') {
			steps {
				dependencyCheck additionalArguments: '', odcInstallation: 'OWASP-check-730'
			}
		}
	}
	post {
		success {
			dependencyCheckPublisher pattern: 'dependency-check-report.xml'
		}

	}
}
