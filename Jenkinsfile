pipeline {
	agent any
	stages {
	    stage('Build') {
           steps {
               echo 'Building..'
               sh 'docker compose build'
           }
       }
       stage('Test') {
           steps {
               echo 'Testing..'
//                sh 'docker stop $CONTAINER_NAME || true'
//                sh 'docker rm $CONTAINER_NAME || true'
//                sh 'docker run --name $CONTAINER_NAME $DOCKER_HUB_REPO /bin/bash -c "pytest test.py && flake8"'
	       sh 'docker network inspect frontnet >/dev/null 2>&1 || docker network create --driver bridge frontnet'
               sh 'docker network inspect backnet >/dev/null 2>&1 || docker network create --driver bridge backnet'
               sh 'docker compose up -d'
           }
       }

		stage('OWASP DependencyCheck') {
			steps {
				dependencyCheck additionalArguments: '', odcInstallation: 'OWASP-check-730'
			}
		}

		stage('Deploy') {
           steps {
               echo 'Deploying....'
//                sh 'docker stop $CONTAINER_NAME || true'
//                sh 'docker rm $CONTAINER_NAME || true'
//                sh 'docker run -d -p 5000:5000 --name $CONTAINER_NAME $DOCKER_HUB_REPO'
           }
       }
	}
	post {
		success {
			dependencyCheckPublisher pattern: 'dependency-check-report.xml'
		}
		// always {
            // Archive Unit and integration test results, if any
            // junit allowEmptyResults: true,
            //        testResults: '**/target/surefire-reports/TEST-*.xml, **/target/failsafe-reports/*.xml'
            // mailIfStatusChanged env.EMAIL_RECIPIENTS
        // }

	}
}
