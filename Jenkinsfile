pipeline {
	agent any
	environment {
        DOCKER_HUB_REPO = "talha1995/test"
        CONTAINER_NAME_FLASK = "3x03_docker-flask_app-1"
	CONTAINER_NAME_DB = "3x03_docker-db-1"
	IMAGE_NAME_FLASK = "3x03_docker-flask_app"
	IMAGE_NAME_DB = "3x03_docker-db"
    	}

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
	       sh 'docker exec $CONTAINER_NAME_FLASK coverage run -m pytest -v -s --junitxml=reports/result.xml'
	       echo 'Copy result.xml into Jenkins container'
	       sh 'rm -rf reports; mkdir reports'
               sh 'docker cp $CONTAINER_NAME_FLASK:/flask/reports/result.xml reports/'
	       echo "Cleanup"
	       sh 'docker stop $CONTAINER_NAME_FLASK'
	       sh 'docker stop $CONTAINER_NAME_DB'
	       sh 'docker rm $CONTAINER_NAME_FLASK'
	       sh 'docker rm $CONTAINER_NAME_DB'
	       sh 'docker rmi $IMAGE_NAME_FLASK'
	       sh 'docker rmi $IMAGE_NAME_DB'
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
		 always {
            // Archive Unit and integration test results, if any
             junit allowEmptyResults: true,
                    testResults: 'reports/*.xml'
            // mailIfStatusChanged env.EMAIL_RECIPIENTS
         }

	}
}
