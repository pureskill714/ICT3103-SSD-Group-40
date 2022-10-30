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
	       sh 'chmod +x db/entrypoint.sh'
	       sh 'chmod +x db/configure-db.sh'
               sh 'docker compose up -d'
	       sh 'docker exec ict3103-ssd-group-40-flask_app-1 coverage run -m pytest -v -s --junitxml=reports/result.xml'
	       echo 'Copy result.xml into Jenkins container'
	       sh 'rm -rf reports; mkdir reports'
               sh 'docker cp ict3103-ssd-group-40-flask_app-1:/flask/reports/result.xml reports/'
	       echo "Cleanup"
	       sh 'docker stop ict3103-ssd-group-40-flask_app-1'
	       sh 'docker stop ict3103-ssd-group-40-db-1'
	       sh 'docker rm ict3103-ssd-group-40-flask_app-1'
	       sh 'docker rm ict3103-ssd-group-40-db-1'
	       sh 'docker rmi ict3103-ssd-group-40-flask_app'
	       sh 'docker rmi ict3103-ssd-group-40-db'
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
