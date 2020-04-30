
@Library('velox') _

veloxPipeline { p ->
	def server = Artifactory.server 'na-artifactory'
	def rtDocker = Artifactory.docker server: server, credentialsId: 'slnode-artifactory'
	def buildInfo = Artifactory.newBuildInfo()
	def releaseName = env.CHANGE_ID ? env.CHANGE_TARGET : env.BRANCH_NAME

	def chartArchive

	p.branch(~/master|\d+(\.\d+)+/) {
        env.ARTIFACTS_DIR = "na.artifactory.swg-devops.com/artifactory/apic-monitoring"
        // set the primary build identifiers
        buildInfo.setName "trawler-${releaseName}"
        buildInfo.setNumber currentBuild.id
        // For easier referencing by other Jenkins builds/jobs
        env.ARTIFACTS_BUILD = "${buildInfo.name}/${buildInfo.number}"
	}

	env.DOCKER_TAG = "latest" //"${currentBuild.id}-${env.START_TIME}-${env.GIT_COMMIT}"
	env.DOCKER_IMAGE = "${env.DOCKER_REPO}/velox/${env.BRANCH_NAME}/trawler:${env.DOCKER_TAG}"

    p.common {
        stage('install dependencies') {
	          sh 'pip3 install setuptools pytest>=3.6 pytest-cov pytest-mock'
	          sh 'pip3 install --user -r requirements.txt'
        }
        stage('Run tests') {
	          sh 'coverage run --source . -m py.test'
            sh 'coverage xml'
        }

        stage('SonarQube Code Analysis') {
            if (env.BRANCH_NAME == "master") {
                try {
                    runSonarScanner()
                } catch (e) {
                }
            }
        }

        if (env.BRANCH_NAME ==~ /^PR-[0-9]*/) {
            echo "Skipping publish for PR build"
            currentBuild.result = 'SUCCESS'
            return
        }

        stage('build trawler image') {
	          sh 'docker build -t $DOCKER_IMAGE . '
//                sshagent(['slnode-ghe-ssh']) {
//                    sh """
//                        git clone git@github.ibm.com:velox/ilmt.git \$BUILD_DIR/../ilmt
//                        \$BUILD_DIR/../ilmt/swidtag.sh "--product-name=api_manager" "--release-name=${releaseName}" "--docker-image=\$DOCKER_IMAGE"
//                        """
//                }
        }

        img = docker.image(env.DOCKER_IMAGE)
        stage('push image') {
            img.push()
        }

    }
}
