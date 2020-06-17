
@Library('velox') _

veloxPipeline { p ->
    def server = Artifactory.server 'na-artifactory'
    def rtDocker = Artifactory.docker server: server, credentialsId: 'slnode-artifactory'
    def buildInfo = Artifactory.newBuildInfo()
    def releaseName = env.CHANGE_ID ? env.CHANGE_TARGET : env.BRANCH_NAME
    def tag = sh(returnStdout: true, script: "git tag --contains | head -1").trim()
    def chartArchive

    p.branch(~/main|\d+(\.\d+)+/) {
        env.ARTIFACTS_DIR = "na.artifactory.swg-devops.com/artifactory/apic-monitoring"
        // set the primary build identifiers
        buildInfo.setName "trawler-${releaseName}"
        buildInfo.setNumber currentBuild.id
        // For easier referencing by other Jenkins builds/jobs
        env.ARTIFACTS_BUILD = "${buildInfo.name}/${buildInfo.number}"
    }
  if (tag) {
      env.DOCKER_TAG = "${tag}"
  } else {
    env.DOCKER_TAG = "build${currentBuild.id}" 
  }
    env.DOCKER_IMAGE = "${env.DOCKER_REPO}/velox/${env.BRANCH_NAME}/trawler"

    p.common {
        stage('install dependencies') {
            sh 'pip3 install setuptools'
            sh 'pip3 install -r requirements-dev.txt'
            sh 'pip3 install --user -r requirements.txt'
        }
        stage('Run tests') {
            sh 'SECRETS=test-assets coverage run --source . -m py.test'
            sh 'coverage xml'
        }

        stage('SonarQube Code Analysis') {
            if (env.BRANCH_NAME == "main") {
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
            sh 'docker build -t $DOCKER_IMAGE:$DOCKER_TAG -t $DOCKER_IMAGE:latest . '
        }

        img = docker.image(env.DOCKER_IMAGE)
        stage('push image') {
            img.push()
        }

    }
}
