import requests
import json
import time
import datetime
import logging
from kubernetes import client, config
from prometheus_client import Gauge
import urllib3
import base64

urllib3.disable_warnings()
logger = logging.getLogger(__name__)

# /mgmt/status/apiconnect/TCPSummary


class ManagerNet(object):
    namespace = 'apic-management'
    username = ''
    password = ''
    hostname = ''
    client_id = "caa87d9a-8cd7-4686-8b6e-ee2cdc5ee267"
    client_secret = "3ecff363-7eb3-44be-9e07-6d4386c48b0b"
    token = None
    token_expires = 0
    max_frequency = 600
    data = {}
    data_time = 0
    use_kubeconfig = False
    errored = False
    version = None
    trawler = None

    def __init__(self, config, trawler):
        # Takes in config object and trawler instance it's behind
        # Use kubeconfig or in-cluster config for k8s comms
        self.use_kubeconfig = trawler.use_kubeconfig
        # Namespace to find managemnet pods
        self.namespace = config.get('namespace', 'default')
        # Maximum frequency to pull data from APIC
        self.max_frequency = int(config.get('frequency', 600))
        if 'secret' in config:
            # If config points to a secret, then load from that
            # either in this namespace, or the specified one
            self.load_credentials_from_secret(
                config.get('secret'),
                config.get('secret_namespace', self.namespace))
        else:
            # Cloud manager username to use for REST calls
            self.username = config.get('username', 'admin')
            # Load password from secret `cloudmanager_password`
            self.password = trawler.read_secret('cloudmanager_password')
        if self.password is None:
            # Use out of box default password
            self.password = 'admin'
        self.version = Gauge('apiconnect_build_info',
                             "A metric with a constant '1' value labeled with API Connect version details",
                             ["version", "juhu_release"])
        self.hostname = self.find_hostname()
        logger.debug("Hostname found is {}".format(self.hostname))
        self.trawler = trawler

    def load_credentials_from_secret(self, secret_name, namespace):
        try:
            if self.use_kubeconfig:
                config.load_kube_config()
            else:
                config.load_incluster_config()
            v1 = client.CoreV1Api()
            logger.info("Loading cloud manager credentials from secret {} in namespace {}".format(secret_name, namespace))
            # Get certificates to communicate with analytics
            secrets_response = v1.read_namespaced_secret(name=secret_name, namespace=namespace)
            self.password = base64.b64decode(secrets_response.data['password']).decode('utf-8')
            self.username = base64.b64decode(secrets_response.data['username']).decode('utf-8')
            logger.info("Username to use is {}, password length is {}".format(self.username, len(self.password)))
        except client.rest.ApiException as e:
            logger.error('Error calling kubernetes API')
            logger.exception(e)

    def find_hostname(self):
        try:
            if self.use_kubeconfig:
                logger.info("Using KUBECONFIG")
                config.load_kube_config()
                v1beta = client.ExtensionsV1beta1Api()
                ingresslist = v1beta.list_namespaced_ingress(namespace=self.namespace)
                for ing in ingresslist.items:
                    if ing.metadata.name.endswith('apiconnect-api') or ing.metadata.name.endswith('platform-api'):
                        logger.info("Identified ingress host: {}".format(ing.spec.rules[0].host))
                        return ing.spec.rules[0].host
            else:
                logger.info("In cluster, so looking for juhu service")
                config.load_incluster_config()
                # Initialise the k8s API
                v1 = client.CoreV1Api()
                # Identify juhu service
                servicelist = v1.list_namespaced_service(namespace=self.namespace)
                logger.info("found {} services in namespace {}".format(len(servicelist.items), self.namespace))
                for service in servicelist.items:
                    if 'juhu' in service.metadata.name:
                        for port_object in service.spec.ports:
                            if port_object.name == 'https-platform' or port_object.name == 'platform-api':
                                port = port_object.port
                        self.version.labels(
                            service.metadata.annotations.get('productVersion', 'unknown'),
                            service.metadata.annotations.get('release', 'unknown')).set(1)
                        hostname = "{}.{}.svc:{}".format(service.metadata.name, self.namespace, port)
                        logger.info("Identified service host: {}".format(hostname))
                        return hostname
        except client.rest.ApiException as e:
            logger.error("Error calling kubernetes API")
            logger.exception(e)

    def fish(self):
        if self.errored:
            logger.debug("Disabled because a fatal error already occurred")
            return

        # Allow 10 seconds to run
        if self.token_expires - 10 < time.time():
            self.get_token(self.hostname)
        data_age = int(time.time()) - self.data_time
        logging.info("Data is {} seconds old".format(data_age))

        if self.token:
            if (data_age > self.max_frequency):
                logging.info("Getting data from API Manager")
                url = "https://{}/api/cloud/topology".format(self.hostname)
                response = requests.get(
                    url=url,
                    headers={
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Authorization": "Bearer {}".format(self.token),
                    },
                    verify=False
                )
                if response.status_code == 200:
                    self.data = response.json()
                    logging.debug(self.data)
                    self.data_time = int(time.time())
                    logger.info("Caching data - time = {}".format(self.data_time))
            else:
                logging.info("Using cached data")
                logging.debug(self.data)
        else:
            logging.warning("No token")
        if 'counts' in self.data:
            for object_type in self.data['counts']:
                logger.debug("Type: {}, Value: {}".format(object_type, self.data['counts'][object_type]))
                self.trawler.set_gauge('manager', object_type, self.data['counts'][object_type])

    # Get the authorization bearer token
    # See https://chrisphillips-cminion.github.io/apiconnect/2019/09/18/GettingoAuthTokenFromAPIC.html
    def get_token(self, host):
        logging.debug("Getting bearer token")

        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        data = {'username': self.username,
                'password': self.password,
                'realm': 'admin/default-idp-1',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'grant_type': 'password'}

        url = "https://{}/api/token".format(host)
        response = requests.post(
            url,
            headers=headers,
            data=json.dumps(data),
            verify=False)

        if response.status_code == 200:
            json_data = response.json()
            self.token = json_data['access_token']
            self.token_expires = json_data['expires_in'] + time.time()
            logger.info("Token expires at {} UTC".format(datetime.datetime.utcfromtimestamp(int(self.token_expires))))
        else:
            logger.error("Disabled manager net as failed to get bearer token: {}".format(response.status_code))
            self.errored = True

if __name__ == "__main__":
    net = ManagerNet({"namespace": "apic-management"}, None)
    net.fish()
