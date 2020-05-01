import requests
import logging
from kubernetes import client, config
from prometheus_client import Gauge
import urllib3

urllib3.disable_warnings()
logger = logging.getLogger(__name__)


class DataPowerNet(object):
    namespace = 'default'
    username = ''
    password = ''
    in_cluster = True
    items = []

    def __init__(self, config, trawler):
        # Takes in config object and trawler instance it's behind
        # In k8s or outside
        self.in_cluster = config.get('in_cluster', True)
        # Namespace to find datapower
        self.namespace = config.get('namespace', 'default')
        # Datapower username to use for REST calls
        self.username = config.get('username', 'admin')
        # Load password from secret `datapower_password`
        self.password = trawler.read_secret('datapower_password')
        if self.password is None:
            # Use out of box default password
            self.password = 'admin'

    def fish(self):
        # Go fishing for datapowers
        # Load appropriate k8s config
        if self.in_cluster:
            config.load_incluster_config()
        else:
            config.load_kube_config()
        # Initialise the k8s API
        v1 = client.CoreV1Api()
        # Retreive pod list for namespace
        ret = v1.list_namespaced_pod(namespace=self.namespace)
        for i in ret.items:
            # Only look at pods with the restPort is defined
            if 'restPort' in i.metadata.annotations and i.status.pod_ip:
                datapower = DataPower(
                    ip=i.status.pod_ip,
                    port=i.metadata.annotations['restPort'],
                    name=i.metadata.name,
                    username=self.username,
                    password=self.password)
                self.items.append(datapower)


class DataPower(object):
    domain = 'apiconnect'
    name = "datapower"
    username = None
    password = None
    ip = '127.0.0.1'
    gauges = {}

    def __init__(self, ip, port, name, username, password):
        self.ip = ip
        self.port = port
        self.name = name
        self.username = username
        self.password = password
        logger.info('DataPower {} initialised at {}:{}'.format(self.name, self.ip, self.port))
        try:
            self.logging_stats()
        except requests.exceptions.ConnectTimeout:
            logger.info(".. timed out (are you outside the cluster)..")

    def logging_stats(self):
        url = "https://{}:{}/mgmt/status/{}/LogTargetStatus".format(
            self.ip,
            self.port,
            self.domain)
        logging = requests.get(url,
                               auth=(self.username, self.password),
                               verify=False, timeout=1).json()

        for l in logging['LogTargetStatus']:
            target_name = "{}_{}".format(self.name, l['LogTarget']['value']).replace('-', '_')
            logger.info("Target name is {}".format(target_name))
            if target_name not in self.gauges:
                logger.info("Creating gauges")
                self.gauges[target_name] = {}
                self.gauges[target_name]['processed'] = Gauge(
                    "{}_processed".format(target_name),
                    'Events dropped for logging target')
                self.gauges[target_name]['dropped'] = Gauge(
                    "{}_dropped".format(target_name),
                    'Events dropped for logging target')
            logger.debug(self.gauges)
            logger.info("Setting guage {} to {}".format(
                self.gauges[target_name]['processed']._name, l['EventsProcessed']))
            self.gauges[target_name]['processed'].set(l['EventsProcessed'])
            logger.info("Setting guage {} to {}".format(
                self.gauges[target_name]['processed']._name, l['EventsDropped']))
            self.gauges[target_name]['dropped'].set(l['EventsDropped'])


if __name__ == "__main__":
    net = DataPowerNet()
    net.find()
