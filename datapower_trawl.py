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
        if self.in_cluster:
            config.load_incluster_config()
        else:
            config.load_kube_config()
        v1 = client.CoreV1Api()
        ret = v1.list_namespaced_pod(namespace=self.namespace)
        for i in ret.items:
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
    guages = {}

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
            target_name = l['LogTarget']['value']
            if target_name not in self.guages:
                self.guages[target_name] = {}
                self.guages[target_name]['processed'] = Gauge(
                    "{}_{}_processed".format(self.name, target_name).replace('-', '_'),
                    'Events dropped for logging target')
                self.guages[target_name]['dropped'] = Gauge(
                    "{}_{}_dropped".format(self.name, target_name).replace('-', '_'),
                    'Events dropped for logging target')
            self.guages[target_name]['processed'].set(l['EventsProcessed'])
            self.guages[target_name]['dropped'].set(l['EventsDropped'])

            logger.info("{}\t{}\t{}".format(
                l['LogTarget']['value'],
                l['EventsProcessed'],
                l['EventsDropped']
            ))


if __name__ == "__main__":
    net = DataPowerNet()
    net.find()
