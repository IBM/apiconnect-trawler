import requests
import logging
from kubernetes import client, config
from prometheus_client import Gauge
import urllib3

urllib3.disable_warnings()
logger = logging.getLogger(__name__)

# /mgmt/status/apiconnect/TCPSummary


class DataPowerNet(object):
    namespace = 'default'
    username = ''
    password = ''
    in_cluster = True
    items = {}

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
                key = "{ip}:{port}".format(ip=i.status.pod_ip, port=i.metadata.annotations['restPort'])
                if key in self.items:
                    logger.info("Seen existing DP again - just get metrics")
                else:
                    if self.in_cluster:
                        ip = i.status.pod_ip
                    else:
                        ip = '127.0.0.1'
                    self.items[key] = DataPower(
                        ip=ip,
                        port=i.metadata.annotations['restPort'],
                        name=i.metadata.name,
                        username=self.username,
                        password=self.password)
                self.items[key].gather_metrics()
                logger.info("DataPowers in list: {}".format(len(self.items)))


class DataPower(object):
    domain = 'apiconnect'
    name = "datapower"
    username = None
    password = None
    statistics_enabled = False
    ip = '127.0.0.1'
    gauges = {}

    def __init__(self, ip, port, name, username, password):
        self.ip = ip
        self.port = port
        self.name = name
        self.username = username
        self.password = password
        logger.info('DataPower {} initialised at {}:{}'.format(self.name, self.ip, self.port))
        self.enable_statistics()

    def enable_statistics(self):
        try:
            # TODO - first check if statistics are already enabled via
            #  https://127.0.0.1:5554/mgmt/config/apiconnect/Statistics

            logger.info("Attempt to enable statistics")
            url = "https://{}:{}/mgmt/config/{}/Statistics/default".format(
                self.ip,
                self.port,
                self.domain)
            state = requests.put(url,
                                 auth=(self.username, self.password),
                                 data='{"Statistics":{"LoadInterval":1000,"mAdminState":"enabled","name":"default"}}',
                                 verify=False,
                                 timeout=1
                                 )
            if state.status_code == 200:
                self.statistics_enabled = True
            else:
                self.statistics_enabled = False
        except requests.exceptions.ConnectTimeout:
            logger.info(".. timed out (are you outside the cluster)..")

    def gather_metrics(self):
        try:
            self.fetch_data('TCPSummary', 'datapower_tcp', '_total')
            self.fetch_data('LogTargetStatus', 'datapower_logtarget')
            self.object_counts()
            # Needs statistics enabled:
            if self.statistics_enabled:
                self.fetch_data('HTTPTransactions2', 'datapower_http')
        except requests.exceptions.ConnectTimeout:
            logger.info(".. timed out (are you outside the cluster)..")

    def set_gauge(self, target_name, value):
        if type(value) is float or type(value) is int:
            target_name = target_name.replace('-', '_')
            if target_name not in self.gauges:
                logger.info("Creating gauges")
                self.gauges[target_name] = Gauge(
                    target_name,
                    target_name, ['pod'])
            logger.debug("Setting gauge {} to {}".format(
                self.gauges[target_name]._name, value))
            self.gauges[target_name].labels(self.name).set(value)

    def fetch_data(self, provider, label, suffix=''):
        logger.info("Processing status provider {}".format(provider))
        url = "https://{}:{}/mgmt/status/{}/{}".format(
            self.ip,
            self.port,
            self.domain,
            provider)
        status = requests.get(url,
                              auth=(self.username, self.password),
                              verify=False, timeout=1).json()
        logger.debug(status)
        data = status.get(provider, {})
        if type(data) is list:
            for item in data:
                name = item[provider.replace('Status', '')]['value']
                del(item[provider.replace('Status', '')])
                logger.debug(item)
                for key in item:
                    self.set_gauge("{}_{}_{}{}".format(label, name, key, suffix), item[key])
        else:
            for key in data:
                self.set_gauge("{}_{}{}".format(label, key, suffix), data[key])

# https://127.0.0.1:5554/mgmt/status/apiconnect/ObjectStatus
    def object_counts(self):
        logger.info("Processing status provider ObjectStatus")
        url = "https://{}:{}/mgmt/status/{}/ObjectStatus".format(
            self.ip,
            self.port,
            self.domain)
        status = requests.get(url,
                              auth=(self.username, self.password),
                              verify=False, timeout=1).json()
        logger.debug(status)
        data = status.get('ObjectStatus', [])
        counts = {}
        for item in data:
            if item['Class'] in counts:
                counts[item['Class']] += 1
            else:
                counts[item['Class']] = 1
        for item_class in counts:
            self.set_gauge("datapower_{}_total".format(item_class), counts[item_class])

        logger.debug(counts)


if __name__ == "__main__":
    net = DataPowerNet()
    net.find()
