import requests
import alog
import logging
from kubernetes import client, config
import urllib3

urllib3.disable_warnings()
logger = alog.use_channel("datapower")

# /mgmt/status/apiconnect/TCPSummary
# /mgmt/status/apiconnect/GatewayPeeringStatus


class DataPowerNet(object):
    namespace = 'default'
    username = ''
    password = ''
    use_kubeconfig = False
    items = {}

    def __init__(self, config, trawler):
        # Takes in config object and trawler instance it's behind
        # Use kubeconfig or in-cluster config for k8s comms
        self.use_kubeconfig = trawler.use_kubeconfig
        # Namespace to find datapower
        self.namespace = config.get('namespace', 'default')
        # Datapower username to use for REST calls
        self.username = config.get('username', 'admin')
        # Load password from secret `datapower_password`
        self.password = trawler.read_secret('datapower_password')
        self.trawler = trawler
        if self.password is None:
            # Use out of box default password
            self.password = 'admin'

    @alog.timed_function(logger.trace)
    def fish(self):
        # Go fishing for datapowers
        # Load appropriate k8s config
        if self.use_kubeconfig:
            config.load_kube_config()
        else:
            config.load_incluster_config()
        try:
            # Initialise the k8s API
            v1 = client.CoreV1Api()
            # Retreive pod list for namespace
            ret = v1.list_namespaced_pod(namespace=self.namespace)
            for i in ret.items:
                if (i.status.pod_ip and i.metadata.annotations and
                        'productName' in i.metadata.annotations and
                        'DataPower Gateway' in i.metadata.annotations['productName']):
                    # Use default port of 5554 if not annotated
                    port = i.metadata.annotations.get('restPort', 5554)
                    key = "{ip}:{port}".format(ip=i.status.pod_ip, port=port)
                    if key in self.items:
                        logger.debug("Seen existing DP again - just get metrics")
                    else:
                        if self.use_kubeconfig:
                            ip = '127.0.0.1'
                        else:
                            ip = i.status.pod_ip
                        self.items[key] = DataPower(
                            ip=ip,
                            port=port,
                            name=i.metadata.name,
                            username=self.username,
                            password=self.password,
                            trawler=self.trawler)
                    self.items[key].gather_metrics()
                    logger.info("DataPowers in list: {}".format(len(self.items)))
        except client.rest.ApiException as e:
            logger.error("Error calling kubernetes API")
            logger.exception(e)


class DataPower(object):
    domain = 'apiconnect'
    name = "datapower"
    username = None
    password = None
    v5c = False
    statistics_enabled = False
    ip = '127.0.0.1'
    trawler = None

    def __init__(self, ip, port, name, username, password, trawler):
        self.ip = ip
        self.port = port
        self.name = name
        self.username = username
        self.password = password
        self.get_info()
        self.trawler = trawler
        self.enable_statistics()
        logger.info('DataPower {} {} initialised at {}:{}'.format(self.name, self.v5c, self.ip, self.port))

    def get_info(self):
        try:
            logger.info("Check mode")
            url = "https://{}:{}/mgmt/config/{}/APIConnectGatewayService/default".format(
                self.ip,
                self.port,
                self.domain)
            state = requests.get(url,
                                 auth=(self.username, self.password),
                                 verify=False,
                                 timeout=1
                                 )
            if state.status_code == 200:
                if state.json()['APIConnectGatewayService'].get('V5CompatibilityMode', 'off') == 'on':
                    self.v5c = True
                    logger.info("DataPower has v5c enabled")
            else:
                logger.info("Failed to identify mode")

        except requests.exceptions.ConnectTimeout:
            logger.info(".. connect timed out (Check rest-mgmt is enabled and you have network connectivity)")
        except requests.exceptions.ReadTimeout:
            logger.info(".. read timed out (Check rest-mgmt is enabled and you have network connectivity)")
        except requests.exceptions.ConnectionError:
            logger.info(".. connection refused (Check rest-mgmt is enabled and you have network connectivity)")

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
            logger.info(".. connect timed out (Check rest-mgmt is enabled and you have network connectivity)")
        except requests.exceptions.ReadTimeout:
            logger.info(".. read timed out (Check rest-mgmt is enabled and you have network connectivity)")
        except requests.exceptions.ConnectionError:
            logger.info(".. connection refused (Check rest-mgmt is enabled and you have network connectivity)")

    def gather_metrics(self):
        try:
            self.fetch_data('TCPSummary', 'tcp', '_total')
            self.fetch_data('LogTargetStatus', 'logtarget')
            self.object_counts()
            if self.v5c:
                self.fetch_data('WSMAgentStatus', 'wsm')
            # Needs statistics enabled:
            if self.statistics_enabled:
                self.fetch_data('HTTPTransactions2', 'http')
        except requests.exceptions.ConnectTimeout:
            logger.info(".. connect timed out (Check rest-mgmt is enabled and you have network connectivity)")
        except requests.exceptions.ReadTimeout:
            logger.info(".. read timed out (Check rest-mgmt is enabled and you have network connectivity)")
        except requests.exceptions.ConnectionError:
            logger.info(".. connection refused (Check rest-mgmt is enabled and you have network connectivity)")

    def fetch_data(self, provider, label, suffix=''):
        logger.debug("Processing status provider {}".format(provider))
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
                try:
                    name = item[provider.replace('Status', '')]['value']
                    del(item[provider.replace('Status', '')])
                    logger.debug(item)
                    for key in item:
                        self.trawler.set_gauge('datapower',
                                               "{}.{}.{}{}".format(label, name, key, suffix), item[key], 
                                               pod_name=self.name)
                except KeyError:
                    logger.warning('Failed to parse response for {}'.format(provider))
                    logger.info(item)
        else:
            for key in data:
                self.trawler.set_gauge('datapower', "{}_{}{}".format(label, key, suffix), data[key], pod_name=self.name)

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
            self.trawler.set_gauge('datapower', "{}_total".format(item_class), counts[item_class], pod_name=self.name)

        logger.debug(counts)



# https://localhost:5554/mgmt/status/apiconnect/GatewayPeeringStatus
#      {
#        "Address": "172.30.131.201",
#        "Name": "rate-limit",
#        "PendingUpdates": 0,
#        "ReplicationOffset": 170111082,
#        "LinkStatus": "ok",
#        "Primary": "yes"
#      },

    def gateway_peering_status(self):
        logger.info("Processing status provider GatewayPeeringStatus")
        url = "https://{}:{}/mgmt/status/{}/GatewayPeeringStatus".format(
            self.ip,
            self.port,
            self.domain)
        status = requests.get(url,
                              auth=(self.username, self.password),
                              verify=False, timeout=1).json()
        logger.debug(status)

        for entry in status["GatewayPeeringStatus"]:
            if self.ip == entry["Address"]:
                labels = {}
                labels["peer_group"] = entry["Name"]
                pvalue = 0
                lvalue = 0
                if entry["Primary"] == "yes":
                    pvalue = 1
                if entry["LinkStatus"] == "ok":
                    lvalue = 1
                self.trawler.set_gauge('datapower', "gateway_peering_primary_info", pvalue, pod_name=self.name, labels)
                self.trawler.set_gauge('datapower', "gateway_peering_primary_link", lvalue, pod_name=self.name, labels)
                self.trawler.set_gauge('datapower', "gateway_peering_primary_offset", entry["ReplicationOffset"], pod_name=self.name, labels)


if __name__ == "__main__":
    net = DataPowerNet()
    net.find()
