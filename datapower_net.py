import base64
import alog
import requests
from kubernetes import client, config
import urllib3

urllib3.disable_warnings()
logger = alog.use_channel("datapower")

# /mgmt/status/apiconnect/TCPSummary
# /mgmt/status/apiconnect/GatewayPeeringStatus


class DataPowerNet():
    """ Collect Metrics from DataPower """
    namespace = None
    username = ''
    password = None
    use_kubeconfig = False
    items = {}
    api_tests = None

    def __init__(self, config, trawler):
        # Takes in config object and trawler instance it's behind
        # Use kubeconfig or in-cluster config for k8s comms
        self.use_kubeconfig = trawler.use_kubeconfig
        # Namespace to find datapower
        self.namespace = config.get('namespace', None)
        # Datapower username to use for REST calls
        self.username = config.get('username', 'admin')
        self.secret = config.get('secret', 'gateway-admin-secret')
        api_test_config = config.get('api_tests', None)
        if api_test_config and api_test_config['enabled'] == True:
            self.api_tests = api_test_config['apis']
        # Load password from secret `datapower_password`
        try:
            self.password = trawler.read_secret('datapower_password')
        except FileNotFoundError:
            self.password = None

        self.trawler = trawler

    def load_password_from_secret(self, secret_name, namespace):
        """ Load password from secret using kubernetes apis """
        try:
            if self.use_kubeconfig:
                config.load_kube_config()
            else:
                config.load_incluster_config()
            v1 = client.CoreV1Api()
            secrets_response = v1.read_namespaced_secret(name=secret_name, namespace=namespace)
            if 'password' in secrets_response.data:
                password = base64.b64decode(secrets_response.data['password']).decode('utf-8')
                logger.info("Password length is {}".format(len(password)))
            return password
        except client.rest.ApiException as exception:
            logger.error('Error calling kubernetes API')
            logger.debug(exception)


    @alog.timed_function(logger.trace)
    def fish(self):
        """ Go fishing for datapowers """
        # Load appropriate k8s config
        if self.use_kubeconfig:
            config.load_kube_config()
        else:
            config.load_incluster_config()
        v1 = client.CoreV1Api()
        try:
            if None is self.namespace:
                pods = v1.list_pod_for_all_namespaces(
                    label_selector="app.kubernetes.io/component=datapower").items
            else:
                pods = v1.list_namespaced_pod(
                    label_selector="app.kubernetes.io/component=datapower", 
                    namespace=self.namespace).items
            for i in pods:
                # Use default port of 5554 if not annotated
                port = i.metadata.annotations.get('restPort', 5554)
                if self.use_kubeconfig:
                    ip = '127.0.0.1'
                else:
                    ip = i.status.pod_ip
                dp_key = "{}:{}".format(i.metadata.namespace, i.metadata.name)
                if dp_key not in self.items:
                    if self.password:
                        password = self.password
                    else:
                        password = self.load_password_from_secret(self.secret, i.metadata.namespace)
                    self.items[dp_key] = DataPower(
                        ip=ip,
                        port=port,
                        name=i.metadata.name,
                        namespace=i.metadata.namespace,
                        username=self.username,
                        password=password,
                        trawler=self.trawler,
                        api_tests=self.api_tests
                        )
                self.items[dp_key].gather_metrics()
                logger.info("DataPowers in list: {}".format(len(pods)))
        except client.rest.ApiException as exception:
            logger.error("Error calling kubernetes API")
            logger.debug(exception)



class DataPower():
    """ Object representing each datapower pod """
    domain = 'apiconnect'
    name = "datapower"
    namespace = "default"
    username = None
    password = None
    v5c = False
    statistics_enabled = False
    ip = '127.0.0.1'
    port = 5554
    apiPort = 9443
    trawler = None
    api_tests = None
    labels = {}

    def __init__(self, ip, port, name, namespace, username, password, trawler, api_tests=None):
        self.ip = ip
        self.port = port
        self.name = name
        self.namespace = namespace
        self.username = username
        self.password = password
        self.get_info()
        self.trawler = trawler
        self.api_tests = api_tests
        self.are_statistics_enabled()
        self.labels = {"namespace": self.namespace}
        logger.info('DataPower {} {} initialised at {}:{}'.format(self.name, self.v5c, self.ip, self.port))

    def get_info(self):
        """ Get DP mode info """
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

    def are_statistics_enabled(self):
        """ Are statistics enabled?"""
        try:
            logger.info("Are statistics enabled?")
            url = "https://{}:{}/mgmt/config/{}/Statistics".format(
                self.ip,
                self.port,
                self.domain)
            state = requests.get(url,
                                 auth=(self.username, self.password),
                                 verify=False,
                                 timeout=1
                                 )
            logger.trace(state.text)
            if state.status_code == 200:
                if state.json()["Statistics"]["mAdminState"] == "enabled":
                    self.statistics_enabled = True
                    logger.info("Statistics are enabled")
                else:
                    self.statistics_enabled = False
                    logger.info("Statistics are not enabled, disabled collecting")
            else:
                self.statistics_enabled = False
                logger.info("Statistics are not enabled, disabled collecting")
        except requests.exceptions.ConnectTimeout:
            logger.info(".. connect timed out (Check rest-mgmt is enabled and you have network connectivity)")
        except requests.exceptions.ReadTimeout:
            logger.info(".. read timed out (Check rest-mgmt is enabled and you have network connectivity)")
        except requests.exceptions.ConnectionError:
            logger.info(".. connection refused (Check rest-mgmt is enabled and you have network connectivity)")

    def gather_metrics(self):
        """ Gather datapower metrics """
        self.fetch_data('AnalyticsEndpointStatus', 'analytics')
        self.fetch_data('TCPSummary', 'tcp', '_total')
        self.fetch_data('LogTargetStatus', 'logtarget')
        self.object_counts()
        self.fetch_document_cache_summary()
        if self.v5c:
            self.fetch_data('WSMAgentStatus', 'wsm')
        # Needs statistics enabled:
        if self.statistics_enabled:
            self.fetch_data('HTTPTransactions2', 'http')
        if self.api_tests:
            for api in self.api_tests:
                self.invoke_api(api)


    def fetch_data(self, provider, label, suffix=''):
        """ fetch data from a status provider """
        try:
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
            labels = self.labels
            if type(data) is list:
                for item in data:
                    try:
                        name = item[provider.replace('Status', '')]['value']
                        del(item[provider.replace('Status', '')])
                        logger.debug(item)
                        for key in item:
                            self.trawler.set_gauge(
                                'datapower',
                                "{}.{}.{}{}".format(label, name, key, suffix), item[key], 
                                pod_name=self.name, labels=self.labels)
                    except KeyError:
                        logger.warning('Failed to parse response for {}'.format(provider))
                        logger.info(item)
            else:
                for key in data:
                    self.trawler.set_gauge(
                        'datapower', 
                        "{}_{}{}".format(label, key, suffix), 
                        data[key], 
                        pod_name=self.name, 
                        labels=labels)
        except requests.exceptions.RequestException as e:
            logger.info("{}: {} (Check rest-mgmt is enabled and you have network connectivity)".format(provider, e.strerror))

# https://127.0.0.1:5554/mgmt/status/apiconnect/ObjectStatus
    def object_counts(self):
        """ Count objects within datapower domain """
        logger.info("Processing status provider ObjectStatus")
        try:
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
                self.trawler.set_gauge('datapower', "{}_total".format(item_class), counts[item_class], pod_name=self.name, labels=self.labels)

            logger.debug(counts)
        except requests.exceptions.RequestException as e:
            logger.info("Failed to get object count: {} (Check rest-mgmt is enabled and you have network connectivity)".format(e.strerror))


    def fetch_document_cache_summary(self, suffix=''):
        """ fetch data from a status provider """
        if self.v5c:
            provider = "DocumentCachingSummary"
            key = "XMLManager"
        else:
            provider = "APIDocumentCachingSummary"
            key = "APIGateway"
        try:
            logger.debug("Retrieving cache summary")
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
            if type(data) is not list:
                data = [data]
            
            for item in data:
                try:
                    name = item[key]['value']
                    if name in ['webapi', 'webapi-internal', 'apiconnect']:
                        del item[key]
                        logger.debug(item)
                        for key in item:
                            self.trawler.set_gauge(
                                'datapower',
                                "{}.{}.{}{}".format("documentcache", name, key, suffix), item[key], 
                                pod_name=self.name, labels=self.labels)
                except KeyError:
                    logger.warning('Failed to parse response for document cache summary')
                    logger.info(item)
        except requests.exceptions.RequestException as e:
            logger.info("{}: {} (Check rest-mgmt is enabled and you have network connectivity)".format(provider, e.strerror))



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
        """ Get peering status detail """
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
                labels = self.labels
                labels["peer_group"] = entry["Name"]
                pvalue = 0
                lvalue = 0
                if entry["Primary"] == "yes":
                    pvalue = 1
                if entry["LinkStatus"] == "ok":
                    lvalue = 1
                self.trawler.set_gauge('datapower', "gateway_peering_primary_info", pvalue, 
                                       pod_name=self.name, labels=labels)
                self.trawler.set_gauge('datapower', "gateway_peering_primary_link", lvalue, 
                                       pod_name=self.name, labels=labels)
                self.trawler.set_gauge('datapower', "gateway_peering_primary_offset", entry["ReplicationOffset"], 
                                       pod_name=self.name, labels=labels)

    def invoke_api(self, api):
        """ invoke api_tests endpoints """
        http_call = getattr(requests, api['method']) 
        try:
            invoke_labels = self.labels
            result = http_call(
                "https://{}:{}{}".format(self.ip, self.apiPort, api['path']), 
                headers=api.get('headers', None),
                timeout=5,
                verify=False,
                allow_redirects=False
            )
            elapsed_time = result.elapsed.microseconds
            size = len(result.text)
            status = result.status_code

            self.trawler.set_gauge(
                'datapower',
                "invoke_api_{}_size".format(api['name']),
                size,
                pod_name=self.name, labels=invoke_labels)
            self.trawler.set_gauge(
                'datapower',
                "invoke_api_{}_time".format(api['name']),
                elapsed_time,
                pod_name=self.name, labels=invoke_labels)

            status_labels = {'code':status}
            self.trawler.inc_counter(
                'datapower',
                "invoke_api_{}_status_total".format(api['name']),
                1,
                pod_name=self.name, labels={**status_labels, **self.labels})
        except requests.RequestException:
            status_labels = {'code': '000'}
            self.trawler.inc_counter(
                'datapower',
                "invoke_api_{}_status_total".format(api['name']),
                0,
                pod_name=self.name, labels={**status_labels, **self.labels})

if __name__ == "__main__":
    net = DataPowerNet()
    net.find()
