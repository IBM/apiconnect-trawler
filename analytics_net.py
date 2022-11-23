import alog
import tempfile
from kubernetes import client, config
import urllib3
import base64
import requests

urllib3.disable_warnings()
logger = alog.use_channel("analytics")


class AnalyticsNet(object):
    """ Analytics Subsystem data """
    namespace = ''
    token = None
    token_expires = 0
    max_frequency = 600
    data = {}
    data_time = 0
    use_kubeconfig = False
    hostname = None
    trawler = None
    version = "10.0"
    certificates = None
    status_map = {"green": 2, "yellow": 1, "red": 0}

    def __init__(self, config, trawler):
        # Takes in config object and trawler instance it's behind
        # In k8s or outside
        self.use_kubeconfig = trawler.use_kubeconfig
        # Namespace to find managemnet pods
        self.namespace = config.get('namespace', 'default')
        # Maximum frequency to pull data from APIC
        self.max_frequency = int(config.get('frequency', 600))
        self.trawler = trawler
        if self.use_kubeconfig:
            logger.error("Analytics metrics currently only available in cluster setting localhost:9200 for testing")
            self.hostname = 'localhost:9200'
            self.find_hostname_and_certs()
        else:
            self.find_hostname_and_certs()
        logger.trace("Hostname is %s", self.hostname)
        logger.trace("Certificate file is %s", self.certificates.name)

    def load_certs_from_secret(self, v1, secret_name):
        # Get certificates to communicate with analytics
        secret = v1.read_namespaced_secret(secret_name, namespace=self.namespace )
        cert = None
        cert = base64.b64decode(secret.data['tls.crt'])
        key = base64.b64decode(secret.data['tls.key'])
        if cert:
            combined = key + "\n".encode() + cert
            self.certificates = tempfile.NamedTemporaryFile('w', delete=False)
            with self.certificates as certfile:
                certfile.write(combined.decode())

    def find_hostname_and_certs(self):
        """ Lookup hostname and certs for communicating with analytics subsystem"""
        try:
            # Initialise the k8s API
            if self.use_kubeconfig:
                config.load_kube_config()
                logger.info("Not in cluster, so will assume port-forward")
                v1 = client.CoreV1Api()
            else:
                config.load_incluster_config()
                logger.info("In cluster, so looking for analytics services")
                v1 = client.CoreV1Api()
            # Identify analytics version
            customObjectsApi = client.CustomObjectsApi()
            analytics_clusters = customObjectsApi.list_cluster_custom_object(
                "analytics.apiconnect.ibm.com",
                'v1beta1',
                'analyticsclusters')
            self.version = analytics_clusters['items'][0]['status']['versions']['reconciled']
            if self.version > '10.0.5':
                director_svc = analytics_clusters['items'][0]['status']['services']['director']
                self.hostname = '{}.{}.svc:3009'.format(director_svc, self.namespace)
                if self.use_kubeconfig:
                    self.hostname = 'localhost:3009'
                self.load_certs_from_secret(v1, analytics_clusters['items'][0]['status']['serviceClientSecret'])
            else:
                # Identify analytics-storage service
                servicelist = v1.list_namespaced_service(namespace=self.namespace)
                logger.info("found {} services in namespace {}".format(len(servicelist.items), self.namespace))
                for service in servicelist.items:
                    if 'analytics-storage' in service.metadata.name:
                        for port_object in service.spec.ports:
                            if port_object.name == 'http-es' or port_object.name == 'http':
                                port = 9200  # default
                                if port_object.port:
                                    port = port_object.port
                                self.hostname = "{}.{}.svc.cluster.local.:{}".format(
                                    service.metadata.name, self.namespace, port)
                if self.hostname:
                    logger.info("Identified service host: {}".format(self.hostname))

                # Get certificates to communicate with analytics
                secrets_response = v1.list_namespaced_secret(namespace=self.namespace)
                cert = None
                for item in secrets_response.items:
                    if item.metadata.name.startswith('analytics-storage-velox-certs'):
                        cert = base64.b64decode(item.data['analytics-storage_client_public.cert.pem'])
                        key = base64.b64decode(item.data['analytics-storage_client_private.key.pem'])
                        break
                    elif item.metadata.name == 'analytics-client':
                        cert = base64.b64decode(item.data['tls.crt'])
                        key = base64.b64decode(item.data['tls.key'])
                        break
                if cert:
                    combined = key + "\n".encode() + cert
                    self.certificates = tempfile.NamedTemporaryFile('w', delete=False)
                    with self.certificates as certfile:
                        certfile.write(combined.decode())

        except client.rest.ApiException as e:
            logger.error('Error calling kubernetes API')
            logger.exception(e)

    def buildQuery(self):
        """ Build search query """
        return """{
            "size": 0,
            "query": {
              "range": {"datetime": {
                  "gte": "now-1h",
                  "lt": "now"
              }}
            },
            "aggs": {"status_codes": {"filters": {"filters": {
                    "1xx": {"regexp": {"status_code": "1.*"}},
                    "2xx": {"regexp": {"status_code": "2.*"}},
                    "3xx": {"regexp": {"status_code": "3.*"}},
                    "4xx": {"regexp": {"status_code": "4.*"}},
                    "5xx": {"regexp": {"status_code": "5.*"}}
            }}}}
            }"""

    def fish_analytics_v1(self):
        errored = False
        try:
            r = requests.get('https://{}/_cluster/health'.format(self.hostname),
                            verify=False,
                            cert=self.certificates.name)

            health_obj = r.json()
            logger.debug(r.text)
        except requests.exceptions.ConnectionError:
            logger.error("Error getting cluster health from 'https://{}/_cluster/health'".format(
                        self.hostname))
            errored = True
            health_obj = {}

        try:
            cluster_status = self.status_map[health_obj['status']]
        except KeyError:
            cluster_status = -1

        self.trawler.set_gauge('analytics', 'cluster_status', cluster_status)
        if not errored:
            self.trawler.set_gauge('analytics', 'data_nodes_total', health_obj['number_of_data_nodes'])
            self.trawler.set_gauge('analytics', 'nodes_total', health_obj['number_of_nodes'])
            self.trawler.set_gauge('analytics', 'active_primary_shards_total', health_obj['active_primary_shards'])
            self.trawler.set_gauge('analytics', 'active_shards_total', health_obj['active_shards'])
            self.trawler.set_gauge('analytics', 'relocating_shards_total', health_obj['relocating_shards'])
            self.trawler.set_gauge('analytics', 'initializing_shards_total', health_obj['initializing_shards'])
            self.trawler.set_gauge('analytics', 'unassigned_shards_total', health_obj['unassigned_shards'])
            self.trawler.set_gauge('analytics', 'initializing_shards_total', health_obj['initializing_shards'])
            self.trawler.set_gauge('analytics', 'pending_tasks_total', health_obj['number_of_pending_tasks'])
            calls_req = requests.get('https://{}/apic-api-r/_search'.format(self.hostname), verify=False,
                                    cert=self.certificates.name, data=self.buildQuery())

            summary = calls_req.json()
            self.trawler.set_gauge('analytics', 'apicalls_lasthour.total', summary['hits']['total'])
            for status in summary['aggregations']['status_codes']['buckets']:
                doc_count = summary['aggregations']['status_codes']['buckets'][status]['doc_count']
                self.trawler.set_gauge('analytics', 'apicalls_lasthour.{}'.format(status), doc_count)
        else:
            logger.info("Cluster health failed, so no data and no point querying for calls")

    def fish_analytics_v2(self):
        errored=False
        # Cluster Health
        try:
            health = requests.get(
                "https://{}/cloud/clustermgmt/storage/cluster/health".format(self.hostname),
                verify=False,
                cert=self.certificates.name
            )        
            health_obj = health.json()
            logger.debug(health.text)
        except requests.exceptions.ConnectionError:
            logger.error("Error getting cluster health")
            errored = True
            health_obj = {}

        try:
            cluster_status = self.status_map[health_obj['status']]
        except KeyError:
            cluster_status = -1

        self.trawler.set_gauge('analytics', 'cluster_status', cluster_status)
        if not errored:
            self.trawler.set_gauge('analytics', 'data_nodes_total', health_obj['number_of_data_nodes'])
            self.trawler.set_gauge('analytics', 'nodes_total', health_obj['number_of_nodes'])
            self.trawler.set_gauge('analytics', 'active_primary_shards_total', health_obj['active_primary_shards'])
            self.trawler.set_gauge('analytics', 'active_shards_total', health_obj['active_shards'])
            self.trawler.set_gauge('analytics', 'relocating_shards_total', health_obj['relocating_shards'])
            self.trawler.set_gauge('analytics', 'initializing_shards_total', health_obj['initializing_shards'])
            self.trawler.set_gauge('analytics', 'unassigned_shards_total', health_obj['unassigned_shards'])
            self.trawler.set_gauge('analytics', 'initializing_shards_total', health_obj['initializing_shards'])
            self.trawler.set_gauge('analytics', 'pending_tasks_total', health_obj['number_of_pending_tasks'])
            calls_req = requests.get('https://{}/cloud/dashboards/status?timeframe=last1hour'.format(self.hostname), verify=False,
                                     cert=self.certificates.name)

            summary = calls_req.json()
            summary_output = {'1':0,'2':0,'3':0,'4':0,'5':0}
            total = 0
            for status in summary['status_codes']['data']:
                if status['group'][0] in summary_output:
                    summary_output[status['group'][0]] += status['value']
                total += status['value']

            self.trawler.set_gauge('analytics', 'apicalls_lasthour.total', total)
            for status in summary_output:
                self.trawler.set_gauge('analytics', 'apicalls_lasthour.{}xx'.format(status), summary_output[status])


    @alog.timed_function(logger.trace)
    def fish(self):
        """ main metrics gathering function """
        
        if self.version < "10.0.5":
            if self.hostname:
                self.fish_analytics_v1()
        else:
            self.fish_analytics_v2()

if __name__ == "__main__":
    net = AnalyticsNet({"namespace": "apic-management"}, None)
    net.fish()
