import logging
import tempfile
from kubernetes import client, config
from prometheus_client import Gauge
import urllib3
import base64
import requests

urllib3.disable_warnings()
logger = logging.getLogger(__name__)


class AnalyticsNet(object):
    namespace = ''
    token = None
    token_expires = 0
    max_frequency = 600
    data = {}
    data_time = 0
    use_kubeconfig = False
    gauges = {}
    hostname = None
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
        if self.use_kubeconfig:
            logger.error("Analytics metrics currently only available in cluster")
        else:
            self.find_hostname_and_certs()

    def find_hostname_and_certs(self):
        logger.info("In cluster, so looking for analytics-storage service")
        config.load_incluster_config()
        # Initialise the k8s API
        v1 = client.CoreV1Api()
        # Identify analytics-storage service
        servicelist = v1.list_namespaced_service(namespace=self.namespace)
        logger.info("found {} services in namespace {}".format(len(servicelist.items), self.namespace))
        for service in servicelist.items:
            if 'analytics-storage' in service.metadata.name:
                for port_object in service.spec.ports:
                    if port_object.name == 'http-es':
                        port = port_object.port
                self.hostname = "{}.{}.svc:{}".format(service.metadata.name, self.namespace, port)
                logger.info("Identified service host: {}".format(self.hostname))

        # Get certificates to communicate with analytics
        secrets_response = v1.list_namespaced_secret(namespace=self.namespace)
        secret = None
        for item in secrets_response.items:
            if item.metadata.name.startswith('analytics-storage-velox-certs'):
                secret = item
        if secret:
            cert = base64.b64decode(secret.data['analytics-storage_client_public.cert.pem'])
            key = base64.b64decode(secret.data['analytics-storage_client_private.key.pem'])
            combined = key + "\n".encode() + cert
            self.certificates = tempfile.NamedTemporaryFile('w', delete=False)
            with self.certificates as certfile:
                certfile.write(combined.decode())

    def fish(self):
        if self.hostname:
            r = requests.get('https://{}/_cluster/health'.format(self.hostname), verify=False,
                             cert=self.certificates.name)

            health_obj = r.json()
            logger.debug(r.text)
            try:
              cluster_status = self.status_map[health_obj['status']]
            except KeyError:
              cluster_status = -1

            self.set_gauge('analytics_cluster_status', cluster_status)
            self.set_gauge('analytics_data_nodes_total', health_obj['number_of_data_nodes'])
            self.set_gauge('analytics_active_primary_shards_total', health_obj['active_primary_shards'])
            self.set_gauge('analytics_active_shards_total', health_obj['active_shards'])
            self.set_gauge('analytics_relocating_shards_total', health_obj['relocating_shards'])
            self.set_gauge('analytics_initializing_shards_total', health_obj['initializing_shards'])
            self.set_gauge('analytics_unassigned_shards_total', health_obj['unassigned_shards'])
            self.set_gauge('analytics_initializing_shards_total', health_obj['initializing_shards'])
            self.set_gauge('analytics_pending_tasks_total', health_obj['number_of_pending_tasks'])

    def set_gauge(self, target_name, value):
        if type(value) is float or type(value) is int:
            target_name = target_name.replace('-', '_')
            if target_name not in self.gauges:
                logger.info("Creating gauge {}".format(target_name))
                self.gauges[target_name] = Gauge(
                    target_name,
                    target_name)
            logger.debug("Setting gauge {} to {}".format(target_name, value))
            self.gauges[target_name].set(value)
        else:
            logger.warning("{} is not float or int".format(value))


if __name__ == "__main__":
    net = AnalyticsNet({"namespace": "apic-management"}, None)
    net.fish()
