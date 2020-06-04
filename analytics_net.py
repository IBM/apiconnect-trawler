import yaml
import logging
from kubernetes import client, config
from kubernetes.stream import stream
from prometheus_client import Gauge
import urllib3

urllib3.disable_warnings()
logger = logging.getLogger(__name__)

# /mgmt/status/apiconnect/TCPSummary


class AnalyticsNet(object):
    namespace = ''
    token = None
    token_expires = 0
    max_frequency = 600
    data = {}
    data_time = 0
    in_cluster = True
    gauges = {}

    def __init__(self, config, trawler):
        # Takes in config object and trawler instance it's behind
        # In k8s or outside
        self.in_cluster = config.get('in_cluster', True)
        # Namespace to find managemnet pods
        self.namespace = config.get('namespace', 'default')
        # Maximum frequency to pull data from APIC
        self.max_frequency = int(config.get('frequency', 600))

    def fish(self):
        if self.in_cluster:
            config.load_incluster_config()
        else:
            config.load_kube_config()
        # Initialise the k8s API
        v1 = client.CoreV1Api()
        # Identify analytics pods
        podlist = v1.list_namespaced_pod(self.namespace)
        podname = None

        for pod in podlist.items:
            if 'analytics-storage-data' in pod.metadata.name:
                podname = pod.metadata.name
                break
        if podname:
            health_command = ['curl_es', '-s', '_cluster/health']
            # Calling exec and waiting for response
            health = stream(v1.connect_get_namespaced_pod_exec,
                            podname,
                            namespace=self.namespace,
                            command=health_command,
                            stderr=True, stdin=False,
                            stdout=True, tty=False)
            health_obj = yaml.safe_load(health)

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
                logger.info("Creating gauges")
                self.gauges[target_name] = Gauge(
                    target_name,
                    target_name)
            logger.warning("Setting gauge {} to {}".format(target_name, value))
            self.gauges[target_name].set(value)
        else:
            logger.warning("{} is not float or int".format(value))


if __name__ == "__main__":
    net = AnalyticsNet({"in_cluster": False, "namespace": "apic-analytics"}, None)
    net.fish()
