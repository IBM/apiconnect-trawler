import alog
from kubernetes import client, config
import urllib3

urllib3.disable_warnings()
logger = alog.use_channel("apiconnect")

# /mgmt/status/apiconnect/TCPSummary


class APIConnectNet(object):
    namespace = 'apic-management'
    use_kubeconfig = False
    trawler = None

    def __init__(self, config, trawler):
        # Takes in config object and trawler instance it's behind
        # Use kubeconfig or in-cluster config for k8s comms
        # self.use_kubeconfig = trawler.use_kubeconfig
        # Namespace to find CRs
        self.namespace = config.get('namespace', 'default')
        self.trawler = trawler
        self.use_kubeconfig = trawler.use_kubeconfig

    @alog.timed_function(logger.trace)
    def fish(self):
        try:
            if self.use_kubeconfig:
                logger.info("Using KUBECONFIG")
                config.load_kube_config()
            else:
                logger.info("In cluster, so looking for juhu service")
                config.load_incluster_config()
            customObjectsApi = client.CustomObjectsApi()
            customResources = [
                {"group": "management.apiconnect.ibm.com", "plural": "managementclusters"},
                {"group": "gateway.apiconnect.ibm.com", "plural": "gatewayclusters"},
                {"group": "portal.apiconnect.ibm.com", "plural": "portalclusters"},
            ]
            for customResource in customResources:
                logger.info("Gathering status for {plural}.{group}".format(**customResource))
                api_response = customObjectsApi.list_cluster_custom_object(
                    customResource['group'],
                    'v1beta1',
                    customResource['plural'])
                for item in api_response['items']:
                    for condition in item['status']['conditions']:
                        self.trawler.set_gauge(
                            'apiconnect',
                            "{}_status".format(customResource['plural']),
                            1,
                            labels={
                                "type": condition['type'],
                                "status": condition['status'],
                                "name": item['metadata']['name'],
                                "namespace": item['metadata']['namespace'],
                            })

            # api_response['status']['conditions']
            # {'lastTransitionTime': '2021-09-30T13:33:10Z', 'message': '', 'reason': 'na', 'status': 'False', 'type': 'Warning'}

        except client.rest.ApiException as e:
            logger.error("Error calling kubernetes API")
            logger.exception(e)


if __name__ == "__main__":
    import trawler
    boaty = trawler.Trawler()
    boaty.secret_path = 'test-assets'
    boaty.use_kubeconfig = True
    net = APIConnectNet({"namespace": "apic"}, boaty)
    net.use_kubeconfig = True
    net.fish()
