import requests
import logging
from kubernetes import client, config
from prometheus_client import Gauge
import urllib3
import base64
import OpenSSL
import ssl, socket
import datetime
import time

urllib3.disable_warnings()
logger = logging.getLogger(__name__)



class CertsNet(object):
    namespace = None
    use_kubeconfig = True
    trawler = None

    def __init__(self, config, trawler):
        # Takes in config object and trawler instance it's behind
        # Use kubeconfig or in-cluster config for k8s comms
        if trawler:
            self.trawler = trawler
            self.use_kubeconfig = trawler.use_kubeconfig
        # Namespace to review
        self.namespace = config.get('namespace', None)

    def getExpiry(self, cert_data):
      cert = base64.b64decode(cert_data)
      x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
      expiry = datetime.datetime.strptime(x509.get_notAfter().decode('utf-8'), "%Y%m%d%H%M%S%z").timestamp()
      return int(expiry - time.time())

    def fish(self):
        # Go fishing 
        # Load appropriate k8s config
        if self.use_kubeconfig:
            config.load_kube_config()
        else:
            config.load_incluster_config()
        # Initialise the k8s API
        v1 = client.CoreV1Api()
        # Retreive secret list for specified namespace if specified, otherwise all namespaces
        if self.namespace:
            ret = v1.list_namespaced_secret(namespace=self.namespace)
        else:
            ret = v1.list_secret_for_all_namespaces()

        for secret in ret.items:
            if secret.type == 'kubernetes.io/tls' and 'ca.crt' in secret.data and secret.data['ca.crt'] != '':
                caSecondsLeft = self.getExpiry(secret.data['ca.crt'])
                tlsSecondsLeft = self.getExpiry(secret.data['tls.crt']) 
                self.trawler.set_gauge(
                    'cert', 'remaining_seconds', 
                    tlsSecondsLeft, 
                    labels={'secret':secret.metadata.name, 'cert':'tls.crt'})
                self.trawler.set_gauge(
                    'cert', 'remaining_seconds', 
                    caSecondsLeft, 
                    labels={'secret':secret.metadata.name, 'cert':'ca.crt'})

      
if __name__ == "__main__":
    net = CertsNet(config={'namespace':'apic'}, trawler=None)
    net.fish()
