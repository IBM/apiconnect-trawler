import requests
import alog
from kubernetes import client, config
from prometheus_client import Gauge
import urllib3
import base64
import OpenSSL
import ssl, socket
import datetime
import time
import sys

urllib3.disable_warnings()

class CertsNet(object):
    namespace = None
    use_kubeconfig = True
    trawler = None
    logger = None

    def __init__(self, config, trawler=None, logger=None):
        # Takes in config object and trawler instance it's behind
        # Use kubeconfig or in-cluster config for k8s comms
        if trawler:
            self.trawler = trawler
            self.use_kubeconfig = self.trawler.use_kubeconfig
        if logger:
            self.logger = logger
        else:
            alog.configure(default_level="info")
            self.logger = alog.use_channel("certs_net")
        self.logger.info("Init CertsNet")
        # Namespace to review
        self.namespace = config.get('namespace', None)


    def getExpiry(self, cert_data):
        try:
            cert = base64.b64decode(cert_data)
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            expiry = datetime.datetime.strptime(x509.get_notAfter().decode('utf-8'), "%Y%m%d%H%M%S%z").timestamp()
            return int(expiry - time.time())
        except:
            self.logger.exception("getExpiry failed")
            return None

    @alog.timed_function(alog.use_channel("fish").trace)
    def fish(self):
        # Go fishing 
        if self.logger:
            self.logger.info("Starting to fish")
        try:
            # Load appropriate k8s config
            if self.use_kubeconfig:
                config.load_kube_config()
            else:
                config.load_incluster_config()
        except:
            self.logger.exception("fish: loading kubeconfig failed")

        try:
            # Initialise the k8s API
            v1 = client.CoreV1Api()
        except:
            self.logger.exception("fish: loading kubenetes CoreV1Api failed")
            return

        try:
            # Retreive secret list for specified namespace if specified, otherwise all namespaces
            if self.namespace:
                self.logger.info("CertsNet: Getting secrets for namespace {}".format(self.namespace))
                ret = v1.list_namespaced_secret(namespace=self.namespace)
            else:
                self.logger.info("CertsNet: Getting secrets for all namespaces")
                ret = v1.list_secret_for_all_namespaces()
        except:
            self.logger.exception("fish: retrieving kubenetes secrets failed")
            return

        tls_secrets_found = 0
        secrets_processed = 0
        for secret in ret.items:
            if secret.type == 'kubernetes.io/tls':
                tls_secrets_found += 1
                this_secret_counted = False
                if 'tls.crt' in secret.data and secret.data['tls.crt'] != '':
                    self.logger.trace("Processing tls.crt for secret {}".format(secret.metadata.name))
                    tlsSecondsLeft = self.getExpiry(secret.data['tls.crt'])
                    if tlsSecondsLeft == None:
                        continue
                    if self.trawler:
                        self.trawler.set_gauge(
                            'cert', 'remaining_seconds',
                            tlsSecondsLeft,
                            labels={'secret':secret.metadata.name, 'cert':'tls.crt', 'namespace': secret.metadata.namespace})
                    this_secret_counted = True
                    secrets_processed += 1
                if 'ca.crt' in secret.data and secret.data['ca.crt'] != '':
                    self.logger.trace("Processing ca.crt for secret {}".format(secret.metadata.name))
                    caSecondsLeft = self.getExpiry(secret.data['ca.crt'])
                    if caSecondsLeft == None:
                        continue
                    if self.trawler:
                        self.trawler.set_gauge(
                            'cert', 'remaining_seconds',
                            caSecondsLeft,
                            labels={'secret':secret.metadata.name, 'cert':'ca.crt', 'namespace': secret.metadata.namespace})
                    if not this_secret_counted:
                        secrets_processed += 1
                else:
                    self.logger.trace("No ca.crt for secret {}".format(secret.metadata.name))
        if self.logger:
            self.logger.info("Finished fish. Processed {}/{}".format(secrets_processed, tls_secrets_found))


if __name__ == "__main__":
    test_logger = None
    if len(sys.argv) > 1:
        alog.configure(default_level="trace")
        test_logger = alog.use_channel("mocktrawler")
    net = CertsNet(config={'namespace':'apic'}, trawler=None, logger=test_logger)
    net.fish()
