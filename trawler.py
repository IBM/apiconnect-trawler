#!/usr/bin/python3
""" Main trawler application """

import os
import time
import threading
import ssl
import alog
import click
from prometheus_client import start_http_server, Gauge, Counter, make_wsgi_app
import yaml
from certs_net import CertsNet
from apiconnect_net import APIConnectNet
from datapower_net import DataPowerNet
from manager_net import ManagerNet
from analytics_net import AnalyticsNet
import metrics_graphite


logger = alog.use_channel("trawler")


class Trawler(object):
    """ The main trawling  """
    config = {
        'prometheus': {'enabled': False},
        'graphite': {'enabled': False}
    }
    # Default looping frequency
    frequency = 10
    # Default to True, but detected unless overridden in config
    use_kubeconfig = True
    # Default path for secrets in container build - override with envvar SECRETS
    secrets_path = '/app/secrets'
    graphite = None
    gauges = {}

    def __init__(self, config_file=None):
        self.secrets_path = os.getenv('SECRETS', self.secrets_path)
        if config_file:
            self.load_config(config_file)
        if 'logging' in self.config:
            alog.configure(
                default_level=self.config['logging'].get('level', 'debug'),
                filters=self.config['logging'].get('filters', None),
                formatter=self.config['logging'].get('format', 'json')
            )
        else:
            alog.configure(default_level='info', formatter='json')
        self.logger = alog.use_channel("trawler")
        if self.config['prometheus']['enabled']:
            port = self.config['prometheus'].get('port')
            logger.info('Starting prometheus http port at http://0.0.0.0:{}'.format(port))
            start_http_server(port)
        if 'graphite' in self.config:
            if self.config['graphite']['enabled']:
                self.graphite = metrics_graphite.instance(self.config['graphite'])

        use_kubeconfig = False
        if 'trawler' in self.config:
            use_kubeconfig = self.config['trawler'].get('use_kubeconfig')
            self.frequency = self.config['trawler'].get('frequency', self.frequency)

        if use_kubeconfig:
            # Explicit override that we want to use kubeconfig rather than in cluster k8s comms
            self.use_kubeconfig = True
        else:
            # Check for KUBERNETES_SERVICE_HOST to determine if running within kubernetes
            if os.getenv('KUBERNETES_SERVICE_HOST'):
                self.use_kubeconfig = False

    def read_secret(self, key):
        """ Helper function read secrets from mounted k8s secrets """
        try:
            with open("{}/{}".format(self.secrets_path, key), 'r', encoding='utf-8') as secret:
                value = secret.read().rstrip()
            return value
        except FileNotFoundError as not_found_exception:
            logger.exception(not_found_exception)
            return None

    def load_config(self, config_file):
        """ Load trawler config """
        try:
            with open(config_file, 'r', encoding='utf-8') as config_yaml:
                self.config = yaml.safe_load(config_yaml)
        except FileNotFoundError as not_found_exception:
            logger.exception(not_found_exception)
            exit(2)

    def set_gauge(self, component, target_name, value, pod_name=None, labels=None):
        """ Set or create prometheus gauge """
        if not labels:
            labels = {}
        if pod_name:
            labels['pod'] = pod_name
        if 'labels' in self.config['prometheus']:
            labels = {**self.config['prometheus']['labels'], **labels}
        logger.debug("Entering set_gauge - params: (%s, %s, %s, %s)",
                     component, target_name, value, pod_name)
        logger.debug(labels)
        if isinstance(value, (float, int)):
            target_name = target_name.replace('-', '_')
            if self.config['prometheus']['enabled']:
                prometheus_target = "{}_{}".format(component, target_name.replace('.', '_'))
                if prometheus_target not in self.gauges:
                    logger.info("Creating gauge %s", prometheus_target)
                    if labels:
                        self.gauges[prometheus_target] = Gauge(
                            prometheus_target,
                            prometheus_target, labels.keys())
                    else:
                        self.gauges[prometheus_target] = Gauge(
                            prometheus_target,
                            prometheus_target)

                logger.debug("Setting gauge %s to %f",
                             self.gauges[prometheus_target]._name, value)
                try:
                    if labels:
                        self.gauges[prometheus_target].labels(**labels).set(value)
                    else:
                        self.gauges[prometheus_target].set(value)
                except ValueError as value_exception:
                    self.logger.exception(value_exception)
            if self.config['graphite']['enabled']:
                if pod_name:
                    metric_name = "{}.{}.{}".format(component, pod_name, target_name)
                else:
                    metric_name = "{}.{}".format(component, target_name)
                self.graphite.stage(metric_name, value)

    def inc_counter(self, component, target_name, value, pod_name=None, labels=None):
        """ Set or increase prometheus counter """
        if not labels:
            labels = {}
        if pod_name:
            labels['pod'] = pod_name
        if 'labels' in self.config['prometheus']:
            labels = {**self.config['prometheus']['labels'], **labels}
        logger.debug("Entering inc_counter - params: (%s, %s, %s, %s)",
                     component, target_name, value, pod_name)
        logger.debug(labels)
        if isinstance(value, (float, int)):
            target_name = target_name.replace('-', '_')
            if self.config['prometheus']['enabled']:
                prometheus_target = "{}_{}".format(component, target_name.replace('.', '_'))
                if prometheus_target not in self.gauges:
                    logger.info("Creating counter %s", prometheus_target)
                    if labels:
                        self.gauges[prometheus_target] = Counter(
                            prometheus_target,
                            prometheus_target, labels.keys())
                    else:
                        self.gauges[prometheus_target] = Counter(
                            prometheus_target,
                            prometheus_target)

                logger.debug("Setting gauge %s to %f",
                             self.gauges[prometheus_target]._name, value)
                if labels:
                    self.gauges[prometheus_target].labels(**labels).inc()
                else:
                    self.gauges[prometheus_target].inc()
            if self.config['graphite']['enabled']:
                if pod_name:
                    metric_name = "{}.{}.{}".format(component, pod_name, target_name)
                else:
                    metric_name = "{}.{}".format(component, target_name)
                self.graphite.stage(metric_name, value)

    def is_enabled(self, net_name):
        """ is net in config and enabled """
        if net_name in self.config['nets']:
            if self.config['nets'][net_name].get('enabled', True):
                return True
        return False

    @alog.timed_function(logger.trace)
    def trawl_metrics(self):
        """ Main loop to trawl for metrics """
        # Initialise
        logger.info("Laying nets...")
        nets = []
        if self.is_enabled('certs'):
            nets.append(CertsNet(self.config['nets']['certs'], self))
        if self.is_enabled('apiconnect'):
            nets.append(APIConnectNet(self.config['nets']['apiconnect'], self))
        if self.is_enabled('datapower'):
            nets.append(DataPowerNet(self.config['nets']['datapower'], self))
        if self.is_enabled('manager'):
            nets.append(ManagerNet(self.config['nets']['manager'], self))
        if self.is_enabled('analytics'):
            nets.append(AnalyticsNet(self.config['nets']['analytics'], self))

        while True:
            logger.info("Trawling for metrics...")
            for net in nets:
                net.fish()
            if self.graphite:
                self.graphite.store()
            time.sleep(self.frequency)


@click.command()
@click.version_option()
@click.option('-c', '--config', required=False, envvar='CONFIG',
              help="Specifies an alternative config file",
              default=None,
              type=click.Path())
def cli(config=None):
    """ run main trawler application """
    trawler = Trawler(config)
    trawler.trawl_metrics()


if __name__ == '__main__':
    cli()
