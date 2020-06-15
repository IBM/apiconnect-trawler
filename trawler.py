#!/usr/bin/python3

import os
import time
import logging
import logging.config
import yaml
import click
from datapower_net import DataPowerNet
from manager_net import ManagerNet
from analytics_net import AnalyticsNet
from prometheus_client import start_http_server


logger = logging.getLogger('trawler')

logging.basicConfig(
    level=logging.getLevelName(logging.INFO),
    format="%(levelname)s: %(asctime)s (%(module)s:%(lineno)d): %(message)s"
)


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

    def __init__(self, config_file=None):
        self.secrets_path = os.getenv('SECRETS', self.secrets_path)
        if config_file:
            self.load_config(config_file)
        if 'logging' in self.config:
          logging.config.dictConfig(self.config['logging'])
        self.logger = logging.getLogger(__name__)
        if self.config['prometheus']['enabled']:
            port = self.config['prometheus'].get('port')
            logger.info('Starting prometheus http port at http://0.0.0.0:{}'.format(port))
            start_http_server(port)
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
        # Helper function read secrets from mounted k8s secrets
        try:
            with open("{}/{}".format(self.secrets_path, key), 'r') as secret:
                value = secret.read().rstrip()
            return value
        except FileNotFoundError as e:
            logger.exception(e)
            return None

    def load_config(self, config_file):
        try:
            with open(config_file, 'r') as config_yaml:
                self.config = yaml.safe_load(config_yaml)
        except FileNotFoundError as e:
            logger.exception(e)
            exit(2)

    def trawl_metrics(self):
        # Initialise
        logger.info("Laying nets...")
        nets = []
        if 'datapower' in self.config['nets'] and self.config['nets']['datapower'].get('enabled', True):
            nets.append(DataPowerNet(self.config['nets']['datapower'], self))
        if 'manager' in self.config['nets'] and self.config['nets']['manager'].get('enabled', True):
            nets.append(ManagerNet(self.config['nets']['manager'], self))
        if 'analytics' in self.config['nets'] and self.config['nets']['analytics'].get('enabled', True):
            nets.append(AnalyticsNet(self.config['nets']['analytics'], self))

        while True:
            logger.info("Trawling for metrics...")
            for net in nets:
                net.fish()
            time.sleep(self.frequency)


@click.command()
@click.version_option()
@click.option('-c', '--config', required=False, envvar='CONFIG',
              help="Specifies an alternative config file",
              default=None,
              type=click.Path())
def cli(config=None):
    trawler = Trawler(config)
    trawler.trawl_metrics()


if __name__ == '__main__':
    cli()
