#!/usr/bin/python3

import os
import time
import logging
import logging.config
import yaml
import click
from datapower_net import DataPowerNet
from productstats_net import ProductStatsNet
from analytics_net import AnalyticsNet
from prometheus_client import start_http_server, Summary


logger = logging.getLogger('trawler')

logging.basicConfig(
    level=logging.getLevelName(logging.INFO),
    format="%(levelname)s: %(asctime)s (%(module)s:%(lineno)d): %(message)s"
)

REQUEST_TIME = Summary('do_stuff', 'Time spent processing request')


class Trawler(object):
    """ The main trawling  """
    config = {
        'prometheus': {'enabled': False},
        'graphite': {'enabled': False}
    }
    secrets_path = '/app/secrets'

    def __init__(self, config_file=None):
        self.secrets_path = os.getenv('SECRETS', '/app/secrets')
        if config_file:
            self.load_config(config_file)
        if 'logging' in self.config:
          logging.config.dictConfig(self.config['logging'])
        self.logger = logging.getLogger(__name__)
        if self.config['prometheus']['enabled']:
            port = self.config['prometheus'].get('port')
            logger.info('Starting prometheus http port at {}'.format(port))
            start_http_server(self.config['prometheus'].get('port'))

    def read_secret(self, key):
        # Helper function read secrets from mounted k8s secrets
        try:
            with open("{}/{}".format(self.secrets_path, key, 'r')) as secret:
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
        if 'product' in self.config['nets'] and self.config['nets']['product'].get('enabled', True):
            nets.append(ProductStatsNet(self.config['nets']['product'], self))
        if 'analytics' in self.config['nets'] and self.config['nets']['analytics'].get('enabled', True):
            nets.append(AnalyticsNet(self.config['nets']['analytics'], self))

        while True:
            logger.info("Trawling for metrics...")
            for net in nets:
                net.fish()
            time.sleep(8)


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
