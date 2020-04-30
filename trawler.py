#!/usr/bin/python3

import os
import time
import logging
import yaml
import click
from prometheus_client import start_http_server, Gauge, Summary


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

    def read_secret(self, key):
        try:
            value = open("{}/{}".format(self.secrets_path, key, 'r').read())
            return value
        except FileNotFoundError as e:
            logger.exception(e)
            return None

    def __init__(self, config_file='/app/config/config.yaml'):
        self.logger = logging.getLogger(__name__)
        self.secrets_path = os.getenv('SECRETS', '/app/secrets')
        try:
            with open(config_file, 'r') as config_yaml:
                config = yaml.safe_load(config_yaml)
        except FileNotFoundError as e:
            logger.exception(e)
            exit(2)
        if config['prometheus']['enabled']:
            port = config['prometheus'].get('port')
            logger.info('Starting prometheus http port at {}'.format(port))
            start_http_server(config['prometheus'].get('port'))
            self.guage = Gauge('what_stuff', 'The metric')

    def trawl_metrics(self):
        while True:
            self.do_stuff()
            time.sleep(8)

    @REQUEST_TIME.time()
    def do_stuff(self):
        time.sleep(2)
        self.guage.set(time.time())
        logger.info('Doing stuff')


@click.command()
@click.version_option()
@click.option('-c', '--config', required=False, envvar='CONFIG',
              help="Specifies an alternative config file",
              default="/app/config/config.yaml",
              type=click.Path())
def cli(config='/app/config/config.yaml'):
    trawler = Trawler(config)
    trawler.trawl_metrics()


if __name__ == '__main__':
    cli()
