#!/usr/bin/python3

import os
import time
import logging
import yaml
import requests
from prometheus_client import start_http_server, Histogram, Gauge, Summary


logger = logging.getLogger('trawler')

logging.basicConfig(level=logging.getLevelName(logging.INFO),
                    format="%(levelname)s: %(asctime)s " +
                           "(%(module)s:%(lineno)d): %(message)s")

REQUEST_TIME = Summary('do_stuff', 'Time spent processing request')
THE_GAUGE = Gauge('what_stuff', 'The metric')




class Trawler(object):
    """ The main trawling  """
    config = {
      'prometheus': {'enabled': False },
      'graphite':   {'enabled': False }
    }
    secrets = {}

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        config_file = os.getenv('CONFIG', '/app/config/config.yaml')
        try:
            with open(config_file, 'r') as config_yaml:
                config = yaml.safe_load(config_yaml)
        except FileNotFoundError as e:
            logger.exception(e)
            exit(2)
        if config['prometheus']['enabled']:
            logger.info('Starting prometheus http port')
            start_http_server(config['prometheus'].get('port'))

    def trawl_metrics(self):
        while True:
            self.do_stuff()
            time.sleep(8)

    @REQUEST_TIME.time()
    def do_stuff(self):
        time.sleep(2)
        THE_GAUGE.set(time.time())
        logger.info('Doing stuff')


if __name__ == '__main__':  
    trawler = Trawler()
    trawler.trawl_metrics()
