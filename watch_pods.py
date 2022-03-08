import time
import threading
import alog
import os
from kubernetes import client, config, watch

logger = alog.use_channel("watch")
alog.configure(default_level='info', formatter='pretty')

class Watcher(object):

  pods = {}
  config = []
  enabled = False
  use_kubeconfig = False

  def __init__(self):
    logger.info("Initialising watcher")

  def getPods(self, groupName):
    listpods = [] 
    for ip in self.pods[groupName]:
      listpods.append(self.pods[groupName][ip])
    return listpods
  
  def register(self, groupName, annotation, value):
    self.config.append({
        'groupName': groupName,
        'annotation': annotation,
        'value': value})
    self.pods[groupName] = {}
    logger.info('Regisered to watch pods with annotation {}={}'.format(annotation, value))
    self.enabled = True

  def start(self):
    if self.enabled:
      logger.info("Starting watcher thread")
      watchThread = threading.Thread(target=self.watch_pods, args=(), daemon=True)
      watchThread.start()
    else:
      logger.info("Nothing to watch")



  def podReady(self, pod):
    if pod.status.conditions:
      for condition in pod.status.conditions:
        if condition.type == "Ready":
          return condition.status
    else:
      return False

  def watch_pods(self):
    logger.info("Starting watch")
    w = watch.Watch()
    if os.getenv('KUBERNETES_SERVICE_HOST'):
        config.load_incluster_config()    
    else:
        config.load_kube_config()
    v1 = client.CoreV1Api()
    while True:
      try:
        for event in w.stream(v1.list_pod_for_all_namespaces, _request_timeout=0):
          pod = event['object']
          for search in self.config:
            if (pod.metadata.annotations and search['annotation'] in pod.metadata.annotations and 
                search['value'] in pod.metadata.annotations[search['annotation']]):
                logger.info("{}: {}/{} - {} {}".format(event['type'], pod.metadata.namespace, pod.metadata.name, pod.status.pod_ip, self.podReady(pod)))

                if event['type'] == "DELETED":
                  self.pods[search['groupName']].pop(pod.status.pod_ip)
                elif pod.status.pod_ip:
                  self.pods[search['groupName']][pod.status.pod_ip] = pod
      except  client.rest.ApiException:
        logger.error("Error calling kubernetes API")

"""
Example usage:
if __name__ == "__main__":
  t = Watcher(True)
  t.register('datapower', 'productName', 'DataPower Gateway')
  t.start()
  time.sleep(30)
  print(len(t.pods['datapower']))
"""
