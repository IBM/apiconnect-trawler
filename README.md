# trawler

![Trawler Logo ](docs/trawler.png)


Trawler for API Connect metrics gathering - owned by Quarks

## Deployment

Trawler is designed to run within the same kubernetes cluster as API Connect, such that it can scrape metrics from the installed components and make them available. The metrics gathering in Trawler is separated into separate nets for the different types of metrics to expose so you can select which ones to enable for a particular environment.

To do this it requires a service account with read access to list pods and services in the namespace(s) the API Connect components are deployed in.


### Configuring trawler

Trawler gets it's config from a mounted configmap containing config.yaml which looks like this:

```yaml
prometheus:
  port: 63512 
  enabled: true
nets:
  datapower:
    enabled: true
    username: trawler-monitor
    namespace: apic-gateway
  product:
    enabled: true
    username: trawler-monitor
    namespace: apic-management
```

The port specfied in the prometheus block needs to match the prometheus annotations on the deployed trawler pod for prometheus to discover the metrics exposed.  Each of the different areas of metrics trawler is handled by a separate net, which can be enabled/disabled independently.  The configuration for these is currently a pointer to the namespace the relevant subsystem is deployed into and a username to use.  Passwords are loaded separately from the following values in a kubernetes secret mounted at /app/secrets :

 - datapower_password - password to use with the datapower net for accessing the [DataPower REST management]() interface. 
 - cloudmanager_password - password to use with the product net to retreive API Connect product usage metrics.




## Development tips

To run locally point the config parameter to a local config file

    python3 trawler.py --config local/config.yaml


Notes on developing with a running k8s pod:

    kubectl cp datapower_trawl.py {trawler_pod}:/app/datapower_trawl.py
    kubectl cp newconfig.yaml {trawler_pod}:/app/newconfig.yaml
    kubectl exec {trawler_pod} -- sh -c 'cd /app;python3 trawler.py -c newconfig.yaml'
