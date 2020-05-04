# trawler

![Trawler Logo ](docs/trawler.png)


Trawler for API Connect metrics gathering - owned by Quarks

## Deployment

Trawler is designed to run within the same kubernetes cluster as API Connect, such that it can scrape metrics from the installed components and make them available.

To do this it requires a service account with read access to list pods in the namespaces API Connect components are deployed in.





## Development tips

To run locally point the config parameter to a local config file

    python3 trawler.py --config local/config.yaml


Notes on developing with a running k8s pod:

    kubectl cp datapower_trawl.py {trawler_pod}:/app/datapower_trawl.py
    kubectl cp newconfig.yaml {trawler_pod}:/app/newconfig.yaml
    kubectl exec {trawler_pod} -- sh -c 'cd /app;python3 trawler.py -c newconfig.yaml'