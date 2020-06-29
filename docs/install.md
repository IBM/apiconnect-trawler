# Prometheus discovery

The example yaml files in the deployment folder are configured to annotate the trawler pod so that if you have prometheus configured to discover based on the set of prometheus.io labels it should discover and scrape metrics from trawler automatically.

# Prometheus Operator model

In the operator model you will need to ensure that prometheus-operator is deployed with the option `--set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false` ([ref](https://github.com/helm/charts/issues/11310)) - this causes it not to pick up any ServiceMonitors that do not match the helm deployment labels. 

In this model alongside the standard trawler deployment, you will also need to create the following, which can be uncommented in kustomization.yaml to use with `kubectl apply -k .`:
 - [service](../deployment/service.yaml) to point to the metrics endpoint on the trawler pod 
 - [ServiceMonitor](../deployment/servicemonitor.yaml) to tell the prometheus operator where to find the metrics. 


Alternatively you can adjust the deployment of the trawler pod to match the search pattern of the prometheus operator - look at it's definition to see what labels it's looking for, which you can see using `kubectl get prometheuses.monitoring.coreos.com -o yaml` - the key part is the values that start serviceMonitor e.g. 

    serviceMonitorNamespaceSelector: {}
    serviceMonitorSelector:
      matchLabels:
        release: prom-operator

In this case prometheus-operator is configured to look for serviceMonitors set up with the release `prom-operator`.



Reference on the operator model:
 - https://coreos.com/operators/prometheus/docs/latest/user-guides/getting-started.html