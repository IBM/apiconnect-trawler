# Installing Trawler

To install trawler, you can make use of the sample yaml files within the [deployment](../deployment) folder. You will need to customise these according to your deployment in the following ways:

 - Adjustments to `config.yaml`:
     - Change namespace pointers to the appropriate namespace you have the API Connect components deployed in.
     - Select which nets you want to enable.
     - Set the usernames for datapower and cloud manager.
 - Adjustments to `kustomization.yaml`:
     - Set the namespace you would like to deploy trawler into.
     - Uncomment secret.yaml if you wish to include creation of secrets.
     - Uncomment servicemonitor.yaml and service.yaml if you are using the prometheus operator model.
 - Set secrets for password values either through base64 encoded values in secret.yaml or through your usual method for managing secrets.

These can either be imported to your cluster directly using `kubectl apply -k .` or to point to as a base for your own kustomize config and overlays with a kustomization.yaml which looks something like this: 

```
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
- trawler-secrets.yaml

configMapGenerator:
- name: trawler
  behavior: replace
  files:
  - config.yaml

bases:
- github.com/ibm/apiconnect-trawler//deployment?ref=main

namespace: apic-trawler

```

## API Manager credentials

For the manager_net you will need to provide trawler credentials to make the API Calls - these can either be client_credentials grants or traditional username/password. For this you will need the following permissions:

 - cloud:view
 - org:view
 - provider-org:view

## Prometheus discovery

The example yaml files in the deployment folder are configured to annotate the trawler pod so that if you have prometheus configured to discover based on the set of prometheus.io labels it should discover and scrape metrics from trawler automatically.

## Prometheus Operator model

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

For more details on the prometheus operator model see https://coreos.com/operators/prometheus/docs/latest/user-guides/getting-started.html

## Scraping Trawler metrics with Instana

If you are using Instana you can configure the Instana agent to scrape metrics from Trawler using the prometheus plugin options.  An example agent config would look something like this:

          com.instana.plugin.prometheus:
            customMetricSources:
            - url: '/'                       # metrics endpoint, the IP and port are auto-discovered
              metricNameIncludeRegex: '.*'   # regular expression to filter metrics 