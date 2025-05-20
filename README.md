# trawler

![Trawler Logo ](docs/trawler.png)


Trawler is a metrics exporter for IBM API Connect.

 [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/5829/badge)](https://bestpractices.coreinfrastructure.org/projects/5829)

## Deployment

Trawler is designed to run within the same kubernetes cluster as API Connect, such that it can scrape metrics from the installed components and make them available. The metrics gathering in Trawler is separated into separate nets for the different types of metrics to expose so you can select which ones to enable for a particular environment.

It requires a service account with read access to list pods and services in the namespace(s) the API Connect components are deployed in.

[More details on installing trawler](docs/install.md)

### Configuring trawler

Trawler gets its config from a mounted configmap containing config.yaml which looks like this:

```yaml
trawler:
  frequency: 10
  use_kubeconfig: false
prometheus:
  port: 63512 
  enabled: true
logging: 
  level: debug
  filters: trawler:trace
  format: pretty
nets:
  datapower:
    enabled: true
    timeout: 5 
    username: trawler-monitor
    namespace: apic-gateway
  product:
    enabled: true
    username: trawler-monitor
    namespace: apic-management
```
**General trawler settings:**
 - frequency: number of seconds to wait between trawling for metrics
 - use_kubeconfig: use the current kubeconfig from the environment instead looking at _in cluster_ config
 - logging: set the default logging level, output format and filters for specific components 
**Prometheus settings:**
The port specified in the prometheus block needs to match the prometheus annotations on the deployed trawler pod for prometheus to discover the metrics exposed.  

**Individual nets**
Each of the different areas of metrics is handled by a separate net, which can be enabled/disabled independently.  The configuration for these is currently a pointer to the namespace the relevant subsystem is deployed into and a username to use.  Passwords are loaded separately from the following values in a kubernetes secret mounted at the default location of `/app/secrets` - which can be overridden using the SECRETS environment variable:

 - datapower_password - password to use with the datapower net for accessing the [DataPower REST management](https://www.ibm.com/support/knowledgecenter/SS9H2Y_7.7.0/com.ibm.dp.doc/restmgtinterface.html) interface. 
 - cloudmanager_password - password to use with the manager net to retreive API Connect usage metrics.

## Issues, enhancements and pull requests

Feature requests and issue reports are welcome as [github issues](https://github.com/IBM/apiconnect-trawler/issues) through this repository.  Contributions of pull requests are also accepted and should be provided with a linked issue explaining the reasoning behind the change, should follow the existing code format standards and tests should be included in the PR ensuring the overall code coverage is not reduced. 

## More documentation

 - [Metrics gathered by trawler](docs/metrics.md)
 - [Install](docs/install.md)
 - [Frequently asked questions](docs/faq.md)


## Development tips

## Running locally for development 

### Secret set up

    secrets/
      datapower/  <-- datapower login credentials (DP_CREDS)
        password
      management/  <-- client credentials for accessing APIC platform api (MGMT_CREDS)
        client_id
        client_secret
      analytics/   <-- client certificate to connect to analytics (ANALYTICS_CERTS)
        ca.crt
        tls.crt
        tls.key
      cert/  <-- server certificates for trawler (CERT_PATH if using SECURE)
        ca.crt
        tls.crt
        tls.key

Then ensure the following environment variables are set:

```
export MGMT_CREDS=secrets/management
export DP_CREDS=secrets/datapower
export ANALYTICS_CERTS=secrets/analytics
# if testing using https and mtls
export SECURE=true
export CERT_PATH=secrets/cert
```


### DataPower

 - Log into your cluster. 
 - Ensure you have the password available in the secrets directory and the username set in your config

```
kubectl get secret gateway-admin-secret -o yaml | grep " password" | awk '{print $2}' | base64 -d > secrets/datapower/password
```

 - Open port-forward to both ports 5554 (for REST Management) and 9443 (for API Invoke)
  
```
kubectl port-forward $(kubectl get pods -l app.kubernetes.io/name=datapower -o name | head -1) 9443 5554
```

By default trawler will look for all the gateway pods in the cluster by label - this can also be restricted by namespace through the config.  Typically running in the cluster, trawler will communicate directly with each pod to retrieve metrics.  For local testing or running outside of the cluster you may wish to override the host it uses to retrieve metrics in the config (nets.datapower.host) - this will then be used instead of each pods individual IP address - getting metrics from a single place but reporting as if it spoke to each in turn.







### Analytics

 - Log into your cluster. 
 - Ensure you have the certificates available in the secrets directory

```
kubectl get secret analytics-client -o yaml > /tmp/analytics-client
cat /tmp/analytics-client | grep " tls.crt" | awk '{print $2}' | base64 -d > secrets/analytics/tls.crt
cat /tmp/analytics-client | grep " tls.key" | awk '{print $2}' | base64 -d > secrets/analytics/tls.key
```

 - Open port-forward to port 3009 on one of the analytics director pods

```
kubectl port-forward $(kubectl get deployment -l app.kubernetes.io/name=director -o name) 3009
```


