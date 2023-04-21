# Configuring Trawler

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
  manager:
    enabled: true
    username: trawler-monitor
    namespace: apic-management
  certs:
    enabled: true
```

## General trawler settings:
 - frequency: number of seconds to wait between trawling for metrics
 - use_kubeconfig: use the current kubeconfig from the environment instead looking at _in cluster_ config

### Logging

Customise the level of detail logged by trawler. Trawler uses [alchemy logging](https://github.com/IBM/alchemy-logging) for logging and the parameters here are passed into alog on initialilsation.

 - level: set the logging level (default is info)
 - filters: specify an individual log level for particular logging channels / trawler nets
 - format: (pretty or json) - typically json is used for parsing and pretty is used in development

### Prometheus settings:
The port specified in the prometheus block needs to match the prometheus annotations on the deployed trawler pod for prometheus to discover the metrics exposed.  

## Individual nets
Each of the different areas of metrics is handled by a separate net, which can be enabled/disabled independently.  The configuration for these is in most cases a pointer to the namespace the relevant subsystem is deployed into and credentials to use, however specific details are detailed below.  Passwords are loaded separately from the following values in a kubernetes secret mounted at the default location of `/app/secrets` - which can be overridden using the SECRETS environment variable:

 - datapower_password - password to use with the datapower net for accessing the [DataPower REST management](https://www.ibm.com/support/knowledgecenter/SS9H2Y_7.7.0/com.ibm.dp.doc/restmgtinterface.html) interface. 
 - cloudmanager_password - password to use with the manager net to retreive API Connect usage metrics.

### DataPower net

Sample configuration:

    datapower:
      enabled: true
      timeout: 5 
      username: trawler-monitor
      namespace: apic-gateway
      api_tests:
          enabled: true
          apis:
            - name: echo
              path: /apic-sre/live/echo?text=trawler
              method: get
              headers: {}

 - timeout: max seconds to wait for responses to DataPower REST calls
 - username: user to authenticate to datapower with - needs read privileges
 - namespace: (optional) namespace in which datapower is deployed - if not specified trawler will discover datapower pods across all namespaces it has permissions to. 
 - api_tests: Enable a set of APIs to test invokes against directly on the datapower pods:
   - enabled: true / false (default false)
   - apis: list of APIs to test
     - name: used for the prometheus metric naming (datapower_invoke_api_{name}...)
     - path: full path for the API 
     - method: HTTP Method to use
     - headers: map of key/value pairs for any headers required



### Management net

Sample config:

      manager:
        enabled: true
        grant_type: client_credentials
        secret: trawler-creds
        secret_namespace: apic-monitoring
        max_frequency: 600
        process_org_metrics: false
        namespace: apic

 - grant_type: Type of credentials to use for authentication to the platform API (currently supports password or client_credentials)
 - secret / secret_namespace: Name and namespace of secret containing the credentials 
 - max_frequency: (default 600) number of seconds between queries to the manager. As the majority of these metrics change less frequently this lets you reduce the frequency of calls made to the platform APIs. 
 - process_org_metrics: (default true) - query gateway processing event status for every provider org, in a large environment this will take a long time so you may want to disable it. 
 - namespace: namespace the management subsystem is deployed in

### Analytics net

Sample config:

      analytics:
        enabled: true
        namespace: apic

 - namespace: namespace the analytics subsystem is deployed in

### Certs net

Sample config:

      certs:
        enabled: true