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
  # Common certificate configuration:
  # Each net can have an 'insecure' option to control certificate validation
  # When insecure is false (default), certificates are validated using CA certificates
  # When insecure is true, certificate validation is skipped
  datapower:
    enabled: true
    timeout: 5
    username: trawler-monitor
    namespace: apic-gateway
    insecure: false
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
      insecure: false
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
 - insecure: (default false) when set to true, certificate validation will be skipped when making API calls to DataPower REST management interface
 - api_tests: Enable a set of APIs to test invokes against directly on the datapower pods:
   - enabled: true / false (default false)
   - insecure: (default false) when set to true, certificate validation will be skipped when making API calls to DataPower
   - apis: list of APIs to test
     - name: used for the prometheus metric naming (datapower_invoke_api_{name}...)
     - path: full path for the API
     - method: HTTP Method to use
     - headers: map of key/value pairs for any headers required

To provide CA certificates to validate the calls against, set the environment variable DP_CERTS to a path containing a `ca.crt` file containing 
a bundle of CA certificates covering for both REST Management and the API invocation.  By default datapower will generate a self-signed certificate within the system for the rest-management interface so configuring this to be a ca signed certificate will require additional configuration. 

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
        insecure: false

 - namespace: namespace the analytics subsystem is deployed in
 - insecure: (default false) when set to true, certificate validation will be skipped when making API calls to the analytics subsystem

### Manager net certificate configuration

The manager net uses the `MGMT_CERTS` environment variable to locate certificates for secure communication. This should point to a directory containing the ca certificate for the management subsystem in ca.crt (typically by mounting the management-server secret)
Sample config:

      manager:
        enabled: true
        insecure: false
        # other manager options...

 - insecure: (default false) when set to true, certificate validation will be skipped when making API calls to the management subsystem

### Analytics net certificate configuration

The analytics net uses the `ANALYTICS_CERTS` environment variable to locate certificates for secure communication. This should point to a directory containing the certificates to communicate with analytics (typically by mounting the analytics-client secret):
 
### Certs net

Sample config:

      certs:
        enabled: true

## Certificate Validation

Trawler uses TLS certificates for secure communication with API Connect components. Each net can be configured with an `insecure` option that controls certificate validation:

```yaml
nets:
  manager:
    insecure: false  # Certificate validation enabled (default)
  analytics:
    insecure: true   # Certificate validation disabled
```

When `insecure` is set to `false` (default), Trawler validates server certificates using CA certificates from the following environment variables:

- `MGMT_CERTS`: Directory containing certificates for the management subsystem
- `ANALYTICS_CERTS`: Directory containing certificates for the analytics subsystem
- `DP_CERTS`: Directory containing ca.crt with CA certificates for the datapower rest management interface and for API invoke tests

These environment variables should point to directories containing the certificates required - for certificate validation they require a `ca.crt` file, for analytics the communication uses mTLS so will require the tls.crt and tls.key to use as the client certificate - these typically point to mounted secrets containing the necessary certificate files.