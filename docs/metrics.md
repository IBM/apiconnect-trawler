# Metrics collected by trawler


The kind of metrics that trawler collects are currently as follows:

### Management subsystem

| Description   | metric name |
| ------------- |-------------|
| API Connect version information | apiconnect_build_info| 
| Total users | apiconnect_users_total| 
| Number of provider_orgs | apiconnect_provider_orgs_total| 
| Number of consumer orgs | apiconnect_consumer_orgs_total| 
| Number of catalogs | apiconnect_catalogs_total| 
| Number of draft products / apis | apiconnect_draft_products_total / apiconnect_draft_apis_total| 
| Number of products / apis | apiconnect_products_total / apiconnect_apis_total| 
| Number of subscriptions | apiconnect_subscriptions_total| 


### DataPower subsystem
| Description   | metric name |
| ------------- |-------------|
| TCP connection stats | datapower_tcp_{state}|
| Log target stats: events processed, dropped, pending | datapower_logtarget_{name}_{type}|
| Object counts e.g. SSLClientProfile, APICollection, APIOperation etc. | datapower_{object}_total|
| HTTP Stats | datapower_http_tenSeconds/oneMinute/tenMinutes/oneDay|

### Analytics subsystem
| Description   | metric name |
| ------------- |-------------|
| Cluster health status | analytics_cluster_status|
| Number of nodes in the cluster | analytics_data_nodes_total/analytics_nodes_total|
| Number of shards in states - active, relocating, initialising, unassigned | analytics_{state}_shards_total|
| Number of pending tasks | analytics_pending_tasks_total|
