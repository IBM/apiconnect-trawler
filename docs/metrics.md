# Metrics collected by trawler


The kind of metrics that trawler collects are currently as follows and are provided in the standard prometheus scrape format on the configured port:

### API Connect overview

| Description   | metric name |
| ------------- |-------------|
| API Connect version information | apiconnect_build_info| 
| Subsystem health (1 or 0)| apiconnect_health_status (labels for subsystems) | 
| Subsystem Resource status (states as labels) | apiconnect_analyticsclusters_status, apiconnect_gatewayclusters_status, apiconnect_managementclusters_status, apiconnect_portalclusters_status | 

### Management subsystem

| Description   | metric name |
| ------------- |-------------|
| Total users | manager_users_total| 
| Number of provider_orgs | manager_provider_orgs_total| 
| Number of catalogs | manager_catalogs_total| 
| Number of spaces | manager_spaces_total| 
| Number of draft products / apis | manager_draft_products_total / manager_draft_apis_total| 
| Number of products / apis | manager_products_total / manager_apis_total| 
| Number of consumer orgs | manager_consumer_orgs_total| 
| Number of consumer apps | manager_consumer_apps_total| 
| Number of subscriptions | manager_subscriptions_total| 
| Outstanding Gateway sent events | manager_gateway_processing_outstanding_sent_events | 
| Outstanding Gateway queued events | manager_gateway_processing_outstanding_queued_events | 


### DataPower subsystem
| Description   | metric name |
| ------------- |-------------|
| TCP connection stats | datapower_tcp_{state}|
| Log target stats: events processed, dropped, pending | datapower_logtarget_{name}_{type}|
| Object counts e.g. SSLClientProfile, APICollection, APIOperation etc. | datapower_{object}_total|
| HTTP Stats | datapower_http_tenSeconds/oneMinute/tenMinutes/oneDay |
| Gateway Peering Is primary? | datapower_gateway_peering_primary_info (peering_group=name) |
| Gateway Peering Primary link ok? | datapower_gateway_peering_primary_link (peering_group=name) |
| Gateway Peering Primary Offset | datapower_gateway_peering_primary_offset (peering_group=name) |
| Invoke test API (defined in config) response time | datapower_invoke_api_{name}_time |
| Invoke test API (defined in config) status | datapower_invoke_api_{name}_status_total (code=200, 500 etc. ) |
| Invoke test API (defined in config) created | datapower_invoke_api_{name}_status_created |



### Analytics subsystem
| Description   | metric name |
| ------------- |-------------|
| Cluster health status | analytics_cluster_status|
| Number of nodes in the cluster | analytics_data_nodes_total/analytics_nodes_total|
| Number of shards in states - active, relocating, initialising, unassigned | analytics_{state}_shards_total|
| Number of pending tasks | analytics_pending_tasks_total|
| API Calls in last hour by status code | analytics_apicalls_lasthour_2xx, 4xx etc|
