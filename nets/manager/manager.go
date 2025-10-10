package manager

import (
	"encoding/json"
	"fmt"
	"net/http"
	"nets"
	"os"
	"strings"
	"time"

	"github.com/IBM/alchemy-logging/src/go/alog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Manager struct {
	nets.BaseNet
	Config     ManagerNetConfig
	metrics    map[string]*prometheus.GaugeVec
	cloudToken nets.Token
	orgToken   nets.Token
}

type ManagerNetConfig struct {
	Enabled           bool   `yaml:"enabled"`
	Frequency         int    `yaml:"frequency"`
	Host              string `yaml:"host"`
	Insecure          bool   `yaml:"insecure"`
	ProcessOrgMetrics bool   `yaml:"process_org_metrics"`
	MoreStats         bool   `yaml:"more_stats"`
	Namespace         string `yaml:"namespace"`
	CertPath          string `yaml:"cert_path"`
}

type CountStruct struct {
	Users                  float64 `json:"users"`
	Members                float64 `json:"members"`
	ProviderOrgs           float64 `json:"provider_orgs"`
	Catalogs               float64 `json:"catalogs"`
	DraftProducts          float64 `json:"draft_products"`
	DraftApis              float64 `json:"draft_apis"`
	Apis                   float64 `json:"apis"`
	Products               float64 `json:"products"`
	ProductLifecycleStates struct {
		Staged     float64 `json:"staged"`
		Published  float64 `json:"published"`
		Deprecated float64 `json:"deprecated"`
		Retired    float64 `json:"retired"`
		Archived   float64 `json:"archived"`
	} `json:"product_lifecyle_states"`
	ConsumerOrgs  float64 `json:"consumer_orgs"`
	Subscriptions float64 `json:"subscriptions"`
	ConsumerApps  float64 `json:"consumer_apps"`
	Apps          float64 `json:"apps"` // At catalog level consumer_apps becomes apps
	Spaces        float64 `json:"spaces"`
}

type CloudTopology struct {
	CloudId   string       `json:"cloud_id"`
	CloudName string       `json:"cloud_name"`
	Counts    CountStruct  `json:"counts"`
	Orgs      TopologyOrgs `json:"orgs"`
}

type TopologyOrgs struct {
	TotalResults int   `json:"total_results"`
	Results      []Org `json:"results"`
}

type Org struct {
	Id      string `json:"id"`
	Name    string `json:"name"`
	Title   string `json:"title"`
	Enabled string `json:"enabled"`
	OrgType string `json:"org_type"`
	// "owner_url", "url", "owner"
	Counts   CountStruct `json:"counts"`
	Catalogs struct {
		TotalResults int       `json:"total_results"`
		Results      []Catalog `json:"results"`
	} `json:"catalogs"`
}
type Catalog struct {
	Id     string      `json:"id"`
	Name   string      `json:"name"`
	Counts CountStruct `json:"counts"`
}

type ConfiguredGatewayServices struct {
	TotalResults int                        `json:"total_results"`
	Results      []ConfiguredGatewayService `json:"results"`
}
type ConfiguredGatewayService struct {
	Name                    string `json:"name"`
	ServiceVersion          string `json:"service_version"`
	ServiceState            string `json:"service_state"`
	GatewayProcessingStatus struct {
		ServiceUpToDate         bool `json:"service_up_to_date"`
		OutstandingSentEvents   int  `json:"number_of_outstanding_sent_events"`
		OutstandingQueuedEvents int  `json:"number_of_outstanding_queued_events"`
	} `json:"gateway_processing_status"`
}

var version string

func invokeAPI(url string, certPath string, token string, insecure bool) (*http.Response, error) {
	return nets.InvokeAPI(url, certPath, token, insecure, false)
}

var log = alog.UseChannel("apim")

func (m *Manager) registerMetrics() {
	m.metrics = make(map[string]*prometheus.GaugeVec)
	m.metrics["userGauge"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "manager_users_total"}, []string{"component", "namespace", "scope", "name"})
	m.metrics["porgGauge"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "manager_provider_orgs_total", Help: "Total number of provider orgs"}, []string{"component", "namespace", "scope", "name"})
	m.metrics["catalogGauge"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "manager_catalogs_total", Help: "Total number of catalogs"}, []string{"component", "namespace", "scope", "name"})
	m.metrics["draftProductGauge"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "manager_draft_products_total", Help: "Total number of draft products"}, []string{"component", "namespace", "scope", "name"})
	m.metrics["draftApiGauge"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "manager_draft_apis_total", Help: "Total number of draft APIs"}, []string{"component", "namespace", "scope", "name"})
	m.metrics["apiGauge"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "manager_apis_total", Help: "Total number of APIs"}, []string{"component", "namespace", "scope", "name"})
	m.metrics["productGauge"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "manager_products_total", Help: "Total number of products"}, []string{"component", "namespace", "scope", "name"})
	m.metrics["corgGauge"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "manager_consumer_orgs_total", Help: "Total number of consumer orgs"}, []string{"component", "namespace", "scope", "name"})
	m.metrics["subGauge"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "manager_subscriptions_total", Help: "Total number of subscriptions"}, []string{"component", "namespace", "scope", "name"})
	m.metrics["appGauge"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "manager_consumer_apps_total", Help: "Total number of consumer applications"}, []string{"component", "namespace", "scope", "name"})
	m.metrics["spaceGauge"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "manager_spaces_total", Help: "Total number of spaces"}, []string{"component", "namespace", "scope", "name"})
	m.metrics["cloudInfo"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "manager_cloud_info", Help: "Cloud information"}, []string{"component", "namespace", "version", "id", "name"})
	m.metrics["outstandingSent"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "manager_gateway_processing_outstanding_sent_events", Help: "Outstanding sent events to gateway"}, []string{"org_name", "catalog_name", "gateway_service", "gateway_version"})
	m.metrics["outstandingQueued"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "manager_gateway_processing_outstanding_queued_events", Help: "Outstanding sent events to gateway"}, []string{"org_name", "catalog_name", "gateway_service", "gateway_version"})
}

//		self.trawler.set_gauge('manager', object_type, self.data['counts'][object_type])

func (m *Manager) getTopologyInfo(management_url string) (CloudTopology, error) {

	url := fmt.Sprintf("%s/api/cloud/topology", management_url)
	log.Log(alog.DEBUG2, url)

	response, err := invokeAPI(url, m.Config.CertPath, m.cloudToken.Token, m.Config.Insecure)
	if err != nil {
		log.Log(alog.ERROR, err.Error())
		return CloudTopology{}, err
	} else {
		defer response.Body.Close()
		var topologyInfo CloudTopology
		err = json.NewDecoder(response.Body).Decode(&topologyInfo)
		if err != nil {
			log.Log(alog.ERROR, err.Error())
			return CloudTopology{}, err
		}
		return topologyInfo, nil

	}

}

func (m *Manager) getWebhookStats(management_url string, org string, catalog string) {
	///api/catalogs/{}/{}/configured-gateway-services?fields=add(gateway_processing_status,events)
	url := fmt.Sprintf("%s/api/catalogs/%s/%s/configured-gateway-services?fields=add(gateway_processing_status,events)", management_url, org, catalog)
	log.Log(alog.DEBUG2, url)

	response, err := invokeAPI(url, m.Config.CertPath, m.orgToken.Token, m.Config.Insecure)
	if err != nil {
		log.Log(alog.ERROR, err.Error())
		return
	} else {
		defer response.Body.Close()
		var cgsResponse ConfiguredGatewayServices
		err = json.NewDecoder(response.Body).Decode(&cgsResponse)
		log.Log(alog.DEBUG, "Webhook status total results: %v", cgsResponse.TotalResults)
		for _, cgs := range cgsResponse.Results {
			m.metrics["outstandingSent"].WithLabelValues(org, catalog, cgs.Name, cgs.ServiceVersion).Set(float64(cgs.GatewayProcessingStatus.OutstandingSentEvents))
			m.metrics["outstandingQueued"].WithLabelValues(org, catalog, cgs.Name, cgs.ServiceVersion).Set(float64(cgs.GatewayProcessingStatus.OutstandingQueuedEvents))
		}
		if err != nil {
			log.Log(alog.ERROR, err.Error())
			return
		}
	}

}

func (m *Manager) setMetric(gauge_name string, value float64, labels []string) {
	m.metrics[gauge_name].WithLabelValues(labels...).Set(value)
}

func (m *Manager) publishTopologyMetrics(topologyCount CountStruct, managementName string, managementNamespace string, scope string, name string) {
	m.metrics["corgGauge"].WithLabelValues(managementName, managementNamespace, scope, name).Set(topologyCount.ConsumerOrgs)
	if scope == "cloud" { // Only cloud uses users other levels are members
		m.metrics["userGauge"].WithLabelValues(managementName, managementNamespace, scope, name).Set(topologyCount.Users)
		m.metrics["porgGauge"].WithLabelValues(managementName, managementNamespace, scope, name).Set(topologyCount.ProviderOrgs)
	} else {
		m.metrics["userGauge"].WithLabelValues(managementName, managementNamespace, scope, name).Set(topologyCount.Members)
	}
	m.metrics["appGauge"].WithLabelValues(managementName, managementNamespace, scope, name).Set(topologyCount.ConsumerApps)
	m.metrics["subGauge"].WithLabelValues(managementName, managementNamespace, scope, name).Set(topologyCount.Subscriptions)
	m.metrics["draftApiGauge"].WithLabelValues(managementName, managementNamespace, scope, name).Set(topologyCount.DraftApis)
	m.metrics["draftProductGauge"].WithLabelValues(managementName, managementNamespace, scope, name).Set(topologyCount.DraftProducts)
	m.metrics["apiGauge"].WithLabelValues(managementName, managementNamespace, scope, name).Set(topologyCount.Apis)
	m.metrics["productGauge"].WithLabelValues(managementName, managementNamespace, scope, name).Set(topologyCount.Products)
	m.metrics["catalogGauge"].WithLabelValues(managementName, managementNamespace, scope, name).Set(topologyCount.Catalogs)
	m.metrics["spaceGauge"].WithLabelValues(managementName, managementNamespace, scope, name).Set(topologyCount.Spaces)
}

func (m *Manager) getTokens(management_url string) error {
	var err error

	currentTimestamp := int(time.Now().Unix())

	if m.cloudToken.Expires < currentTimestamp {
		m.cloudToken, err = nets.GetToken(management_url, os.Getenv(("MGMT_CREDS")))
		if err != nil {
			log.Log(alog.ERROR, err.Error())
			return err
		}
	} else {
		log.Log(alog.DEBUG, "Using cached cloud token")
	}
	if m.orgToken.Expires < currentTimestamp {
		m.orgToken, err = nets.GetToken(management_url, os.Getenv(("ORG_CREDS")))
		if err != nil {
			log.Log(alog.ERROR, err.Error())
			m.orgToken = m.cloudToken // If org creds are not set use cloud creds
			log.Log(alog.WARNING, "Using cloud token for org level API calls as org creds are not set")
		}
	} else {
		log.Log(alog.DEBUG, "Using cached org token")
	}
	return nil
}

type ManagementClusterInfo struct {
	Name      string
	Namespace string
	Version   string
	URL       string
}

func (m *Manager) findAPIM() error {
	m.Config.CertPath = os.Getenv("MGMT_CERTS")
	apims := nets.GetCustomResourceList("management.apiconnect.ibm.com", "v1beta1", "managementclusters", m.Config.Namespace)
	if apims == nil {
		return nil
	}

	for _, apim := range apims.Items {
		if err := m.processManagementCluster(apim); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) processManagementCluster(apim interface{}) error {
	// Extract management cluster information
	clusterInfo := extractManagementClusterInfo(apim)
	log.Log(alog.INFO, "Found managementcluster: name %s, namespace %s, version: %s", 
		clusterInfo.Name, clusterInfo.Namespace, clusterInfo.Version)
	
	// Set global version (maintain compatibility with original code)
	version = clusterInfo.Version

	// Get tokens for API calls
	if err := m.getTokens(clusterInfo.URL); err != nil {
		return err
	}

	// Get topology information
	topology, err := m.getTopologyInfo(clusterInfo.URL)
	if err != nil {
		log.Log(alog.ERROR, err.Error())
		return err
	}

	// Publish cloud scoped metrics
	m.publishTopologyMetrics(topology.Counts, clusterInfo.Name, clusterInfo.Namespace, "cloud", "")
	
	// Process organizations if enabled
	if m.Config.ProcessOrgMetrics {
		m.processOrganizations(topology, clusterInfo)
	}
	
	return nil
}

func (m *Manager) processOrganizations(topology CloudTopology, clusterInfo ManagementClusterInfo) {
	for _, org := range topology.Orgs.Results {
		// Process catalogs and aggregate metrics
		for _, catalog := range org.Catalogs.Results {
			// Get webhook stats for this catalog
			m.getWebhookStats(clusterInfo.URL, org.Name, catalog.Name)
			
			// Aggregate catalog metrics to org level
			aggregateCatalogMetricsToOrg(&org.Counts, catalog.Counts)
		}
		
		// Set catalog count based on actual number of catalogs
		org.Counts.Catalogs = float64(len(org.Catalogs.Results))
		
		// Publish org scoped metrics
		m.publishTopologyMetrics(org.Counts, clusterInfo.Name, clusterInfo.Namespace, "org", org.Name)
	}
}

func aggregateCatalogMetricsToOrg(orgCounts *CountStruct, catalogCounts CountStruct) {
	orgCounts.Apis += catalogCounts.Apis
	orgCounts.Products += catalogCounts.Products
	orgCounts.ConsumerApps += catalogCounts.Apps // At catalog level consumer_apps becomes apps
	orgCounts.ConsumerOrgs += catalogCounts.ConsumerOrgs
	orgCounts.Spaces += catalogCounts.Spaces
	orgCounts.Subscriptions += catalogCounts.Subscriptions
}

func extractManagementClusterInfo(apim interface{}) ManagementClusterInfo {
	metadata := apim.(map[string]interface{})["metadata"].(map[string]interface{})
	status := apim.(map[string]interface{})["status"].(map[string]interface{})
	services := status["services"].(map[string]interface{})
	
	info := ManagementClusterInfo{
		Name:      metadata["name"].(string),
		Namespace: metadata["namespace"].(string),
		Version:   status["versions"].(map[string]interface{})["reconciled"].(string),
	}
	
	// Build the management URL with override handling
	defaultURL := fmt.Sprintf("https://%s.%s.svc:2000", services["juhu"], info.Namespace)
	log.Log(alog.INFO, "URL to use is %s", fmt.Sprintf("%s.%s.svc:2000", services["juhu"], info.Namespace))
	
	hostOverride := os.Getenv("MGMT_HOST")
	info.URL = defaultURL
	
	if hostOverride != "" {
		info.URL = ensureHTTPSPrefix(hostOverride)
		log.Log(alog.INFO, "Override host set - using %s for manager", hostOverride)
	}
	
	return info
}

func ensureHTTPSPrefix(url string) string {
	if !strings.HasPrefix(url, "https://") {
		return "https://" + url
	}
	return url
}

func (m *Manager) BackgroundFishing() {
	interval := m.Frequency
	ticker := time.NewTicker(interval)
	m.registerMetrics()
	for range ticker.C {
		if !m.Disabled {
			log.Log(alog.DEBUG, "Fishing for management clusters")
			m.Fish()
		}
	}
}

func (m *Manager) Fish() {
	err := m.findAPIM()
	if err != nil {
		log.Log(alog.FATAL, "disabled manager net")
		m.Disabled = true
	}
}
