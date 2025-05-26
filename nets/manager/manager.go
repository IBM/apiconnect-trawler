package manager

import (
	"encoding/json"
	"fmt"
	"nets"
	"strings"
	"time"

	"github.com/IBM/alchemy-logging/src/go/alog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Manager struct {
	nets.BaseNet
	Config  ManagerNetConfig
	metrics map[string]*prometheus.GaugeVec
	token   string
}

type ManagerNetConfig struct {
	Enabled           bool   `yaml:"enabled"`
	Frequency         int    `yaml:"frequency"`
	Host              string `yaml:"host"`
	ProcessOrgMetrics bool   `yaml:"process_org_metrics"`
	MoreStats         bool   `yaml:"more_stats"`
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

var crlList = nets.GetCustomResourceList
var invokeAPI = nets.InvokeAPI
var getToken = nets.GetToken

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
	log.Log(alog.DEBUG, url)

	response, err := invokeAPI(url, "", m.token)
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
	log.Log(alog.DEBUG, url)

	response, err := invokeAPI(url, "", m.token)
	if err != nil {
		log.Log(alog.ERROR, err.Error())
		return
	} else {
		defer response.Body.Close()
		var cgsResponse ConfiguredGatewayServices
		err = json.NewDecoder(response.Body).Decode(&cgsResponse)
		log.Log(alog.DEBUG, "Webhook status total results:", cgsResponse.TotalResults)
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

func (m *Manager) findAPIM() error {

	apims := crlList("management.apiconnect.ibm.com", "v1beta1", "managementclusters")
	if apims != nil {
		for _, apim := range apims.Items {
			managementName := apim.Object["metadata"].(map[string]interface{})["name"].(string)
			managementNamespace := apim.Object["metadata"].(map[string]interface{})["namespace"].(string)
			version = apim.Object["status"].(map[string]interface{})["versions"].(map[string]interface{})["reconciled"].(string)
			log.Log(alog.INFO, "Found managementcluster: name %s, namespace %s, version: %s", managementName, managementNamespace, version)

			services := apim.Object["status"].(map[string]interface{})["services"].(map[string]interface{})

			management_url := fmt.Sprintf("https://%s.%s.svc:2000", services["juhu"], managementNamespace)
			log.Log(alog.INFO, "URL to use is %s", fmt.Sprintf("%s.%s.svc:2000", services["juhu"], managementNamespace))
			if m.Config.Host != "" {
				management_url = m.Config.Host
				if !strings.HasPrefix(management_url, "https://") {
					management_url = "https://" + management_url
				}
				log.Log(alog.INFO, "Override host set - using %s for manager", m.Config.Host)
			}
			var err error
			m.token, err = getToken(management_url)
			if err != nil {
				log.Log(alog.ERROR, err.Error())
				return err
			}
			topology, err := m.getTopologyInfo(management_url)
			if err != nil {
				log.Log(alog.ERROR, err.Error())
				return err
			}

			//		m.metrics["cloudInfo"].WithLabelValues(managementName, managementNamespace, version, topologyInfo.CloudId, topologyInfo.CloudName).Set(1)
			// Publish cloud scoped count metrics
			m.publishTopologyMetrics(topology.Counts, managementName, managementNamespace, "cloud", "")
			for _, org := range topology.Orgs.Results {
				if m.Config.ProcessOrgMetrics {
					for _, catalog := range org.Catalogs.Results {
						// Retreive catalog level webhook information
						m.getWebhookStats(management_url, org.Name, catalog.Name)
						// Maybe Publish catalog scoped count metrics? - should be an option
						// m.publishTopologyMetrics(catalog.Counts, managementName, managementNamespace, "catalog", catalog.Name)
						// TODO: Expand this to cover all objects we want to total at org level
						org.Counts.Apis += catalog.Counts.Apis
						org.Counts.Products += catalog.Counts.Products
						org.Counts.ConsumerApps += catalog.Counts.Apps // At catalog level consumer_apps becomes apps
						org.Counts.ConsumerOrgs += catalog.Counts.ConsumerOrgs
						org.Counts.Spaces += catalog.Counts.Spaces
						org.Counts.Subscriptions += catalog.Counts.Subscriptions
					}
					org.Counts.Catalogs = float64(len(org.Catalogs.Results))
					// Publish org scoped count metrics
					m.publishTopologyMetrics(org.Counts, managementName, managementNamespace, "org", org.Name)
				}

			}
		}
	}
	return nil
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
