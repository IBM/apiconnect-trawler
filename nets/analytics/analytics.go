package analytics

import (
	"encoding/json"
	"fmt"
	"nets"
	"os"
	"strings"
	"time"

	"github.com/IBM/alchemy-logging/src/go/alog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"k8s.io/client-go/dynamic"
)

type Analytics struct {
	nets.BaseNet
	Config AnalyticsNetConfig
}

type AnalyticsNetConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Insecure  bool   `yaml:"insecure"`
	Frequency int    `yaml:"frequency"`
	Host      string `yaml:"host"`
	Namespace string `yaml:"namespace"`
}

type ClusterHealth struct {
	ClusterName              string `json:"cluster_name"`
	Status                   string `json:"status"`
	TimedOut                 bool   `json:"timed_out"`
	NodeCount                int    `json:"number_of_nodes"`
	DataNodeCount            int    `json:"number_of_data_nodes"`
	DiscoveredMaster         bool   `json:"discovered_master"`
	DiscoveredClusterManager bool   `json:"discovered_cluster_manager"`
	ActivePrimaryShards      int    `json:"active_primary_shards"`
	ActiveShards             int    `json:"active_shards"`
	RelocatingShards         int    `json:"relocating_shards"`
	InitialisingShards       int    `json:"initializing_shards"`
	UnassignedShards         int    `json:"unassigned_shards"`
	PendingTasks             int    `json:"pending_tasks"`
	//"delayed_unassigned_shards":0,"number_of_in_flight_fetch":0,"task_max_waiting_in_queue_millis":0,"active_shards_percent_as_number":100}
}

type StatusGroup struct {
	Group string `json:"group"`
	Value int    `json:"value"`
}

/*
	{
		"search_time":5,
		"status_codes":{
			"total":0,
			"data":[]
		},
		"total_api_calls":{
			"data":0
		},"errors":{"total":0,"data":[]},"success_rate":{"total":0,"data":[]},"total_errors":{"data":0}}
*/
type StatusDashboard struct {
	SearchTime  int `json:"search_time"`
	StatusCodes struct {
		Total int           `json:"total"`
		Data  []StatusGroup `json:"data"`
	} `json:"status_codes"`
	TotalAPICalls struct {
		Data int `json:"data"`
	} `json:"total_api_calls"`
}
type PipelineStats struct {
	Events struct {
		In  int `json:"in"`
		Out int `json:"out"`
	} `json:"events"`
}

type IngestionPipelineStats struct {
	Data struct {
		Host      string `json:"host"`
		Version   string `json:"version"`
		Status    string `json:"status"`
		Pipelines struct {
			Offload PipelineStats `json:"offload"`
			Storage PipelineStats `json:"storage"`
			Intake  PipelineStats `json:"intake"`
		} `json:"pipelines"`
	} `json:"data"`
}

var clusterStatus = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "analytics_cluster_status", Help: "Cluster Status"}, []string{"component", "namespace"})
var dataNodeCount = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "analytics_data_nodes_total", Help: "Active Shards"}, []string{"component", "namespace"})
var nodeCount = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "analytics_nodes_total", Help: "Active Shards"}, []string{"component", "namespace"})
var primaryShards = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "analytics_active_primary_shards_total", Help: "Active Shards"}, []string{"component", "namespace"})
var activeShards = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "analytics_active_shards_total", Help: "Active Shards"}, []string{"component", "namespace"})
var relocatingShards = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "analytics_relocating_shards_total", Help: "Active Shards"}, []string{"component", "namespace"})
var initializingShards = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "analytics_initializing_shards_total", Help: "Active Shards"}, []string{"component", "namespace"})
var unassignedShards = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "analytics_unassigned_shards_total", Help: "Active Shards"}, []string{"component", "namespace"})
var pendingTasks = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "analytics_pending_tasks_total", Help: "Active Shards"}, []string{"component", "namespace"})
var eventsIn = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "analytics_ingestion_events_in", Help: "Pipeline stats - events in"}, []string{"pod_name", "component", "namespace", "pipeline"})
var eventsOut = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "analytics_ingestion_events_out", Help: "Pipeline stats - events out"}, []string{"pod_name", "component", "namespace", "pipeline"})

var apiCallsGauge *prometheus.GaugeVec
var log = alog.UseChannel("a7s")

var healthStatus = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "analytics_data",
		Help: "Health",
	},
	[]string{"component", "crnMask", "version"})

func (a *Analytics) clusterHealth(analytics_url string, analyticsName string, analyticsNamespace string) {
	certPath := os.Getenv("ANALYTICS_CERTS")
	url := fmt.Sprintf("%s/cloud/clustermgmt/storage/cluster/health", analytics_url)
	log.Log(alog.INFO, "Calling %s", url)
	response, err := nets.InvokeAPI(url, certPath, "", a.Config.Insecure, true)
	if err != nil {
		log.Log(alog.ERROR, err.Error())
	} else {
		var health ClusterHealth
		err = json.NewDecoder(response.Body).Decode(&health)
		if err != nil {
			log.Log(alog.ERROR, err.Error())
		}
		err = response.Body.Close()
		if err != nil {
			log.Log(alog.ERROR, err.Error())
		}

		activeShards.WithLabelValues(analyticsName, analyticsNamespace).Set(float64(health.ActiveShards))
		dataNodeCount.WithLabelValues(analyticsName, analyticsNamespace).Set(float64(health.DataNodeCount))
		nodeCount.WithLabelValues(analyticsName, analyticsNamespace).Set(float64(health.NodeCount))
		primaryShards.WithLabelValues(analyticsName, analyticsNamespace).Set(float64(health.ActivePrimaryShards))
		activeShards.WithLabelValues(analyticsName, analyticsNamespace).Set(float64(health.ActiveShards))
		relocatingShards.WithLabelValues(analyticsName, analyticsNamespace).Set(float64(health.RelocatingShards))
		initializingShards.WithLabelValues(analyticsName, analyticsNamespace).Set(float64(health.InitialisingShards))
		unassignedShards.WithLabelValues(analyticsName, analyticsNamespace).Set(float64(health.UnassignedShards))
		pendingTasks.WithLabelValues(analyticsName, analyticsNamespace).Set(float64(health.PendingTasks))
		switch health.Status {
		case "green":
			clusterStatus.WithLabelValues(analyticsName, analyticsNamespace).Set(2)
		case "yellow":
			clusterStatus.WithLabelValues(analyticsName, analyticsNamespace).Set(1)
		case "red":
			clusterStatus.WithLabelValues(analyticsName, analyticsNamespace).Set(0)
		}
	}
}

func (a *Analytics) apiCallCount(analytics_url string, analyticsName string, analyticsNamespace string) {
	certPath := os.Getenv("ANALYTICS_CERTS")
	timeframe := "timeframe=last1hour"
	url := fmt.Sprintf("%s/cloud/dashboards/status?%s", analytics_url, timeframe)
	log.Log(alog.INFO, "Calling %s", url)
	response, err := nets.InvokeAPI(url, certPath, "", a.Config.Insecure, true)
	if err != nil {
		log.Log(alog.ERROR, err.Error())
	} else {
		var status StatusDashboard
		err = json.NewDecoder(response.Body).Decode(&status)
		if err != nil {
			log.Log(alog.ERROR, err.Error())
		}
		err = response.Body.Close()
		if err != nil {
			log.Log(alog.ERROR, err.Error())
		}
		log.Log(alog.DEBUG, "%v", status)

		for _, statusPair := range status.StatusCodes.Data {
			apiCallsGauge.WithLabelValues(statusPair.Group[0:3]).Set(float64(statusPair.Value))
		}
	}
}

func (a *Analytics) ingestionStats(analytics_url string, analyticsName string, analyticsNamespace string) {
	certPath := os.Getenv("ANALYTICS_CERTS")
	url := fmt.Sprintf("%s/cloud/clustermgmt/ingestion/node/stats/pipelines", analytics_url)
	log.Log(alog.INFO, "Calling %s", url)
	response, err := nets.InvokeAPI(url, certPath, "", a.Config.Insecure, true)
	if err != nil {
		log.Log(alog.ERROR, err.Error())
	} else {
		var ingestion IngestionPipelineStats
		err = json.NewDecoder(response.Body).Decode(&ingestion)
		if err != nil {
			log.Log(alog.ERROR, err.Error())
		}
		err = response.Body.Close()
		if err != nil {
			log.Log(alog.ERROR, err.Error())
		}
		eventsIn.WithLabelValues(ingestion.Data.Host, analyticsName, analyticsNamespace, "offload").Set(float64(ingestion.Data.Pipelines.Offload.Events.In))
		eventsOut.WithLabelValues(ingestion.Data.Host, analyticsName, analyticsNamespace, "offload").Set(float64(ingestion.Data.Pipelines.Offload.Events.Out))
		eventsIn.WithLabelValues(ingestion.Data.Host, analyticsName, analyticsNamespace, "storage").Set(float64(ingestion.Data.Pipelines.Storage.Events.In))
		eventsOut.WithLabelValues(ingestion.Data.Host, analyticsName, analyticsNamespace, "storage").Set(float64(ingestion.Data.Pipelines.Storage.Events.Out))
		eventsIn.WithLabelValues(ingestion.Data.Host, analyticsName, analyticsNamespace, "intake").Set(float64(ingestion.Data.Pipelines.Intake.Events.In))
		eventsOut.WithLabelValues(ingestion.Data.Host, analyticsName, analyticsNamespace, "intake").Set(float64(ingestion.Data.Pipelines.Intake.Events.Out))
	}
}

func (a *Analytics) findAnalytics(dynamicClient dynamic.DynamicClient) error {
	a7ss := nets.GetCustomResourceList("analytics.apiconnect.ibm.com", "v1beta1", "analyticsclusters", a.Config.Namespace)

	for _, a7s := range a7ss.Items {
		analyticsName := a7s.Object["metadata"].(map[string]interface{})["name"].(string)
		analyticsNamespace := a7s.Object["metadata"].(map[string]interface{})["namespace"].(string)
		version := a7s.Object["status"].(map[string]interface{})["versions"].(map[string]interface{})["reconciled"].(string)
		log.Log(alog.INFO, "Found analyticscluster: name %s, namespace %s, version: %s", analyticsName, analyticsNamespace, version)

		services := a7s.Object["status"].(map[string]interface{})["services"].(map[string]interface{})

		var analytics_url string
		analytics_url = fmt.Sprintf("https://%s.%s.svc:3009", services["director"], analyticsNamespace)
		log.Log(alog.INFO, "Host/port to use is  %s", fmt.Sprintf("%s.%s.svc:3009", services["director"], analyticsNamespace))
		if a.Config.Host != "" {
			// TODO: Add support to run from outside the cluster
			analytics_url = a.Config.Host
			if !strings.HasPrefix(analytics_url, "https://") {
				analytics_url = "https://" + analytics_url
			}
			log.Log(alog.INFO, "Override host set - using %s for analytics", a.Config.Host)
		}
		a.clusterHealth(analytics_url, analyticsName, analyticsNamespace)
		a.apiCallCount(analytics_url, analyticsName, analyticsNamespace)
		a.ingestionStats(analytics_url, analyticsName, analyticsNamespace)
	}
	return nil
}

func (a *Analytics) Fish() {
	dynamicClient := nets.GetDynamicKubeClient()

	err := a.findAnalytics(*dynamicClient)
	if err != nil {
		log.Log(alog.FATAL, "disabled analytics net")
		a.Disabled = true
	}
}

func (a *Analytics) BackgroundFishing() {
	interval := a.Frequency
	ticker := time.NewTicker(interval)
	apiCallsGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "apicalls_last_hour_total", Help: "API Calls made"}, []string{"status"})
	// TODO: should we do apiCalls metrics on a different ticker?
	// Start the analytics loop
	for range ticker.C {
		if !a.Disabled {
			log.Log(alog.DEBUG, "Fishing for analytics")
			a.Fish()
		}
	}
}
