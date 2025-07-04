package apiconnect

import (
	"fmt"
	"nets"
	"strings"
	"time"

	"github.com/IBM/alchemy-logging/src/go/alog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type APIConnect struct {
	nets.BaseNet
	nets.NetInterface
	Config       APIConnectNetConfig
	metrics      map[string]*prometheus.GaugeVec
	healthStatus prometheus.GaugeVec
}
type APIConnectNetConfig struct {
	Enabled      bool        `yaml:"enabled"`
	Frequency    int         `yaml:"frequency"`
	Host         string      `yaml:"host"`
	HealthPrefix string      `yaml:"health_prefix"`
	HealthLabel  HealthLabel `yaml:"health_label"`
	Namespace    string      `yaml:"namespace"`
}
type HealthLabel struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

var log = alog.UseChannel("apic")

func (a *APIConnect) crdStatusMetrics(group, version, resource string, crdStatus prometheus.GaugeVec) {
	subsystems := nets.GetCustomResourceList(group, version, resource, a.Config.Namespace)

	for _, subsystem := range subsystems.Items {
		subsystemName := subsystem.Object["metadata"].(map[string]interface{})["name"].(string)
		subsystemNamespace := subsystem.Object["metadata"].(map[string]interface{})["namespace"].(string)
		version := subsystem.Object["status"].(map[string]interface{})["versions"].(map[string]interface{})["reconciled"].(string)
		conditions := subsystem.Object["status"].(map[string]interface{})["conditions"].([]interface{})
		for i := 0; i < len(conditions); i++ {
			conditionType := conditions[i].(map[string]interface{})["type"].(string)
			conditionStatus := conditions[i].(map[string]interface{})["status"].(string)
			if conditionStatus == "True" {
				crdStatus.WithLabelValues(subsystemName, subsystemNamespace, conditionType).Set(1)
			} else {
				crdStatus.WithLabelValues(subsystemName, subsystemNamespace, conditionType).Set(0)
			}
			if conditionType == "Ready" {
				conditionMessage := conditions[i].(map[string]interface{})["message"].(string)
				var healthValue float64
				if conditionStatus == "True" || strings.Contains(conditionMessage, "Site Upgrades Executing") {
					healthValue = 1
				} else {
					healthValue = 0
				}
				if version != "" {
					if a.Config.HealthLabel.Name != "" {
						a.healthStatus.WithLabelValues(resource+"_"+subsystemName, version, a.Config.HealthLabel.Value).Set(healthValue)
					} else {
						a.healthStatus.WithLabelValues(resource+"_"+subsystemName, version).Set(healthValue)
					}
				}
			}

		}

	}
}

func (a *APIConnect) BackgroundFishing() {
	interval := a.Frequency
	ticker := time.NewTicker(interval)
	var metricName = "health_status"
	var metricLabels = []string{"component", "version"}

	if a.Config.HealthLabel.Name != "" {
		metricLabels = append(metricLabels, a.Config.HealthLabel.Name)
	}
	if a.Config.HealthPrefix != "" {
		metricName = fmt.Sprintf("%s_health_status", a.Config.HealthPrefix)
	}
	a.healthStatus = *promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: metricName,
			Help: "Health",
		},
		metricLabels)
	a.registerMetrics()
	// Start the main loop
	for range ticker.C {
		log.Log(alog.DEBUG, "Fishing for API Connect subsystem CRs")
		a.Fish()
	}
}

func (a *APIConnect) registerMetrics() {
	a.metrics = make(map[string]*prometheus.GaugeVec)

	a.metrics["gwCrdStatus"] = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "apiconnect_gatewaycluster_status",
			Help: "The status of CRD conditions for gateway clusters",
		},
		[]string{"name", "namespace", "type"})

	a.metrics["mgmtCrdStatus"] = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "apiconnect_managementcluster_status",
			Help: "The status of CRD conditions for management clusters",
		},
		[]string{"name", "namespace", "type"})

	a.metrics["ptlCrdStatus"] = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "apiconnect_portalcluster_status",
			Help: "The status of CRD conditions for portal clusters",
		},
		[]string{"name", "namespace", "type"})

	a.metrics["a7sCrdStatus"] = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "apiconnect_analyticscluster_status",
			Help: "The status of CRD conditions for analytics clusters",
		},
		[]string{"name", "namespace", "type"})
}
func (a *APIConnect) Fish() {
	a.crdStatusMetrics("gateway.apiconnect.ibm.com", "v1beta1", "gatewayclusters", *a.metrics["gwCrdStatus"])
	a.crdStatusMetrics("management.apiconnect.ibm.com", "v1beta1", "managementclusters", *a.metrics["mgmtCrdStatus"])
	a.crdStatusMetrics("portal.apiconnect.ibm.com", "v1beta1", "portalclusters", *a.metrics["ptlCrdStatus"])
	a.crdStatusMetrics("analytics.apiconnect.ibm.com", "v1beta1", "analyticsclusters", *a.metrics["a7sCrdStatus"])
}
