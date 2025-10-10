package consumption

import (
	"context"
	"encoding/json"
	"fmt"
	"nets"
	"os"
	"strings"
	"time"

	"github.com/IBM/alchemy-logging/src/go/alog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

type Consumption struct {
	nets.BaseNet
	Config ConsumptionNetConfig
}

type ConsumptionNetConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Insecure  bool   `yaml:"insecure"`
	Frequency int    `yaml:"frequency"`
	CrnMask   string `yaml:"crn_mask"`
	Namespace string `yaml:"namespace"`
	Host      string `yaml:"host"`
}

type TotalResponse struct {
	Total int `json:"total"`
}

var log = alog.UseChannel("consumption")

var healthStatus = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "consumption_health_status",
		Help: "Health",
	},
	[]string{"component", "crnMask"})

func (a *Consumption) apiCallCount(analytics_url string) {
	formFactor := os.Getenv(("formFactor"))
	log.Log(alog.DEBUG, "Form factor is", formFactor)
	certPath := os.Getenv("ANALYTICS_CERTS")
	timeframe := "timeframe=last1minute"
	//url := fmt.Sprintf("%s/cloud/dashboards/status?%s", analytics_url, timeframe)
	url := fmt.Sprintf("%s/cloud/events/count?%s", analytics_url, timeframe)
	log.Log(alog.INFO, "Calling %s", url)
	response, err := nets.InvokeAPI(url, certPath, "", a.Config.Insecure, true)
	if err != nil {
		log.Log(alog.ERROR, err.Error())
	} else {
		var total TotalResponse
		err = json.NewDecoder(response.Body).Decode(&total)
		if err != nil {
			log.Log(alog.ERROR, err.Error())
		}
		err = response.Body.Close()
		if err != nil {
			log.Log(alog.ERROR, err.Error())
		}
		log.Log(alog.DEBUG, "%v", total)
		if total.Total > 0 {
			if formFactor == "ibm-cloud" {
				err := SendMetrics(true)
				if err != nil {
					log.Log(alog.ERROR, "Error sending metrics:", err)
				} else {
					log.Log(alog.INFO, "Metrics sent successfully.")
				}

			}
			healthStatus.WithLabelValues("API Calls", a.Config.CrnMask).Set(float64(1))
		} else {
			if formFactor == "ibm-cloud" {
				err := SendMetrics(false)
				if err != nil {
					log.Log(alog.ERROR, "Error sending metrics:", err)
				} else {
					log.Log(alog.INFO, "Metrics sent successfully.")
				}

			}
			healthStatus.WithLabelValues("API Calls", a.Config.CrnMask).Set(float64(0))
		}
	}
}

func (a *Consumption) findAnalytics(dynamicClient dynamic.DynamicClient) error {
	a7s_gvr := schema.GroupVersionResource{
		Group:    "analytics.apiconnect.ibm.com",
		Version:  "v1beta1",
		Resource: "analyticsclusters",
	}

	a7ss, err := dynamicClient.Resource(a7s_gvr).List(context.Background(), v1.ListOptions{})
	if err != nil {
		log.Log(alog.ERROR, "error getting analyticscluster: %v\n", err)
		return err
	}
	for _, a7s := range a7ss.Items {
		analyticsName := a7s.Object["metadata"].(map[string]interface{})["name"].(string)
		analyticsNamespace := a7s.Object["metadata"].(map[string]interface{})["namespace"].(string)
		log.Log(alog.INFO, "Found analyticscluster: name %s, namespace %s", analyticsName, analyticsNamespace)

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
			log.Log(alog.INFO, "Override host set - using %s for consumption", a.Config.Host)
		}
		a.apiCallCount(analytics_url)

	}
	return nil
}

func (a *Consumption) Fish() {
	dynamicClient := nets.GetDynamicKubeClient()

	err := a.findAnalytics(*dynamicClient)
	if err != nil {
		log.Log(alog.FATAL, "disabled consumption net")
		a.Disabled = true
	}
}

func (a *Consumption) BackgroundFishing() {
	interval := a.Frequency
	ticker := time.NewTicker(interval)

	// Start the  loop
	for range ticker.C {
		if !a.Disabled {
			log.Log(alog.DEBUG, "Fishing for consumption metrics")
			a.Fish()
		}
	}
}
