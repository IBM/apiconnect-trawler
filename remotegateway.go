package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/IBM/alchemy-logging/src/go/alog"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// allowedMetrics is a list of metrics that are allowed to be exposed
var allowedMetrics = map[string]bool{
	"trawler_version_info":             true,
	"health_status":                    true,
	"datapower_version_info":           true,
	"apiconnect_gatewaycluster_status": true,
}

func RemoteGatewayMetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, getMetrics())
}

// Set up a timer to report hourly
func RemoteGatewayReport(ClientId, Url string) {
	log.Log(alog.INFO, "Starting hourly reporting for remote gateway")
	ticker := time.NewTicker(1 * time.Hour)
	// Start the datapower loop
	for range ticker.C {
		PostMetrics(ClientId, Url)
	}
}

// Send metrics for remote gateway back to IBM APIC SaaS
func PostMetrics(ClientId, Url string) {

	client := &http.Client{}

	client.Transport = &http.Transport{}
	log.Log(alog.DEBUG, "Calling %s", Url)

	req, err := http.NewRequest("POST", Url, strings.NewReader(getMetrics()))
	if err != nil {
		log.Log(alog.ERROR, err.Error())
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("User-Agent", fmt.Sprintf("Trawler/%s", Version))
	req.Header.Add("X-IBM-Client-ID", ClientId)

	response, err := client.Do(req)
	if err != nil {
		log.Log(alog.ERROR, err.Error())
	}
	if response.StatusCode != 200 {
		log.Log(alog.ERROR, "unexpected status - got %s, expected 200", response.Status)
	}
}

// MetricData represents the structured data for a metric
type MetricData map[string]interface{}

// StatusMetricData represents the structured data for a status metric
type StatusMetricData map[string]interface{}

type StatusOutput struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Namespace string `json:"namespace"`
	Version   string `json:"version"`
}
type TrawlerDetails struct {
	Version   string `json:"version"`
	BuildTime string `json:"buildtime"`
}

type Payload struct {
	Subsystems []StatusOutput `json:"subsystems"`
	Trawler    TrawlerDetails `json:"trawler"`
}

// getMetrics gathers and formats Prometheus metrics for remote gateway consumption
func getMetrics() string {
	metrics, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		// Log the error properly instead of just printing
		fmt.Println(err)
		return "{}"
	}

	// Process metrics and build the compact representation
	gatewayMetrics := processMetrics(metrics)

	response := Payload{
		Trawler:    TrawlerDetails{Version: Version, BuildTime: BuildTime},
		Subsystems: gatewayMetrics,
	}
	jsonData, _ := json.MarshalIndent(response, "", "  ")
	return string(jsonData)
}

// processMetrics processes the gathered metrics and separates them into status and non-status metrics
func processMetrics(metrics []*dto.MetricFamily) []StatusOutput {
	// Map to store status metrics by name and namespace
	var gatewayMetrics []StatusOutput

	for _, metricFamily := range metrics {
		metricName := metricFamily.GetName()

		// Skip metrics that are not in the allowlist
		if !allowedMetrics[metricName] {
			continue
		}

		for _, metric := range metricFamily.GetMetric() {
			// Extract labels from the metric
			labels := extractLabels(metric)

			// Get the value based on metric type
			//value := extractValue(metric)

			switch metricName {
			case "trawler_version_info":
				// Include trawler details
			case "health_status":
				gatewayMetrics = append(gatewayMetrics, processHealthStatusMetric(labels))
			}
		}
	}
	return gatewayMetrics
}

// extractLabels extracts label key-value pairs from a metric
func extractLabels(metric *dto.Metric) map[string]string {
	labels := make(map[string]string)
	for _, label := range metric.GetLabel() {
		labels[label.GetName()] = label.GetValue()
	}
	return labels
}

// processStatusMetric handles status metrics specifically
func processHealthStatusMetric(labels map[string]string) StatusOutput {

	// Initialize the entry if it doesn't exist
	statusMetric := StatusOutput{
		Status:    labels["condition"],
		Version:   labels["version"],
		Name:      labels["name"],
		Namespace: labels["namespace"],
	}

	// Append to gateway metrics
	return statusMetric
}
