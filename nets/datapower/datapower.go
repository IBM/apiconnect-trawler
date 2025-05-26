package datapower

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"nets"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/IBM/alchemy-logging/src/go/alog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

type DataPower struct {
	nets.BaseNet
	Config        DataPowerNetConfig
	metrics       map[string]*prometheus.GaugeVec
	invokeCounter *prometheus.CounterVec
}

type DataPowerNetConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Frequency int    `yaml:"frequency"`
	Host      string `yaml:"host"`
	Username  string `yaml:"username"`
	TimeOut   int    `yaml:"timeout"`
	Namespace string `yaml:"namespace"`
	APITests  struct {
		Enabled bool      `yaml:"enabled"`
		TimeOut int       `yaml:"timeout"`
		APIs    []APITest `yaml:"apis"`
	} `yaml:"api_tests"`
}

type APITest struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Method  string `json:"method"`
	Headers map[string]string
}

type Identifier struct {
	Href  string `json:"href"`
	Value string `json:"value,omitempty"`
}

type Links struct {
	Doc  Identifier `json:"doc"`
	Self Identifier `json:"self"`
}

// Response from the /mgmt/status/{domain}/TCPSummary endpoint of the DataPower
// REST Management Interface.
type TCPSummaryResponse struct {
	Links      Links `json:"_links"`
	TCPSummary struct {
		Established uint64 `json:"established"`
		SynSent     uint64 `json:"syn_sent"`
		SynReceived uint64 `json:"syn_received"`
		FinWait1    uint64 `json:"fin_wait_1"`
		FinWait2    uint64 `json:"fin_wait_2"`
		TimeWait    uint64 `json:"time_wait"`
		Closed      uint64 `json:"closed"`
		CloseWait   uint64 `json:"close_wait"`
		LastAck     uint64 `json:"last_ack"`
		Listen      uint64 `json:"listen"`
		Closing     uint64 `json:"closing"`
	}
}

// Response from the /mgmt/status/{domain}/LogTargetStatus endpoint of the
// DataPower REST Management Interface.
type LogTargetStatusResponse struct {
	Links           Links `json:"_links"`
	LogTargetStatus []struct {
		LogTarget            Identifier
		Status               string
		EventsProcessed      uint64
		EventsDropped        uint64
		EventsPending        uint64
		ErrorInfo            string
		RequestedMemory      uint64
		EventsPendingHighest uint64
	}
}

// Response from the /mgmt/status/{domain}/FirmwareVersion3 endpoint of the
// DataPower REST Management Interface.
type FirmwareVersion3Response struct {
	Links            Links `json:"_links"`
	FirmwareVersion3 struct {
		Serial         string
		Version        string
		Build          string
		BuildDate      string
		DeliveryType   string
		WatchdogBuild  string
		InstalledDPOS  string
		RunningDPOS    string
		XMLAccelerator string
		MachineType    string
		ModelType      string
	}
}

// Response from the /mgmt/status/{domain}/GatewayPeeringStatus endpoint of the
// DataPower REST Management Interface.
type GatewayPeeringStatusResponse struct {
	Links                Links `json:"_links"`
	GatewayPeeringStatus []struct {
		Address           string
		Name              string
		PendingUpdates    uint64
		ReplicationOffset uint64
		LinkStatus        string
		Primary           string
		ServicePort       uint64
		MonitorPort       uint64
		Priority          uint64
	}
}

// Response from the /mgmt/status/{domain}/APIDocumentCachingSummary endpoint
// of the DataPower REST Management Interface.
type APIDocumentCachingSummaryResponse struct {
	Links                     Links `json:"_links"`
	APIDocumentCachingSummary struct {
		APIGateway   Identifier
		CacheCount   uint64
		DocCount     uint64
		CacheSizeKiB uint64
		KiByteCount  uint64
		ExpiredCount uint64
	}
}

// Response from the /mgmt/status/{domain}/AnalyticsEndpointStatus2 endpoint of
// the DataPower REST Management Interface.
type AnalyticsEndpointStatus2Response struct {
	Links                    Links `json:"_links"`
	AnalyticsEndpointStatus2 struct {
		AnalyticsEndpoint Identifier
		Start             string
		APIGateway        string
		Success           uint64
		Drop              uint64
		Pending           uint64
	}
}

// Response from the /mgmt/status/apiconnect/OpenTelemetryExporterStatus endpoint
// of the DataPower REST Management Interface.
type OpenTelemetryExporterStatusResponse struct {
	Links                       Links `json:"_links"`
	OpenTelemetryExporterStatus []struct {
		Exporter     Identifier
		SuccessSpans uint64
		FailedSpans  uint64
		DroppedSpans uint64
	}
}

// Response from the /mgmt/config/apiconnect/APIConnectGatewayService endpoint
// of the DataPower REST Management Interface.
type APIConnectGatewayServiceResponse struct {
	Links                    Links `json:"_links"`
	APIConnectGatewayService struct {
		UserDefinedPolicies []Identifier
	}
}

var log = alog.UseChannel("dp")

func (d *DataPower) registerMetrics() {
	d.metrics = make(map[string]*prometheus.GaugeVec)

	// Version
	d.metrics["version"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_version_info"}, []string{"pod", "namespace", "version", "build"})

	// TCP Summary
	d.metrics["tcp_established_total"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_tcp_established_total"}, []string{"pod", "namespace"})
	d.metrics["tcp_syn_sent_total"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_tcp_syn_sent_total"}, []string{"pod", "namespace"})
	d.metrics["tcp_syn_received_total"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_tcp_syn_received_total"}, []string{"pod", "namespace"})
	d.metrics["tcp_fin_wait_1_total"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_tcp_fin_wait_1_total"}, []string{"pod", "namespace"})
	d.metrics["tcp_fin_wait_2_total"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_tcp_fin_wait_2_total"}, []string{"pod", "namespace"})
	d.metrics["tcp_time_wait_total"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_tcp_time_wait_total"}, []string{"pod", "namespace"})
	d.metrics["tcp_closed_total"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_tcp_closed_total"}, []string{"pod", "namespace"})
	d.metrics["tcp_close_wait_total"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_tcp_close_wait_total"}, []string{"pod", "namespace"})
	d.metrics["tcp_last_ack_total"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_tcp_last_ack_total"}, []string{"pod", "namespace"})
	d.metrics["tcp_listen_total"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_tcp_listen_total"}, []string{"pod", "namespace"})
	d.metrics["tcp_closing_total"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_tcp_closing_total"}, []string{"pod", "namespace"})

	// Log Targets
	d.metrics["logtarget_status_up"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_logtarget_status_up"}, []string{"pod", "namespace", "logtarget"})
	d.metrics["logtarget_processed"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_logtarget_events_processed"}, []string{"pod", "namespace", "logtarget"})
	d.metrics["logtarget_dropped"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_logtarget_events_dropped"}, []string{"pod", "namespace", "logtarget"})
	d.metrics["logtarget_pending"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_logtarget_events_pending"}, []string{"pod", "namespace", "logtarget"})
	d.metrics["logtarget_highest"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_logtarget_events_highest_pending"}, []string{"pod", "namespace", "logtarget"})
	d.metrics["logtarget_memory"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_logtarget_requested_memory"}, []string{"pod", "namespace", "logtarget"})

	// Analytics Endpoint
	d.metrics["analytics_success"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_analytics_events_success"}, []string{"pod", "namespace"})
	d.metrics["analytics_drop"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_analytics_events_dropped"}, []string{"pod", "namespace"})
	d.metrics["analytics_pending"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_analytics_events_pending"}, []string{"pod", "namespace"})

	// Document Cache
	d.metrics["documentcache_document_total"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_documentcache_document_total"}, []string{"pod", "namespace"})
	d.metrics["documentcache_expired_total"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_documentcache_expired_total"}, []string{"pod", "namespace"})
	d.metrics["documentcache_size"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_documentcache_size"}, []string{"pod", "namespace"})

	// Gateway Peering
	d.metrics["gateway_peering_primary_info"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_gateway_peering_primary_info"}, []string{"pod", "namespace", "peering_group"})
	d.metrics["gateway_peering_primary_link"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_gateway_peering_primary_link"}, []string{"pod", "namespace", "peering_group"})
	d.metrics["gateway_peering_primary_offset"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_gateway_peering_primary_offset"}, []string{"pod", "namespace", "peering_group"})
	d.metrics["gateway_peering_group_members"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_gateway_peering_group_members"}, []string{"pod", "namespace", "peering_group"})

	// Otel Exporter Status
	d.metrics["otel_exporter_success"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_gateway_otel_exporter_success"}, []string{"pod", "namespace", "exporter"})
	d.metrics["otel_exporter_failed"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_gateway_otel_exporter_failed"}, []string{"pod", "namespace", "exporter"})
	d.metrics["otel_exporter_dropped"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_gateway_otel_exporter_dropped"}, []string{"pod", "namespace", "exporter"})

	// User defined policies Status
	d.metrics["user_defined_policies_info"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_user_defined_policies_info"}, []string{"pod", "namespace", "policy", "version"})

	// Invoke API Tests
	d.metrics["invoke_api_size"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_invoke_api_size", Help: "invoke response content length"}, []string{"pod", "namespace", "name"})
	d.metrics["invoke_api_time"] = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "datapower_invoke_api_time", Help: "invoke time taken in ms"}, []string{"pod", "namespace", "name"})

	d.invokeCounter = promauto.NewCounterVec(prometheus.CounterOpts{Name: "datapower_invoke_api_status_total"}, []string{"pod", "namespace", "name", "code"})
}

func (d *DataPower) findGW(dynamicClient dynamic.DynamicClient) error {
	config, err := nets.GetKubeConfig()
	if err != nil {
		log.Log(alog.ERROR, "Failed to get config: %v", err)
		return err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Log(alog.ERROR, "Failed to create client set: %v", err)
		return err
	}

	// List all pods from datapower CRDs that are running - we can't get status from them if they're not
	listOptions := v1.ListOptions{
		LabelSelector: "crd.apiconnect.ibm.com/kind=datapower",
		FieldSelector: "status.phase=Running"}

	log.Log(alog.INFO, "Looking in namespace : %v", d.Config.Namespace)
	pods, err := clientset.CoreV1().Pods(d.Config.Namespace).List(context.Background(), listOptions)
	if err != nil {
		log.Log(alog.ERROR, "Failed to list pods: %v", err)
		return err
	}

	for _, pod := range pods.Items {
		log.Log(alog.TRACE, "pod name: %v", pod.Name)
		var V5Compatible bool
		//Check for APICONNECT_V5_COMPAT_MODE set to on
		for _, env := range pod.Spec.Containers[0].Env {
			if env.Name == "APICONNECT_V5_COMPAT_MODE" && env.Value == "on" {
				log.Log(alog.DEBUG, "Running in v5 compatibility mode")
				V5Compatible = true
			}
		}
		ip := pod.Status.PodIP
		if d.Config.Host != "" {
			log.Log(alog.TRACE, "Overriding host from %s to %s", ip, d.Config.Host)
			ip = d.Config.Host
		}
		d.firmwareVersion(ip, pod.Name, pod.Namespace)
		d.logTargetStatus(ip, pod.Name, pod.Namespace)
		d.tcpSummary(ip, pod.Name, pod.Namespace)
		d.analyticsStatus(ip, pod.Name, pod.Namespace)
		d.gatewayPeeringStatus(ip, pod.Name, pod.Namespace)
		d.openTelemetryExporterStatus(ip, pod.Name, pod.Namespace)
		d.apiConnectGatewayServiceStatus(ip, pod.Name, pod.Namespace)
		// Still to do:
		//  - Object Counts
		if V5Compatible {
			//  - [v5c] WSMAgentStatus
			//  - [v5c] Cache Summary
			log.Log(alog.DEBUG, "v5c - Cache and wsm status not yet supported")
		} else {
			d.documentCacheSummaryAPIGW(ip, pod.Name, pod.Namespace)
		}

		if d.Config.APITests.Enabled {
			d.doAPITests(ip, pod.Name, pod.Namespace)
		}
	}
	return nil
}

func (d *DataPower) doAPITests(ip string, pod string, namespace string) {
	client := &http.Client{
		Timeout: time.Second * time.Duration(d.Config.APITests.TimeOut),
	}

	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // #nosec G402 -- Only Insecure TLS allowed for in-cluster communications
		},
	}

	for _, apitest := range d.Config.APITests.APIs {

		url := fmt.Sprintf("https://%s:9443/%s", ip, apitest.Path)
		log.Log(alog.DEBUG, "Calling %s", url)

		req, err := http.NewRequest(apitest.Method, url, nil)
		if err != nil {
			log.Log(alog.ERROR, err.Error())
			return
		}

		startTime := time.Now()

		response, err := client.Do(req)
		duration := time.Since(startTime)
		if err != nil {
			log.Log(alog.ERROR, err.Error())
			return
		}

		d.metrics["invoke_api_time"].WithLabelValues(pod, namespace, apitest.Name).Set(float64(duration.Milliseconds()))
		d.metrics["invoke_api_size"].WithLabelValues(pod, namespace, apitest.Name).Set(float64(response.ContentLength))

		d.invokeCounter.WithLabelValues(pod, namespace, apitest.Name, fmt.Sprint(response.StatusCode)).Inc()

		err = response.Body.Close()
		if err != nil {
			log.Log(alog.ERROR, err.Error())
		}
	}

}

// *DataPower.tcpSummary makes a request to the TCPSummary endpoint and stores
// the resulting values to their matching *prometheus.GaugeVec items in the
// *DataPower.metrics map.
func (d *DataPower) tcpSummary(ip string, podName string, podNamespace string) {
	log.Log(alog.TRACE, "Entering tcpSummary(%s, %s, %s)", ip, podName, podNamespace)
	response, err := d.invokeRestMgmt(ip, "mgmt/status/apiconnect/TCPSummary")
	if err != nil {
		log.Log(alog.ERROR, err.Error())
		return
	}

	var tcp TCPSummaryResponse
	err = json.NewDecoder(response.Body).Decode(&tcp)
	if err != nil {
		log.Log(alog.ERROR, err.Error())
	}
	err2 := response.Body.Close()
	if err2 != nil {
		log.Log(alog.ERROR, err2.Error())
	}
	if err != nil || err2 != nil {
		return
	}

	d.metrics["tcp_established_total"].WithLabelValues(podName, podNamespace).Set(float64(tcp.TCPSummary.Established))
	d.metrics["tcp_syn_sent_total"].WithLabelValues(podName, podNamespace).Set(float64(tcp.TCPSummary.SynSent))
	d.metrics["tcp_syn_received_total"].WithLabelValues(podName, podNamespace).Set(float64(tcp.TCPSummary.SynReceived))
	d.metrics["tcp_fin_wait_1_total"].WithLabelValues(podName, podNamespace).Set(float64(tcp.TCPSummary.FinWait1))
	d.metrics["tcp_fin_wait_2_total"].WithLabelValues(podName, podNamespace).Set(float64(tcp.TCPSummary.FinWait2))
	d.metrics["tcp_time_wait_total"].WithLabelValues(podName, podNamespace).Set(float64(tcp.TCPSummary.TimeWait))
	d.metrics["tcp_closed_total"].WithLabelValues(podName, podNamespace).Set(float64(tcp.TCPSummary.Closed))
	d.metrics["tcp_close_wait_total"].WithLabelValues(podName, podNamespace).Set(float64(tcp.TCPSummary.CloseWait))
	d.metrics["tcp_last_ack_total"].WithLabelValues(podName, podNamespace).Set(float64(tcp.TCPSummary.LastAck))
	d.metrics["tcp_listen_total"].WithLabelValues(podName, podNamespace).Set(float64(tcp.TCPSummary.Listen))
	d.metrics["tcp_closing_total"].WithLabelValues(podName, podNamespace).Set(float64(tcp.TCPSummary.Closing))
}

// *DataPower.firmwareVersion makes a request to the FirmwareVersion3 endpoint
// and stores the resulting values to their matching *prometheus.GaugeVec items
// in the *DataPower.metrics map.
func (d *DataPower) firmwareVersion(ip string, podName string, podNamespace string) {
	log.Log(alog.TRACE, "Entering firmwareVersion(%s, %s, %s)", ip, podName, podNamespace)
	response, err := d.invokeRestMgmt(ip, "mgmt/status/apiconnect/FirmwareVersion3")
	if err != nil {
		log.Log(alog.ERROR, err.Error())
		return
	}

	var fw FirmwareVersion3Response
	err = json.NewDecoder(response.Body).Decode(&fw)
	if err != nil {
		log.Log(alog.ERROR, err.Error())
	}
	err2 := response.Body.Close()
	if err2 != nil {
		log.Log(alog.ERROR, err2.Error())
	}
	if err != nil || err2 != nil {
		return
	}

	d.metrics["version"].WithLabelValues(podName, podNamespace, fw.FirmwareVersion3.Version, fw.FirmwareVersion3.Build).Set(1.0)
}

// *DataPower.logTargetStatus makes a request to the LogTargetStatus endpoint
// and stores the resulting values to their matching *prometheus.GaugeVec items
// in the *DataPower.metrics map.
func (d *DataPower) logTargetStatus(ip string, podName string, podNamespace string) {
	log.Log(alog.TRACE, "Entering logTargetStatus(%s, %s, %s)", ip, podName, podNamespace)
	response, err := d.invokeRestMgmt(ip, "mgmt/status/apiconnect/LogTargetStatus")
	if err != nil {
		log.Log(alog.ERROR, err.Error())
		return
	}

	var logs LogTargetStatusResponse
	err = json.NewDecoder(response.Body).Decode(&logs)
	if err != nil {
		log.Log(alog.ERROR, err.Error())
	}
	err2 := response.Body.Close()
	if err2 != nil {
		log.Log(alog.ERROR, err2.Error())
	}
	if err != nil || err2 != nil {
		return
	}

	for _, target := range logs.LogTargetStatus {
		var active float64
		if target.Status == "active" {
			active = 1
		}
		d.metrics["logtarget_status_up"].WithLabelValues(podName, podNamespace, target.LogTarget.Value).Set(active)
		d.metrics["logtarget_processed"].WithLabelValues(podName, podNamespace, target.LogTarget.Value).Set(float64(target.EventsProcessed))
		d.metrics["logtarget_dropped"].WithLabelValues(podName, podNamespace, target.LogTarget.Value).Set(float64(target.EventsDropped))
		d.metrics["logtarget_pending"].WithLabelValues(podName, podNamespace, target.LogTarget.Value).Set(float64(target.EventsPending))
		d.metrics["logtarget_memory"].WithLabelValues(podName, podNamespace, target.LogTarget.Value).Set(float64(target.RequestedMemory))
		d.metrics["logtarget_highest"].WithLabelValues(podName, podNamespace, target.LogTarget.Value).Set(float64(target.EventsPendingHighest))
	}
}

// *DataPower.analyticsStatus makes a request to the AnalyticsEndpointStatus2
// endpoint and stores the resulting values to their matching
// *prometheus.GaugeVec items in the *DataPower.metrics map.
func (d *DataPower) analyticsStatus(ip string, podName string, podNamespace string) {
	log.Log(alog.TRACE, "Entering analyticsStatus(%s, %s, %s)", ip, podName, podNamespace)
	response, err := d.invokeRestMgmt(ip, "mgmt/status/apiconnect/AnalyticsEndpointStatus2")
	if err != nil {
		log.Log(alog.ERROR, err.Error())
		return
	}

	var analyticsStatus AnalyticsEndpointStatus2Response
	err = json.NewDecoder(response.Body).Decode(&analyticsStatus)
	if err != nil {
		log.Log(alog.ERROR, err.Error())
	}
	err2 := response.Body.Close()
	if err2 != nil {
		log.Log(alog.ERROR, err2.Error())
	}
	if err != nil || err2 != nil {
		return
	}
	d.metrics["analytics_success"].WithLabelValues(podName, podNamespace).Set(float64(analyticsStatus.AnalyticsEndpointStatus2.Success))
	d.metrics["analytics_drop"].WithLabelValues(podName, podNamespace).Set(float64(analyticsStatus.AnalyticsEndpointStatus2.Drop))
	d.metrics["analytics_pending"].WithLabelValues(podName, podNamespace).Set(float64(analyticsStatus.AnalyticsEndpointStatus2.Pending))
}

// *DataPower.documentCacheSummary makes a request to the
// APIDocumentCachingSummary endpoint and stores the resulting values to their
// matching *prometheus.GaugeVec items in the *DataPower.metrics map.
func (d *DataPower) documentCacheSummaryAPIGW(ip string, podName string, podNamespace string) {
	log.Log(alog.TRACE, "Entering documentCacheSummaryAPIGW(%s,%s, %s)", ip, podName, podNamespace)
	response, err := d.invokeRestMgmt(ip, "mgmt/status/apiconnect/APIDocumentCachingSummary")
	if err != nil {
		log.Log(alog.ERROR, err.Error())
		return
	}

	var documentCache APIDocumentCachingSummaryResponse
	err = json.NewDecoder(response.Body).Decode(&documentCache)
	if err != nil {
		log.Log(alog.ERROR, err.Error())
	}
	err2 := response.Body.Close()
	if err2 != nil {
		log.Log(alog.ERROR, err2.Error())
	}
	if err != nil || err2 != nil {
		return
	}

	d.metrics["documentcache_document_total"].WithLabelValues(podName, podNamespace).Set(float64(documentCache.APIDocumentCachingSummary.DocCount))
	d.metrics["documentcache_expired_total"].WithLabelValues(podName, podNamespace).Set(float64(documentCache.APIDocumentCachingSummary.ExpiredCount))
	d.metrics["documentcache_size"].WithLabelValues(podName, podNamespace).Set(float64(documentCache.APIDocumentCachingSummary.CacheSizeKiB))
}

// *DataPower.gatewayPeeringStatus makes a request to the GatewayPeeringStatus
// endpoint and stores the resulting values to their matching
// *prometheus.GaugeVec items in the *DataPower.metrics map.
func (d *DataPower) gatewayPeeringStatus(ip string, podName string, podNamespace string) {
	log.Log(alog.TRACE, "Entering gatewayPeeringStatus(%s, %s, %s)", ip, podName, podNamespace)
	response, err := d.invokeRestMgmt(ip, "mgmt/status/apiconnect/GatewayPeeringStatus")
	if err != nil {
		log.Log(alog.ERROR, err.Error())
		return
	}

	var peeringStatus GatewayPeeringStatusResponse
	err = json.NewDecoder(response.Body).Decode(&peeringStatus)
	if err != nil {
		log.Log(alog.ERROR, err.Error())
	}
	err2 := response.Body.Close()
	if err2 != nil {
		log.Log(alog.ERROR, err2.Error())
	}
	if err != nil || err2 != nil {
		return
	}
	var peeringGroupCounts = make(map[string]int)

	for _, entry := range peeringStatus.GatewayPeeringStatus {
		peeringGroupCounts[entry.Name]++
		if ip == entry.Address {
			var primary float64
			var link float64
			if entry.Primary == "yes" {
				primary = 1
			}
			if entry.LinkStatus == "ok" {
				link = 1
			}
			d.metrics["gateway_peering_primary_info"].WithLabelValues(
				podName,
				podNamespace,
				entry.Name,
			).Set(primary)
			d.metrics["gateway_peering_primary_link"].WithLabelValues(
				podName,
				podNamespace,
				entry.Name,
			).Set(link)
			d.metrics["gateway_peering_primary_offset"].WithLabelValues(
				podName,
				podNamespace,
				entry.Name,
			).Set(float64(entry.ReplicationOffset))
		}
	}
	for key, value := range peeringGroupCounts {
		d.metrics["gateway_peering_group_members"].WithLabelValues(
			podName,
			podNamespace,
			key,
		).Set(float64(value))
	}
}

// *DataPower.openTelemetryExporterStatus makes a request to the OpenTelemetryExporterStatus endpoint
// and stores the resulting values to their matching *prometheus.GaugeVec items
// in the *DataPower.metrics map.
func (d *DataPower) openTelemetryExporterStatus(ip string, podName string, podNamespace string) {
	log.Log(alog.TRACE, "Entering openTelemetryExporterStatus(%s, %s, %s)", ip, podName, podNamespace)
	response, err := d.invokeRestMgmt(ip, "mgmt/status/apiconnect/OpenTelemetryExporterStatus")
	if err != nil {
		log.Log(alog.ERROR, err.Error())
		return
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Log(alog.ERROR, err.Error())
		return
	}

	defer response.Body.Close()

	var otelExporterStatusRes OpenTelemetryExporterStatusResponse
	err = json.Unmarshal(body, &otelExporterStatusRes)
	if err != nil {
		// If there is only one exporter object, the response is coming as an object.
		// So we try unmarshalling it as a single object and append to the slice
		var tempResponse struct {
			Links                       Links `json:"_links"`
			OpenTelemetryExporterStatus struct {
				Exporter     Identifier
				SuccessSpans uint64
				FailedSpans  uint64
				DroppedSpans uint64
			}
		}

		err := json.Unmarshal(body, &tempResponse)
		if err != nil {
			log.Log(alog.ERROR, err.Error())
			return
		}

		otelExporterStatusRes.Links = tempResponse.Links
		otelExporterStatusRes.OpenTelemetryExporterStatus = append(otelExporterStatusRes.OpenTelemetryExporterStatus, tempResponse.OpenTelemetryExporterStatus)
	}

	for _, target := range otelExporterStatusRes.OpenTelemetryExporterStatus {
		d.metrics["otel_exporter_success"].WithLabelValues(podName, podNamespace, target.Exporter.Value).Set(float64(target.SuccessSpans))
		d.metrics["otel_exporter_failed"].WithLabelValues(podName, podNamespace, target.Exporter.Value).Set(float64(target.FailedSpans))
		d.metrics["otel_exporter_dropped"].WithLabelValues(podName, podNamespace, target.Exporter.Value).Set(float64(target.DroppedSpans))
	}
}

// *DataPower.apiConnectGatewayServiceStatus makes a request to the APIConnectGatewayService endpoint
// and stores the resulting values to their matching *prometheus.GaugeVec items
// in the *DataPower.metrics map.
func (d *DataPower) apiConnectGatewayServiceStatus(ip string, podName string, podNamespace string) {
	log.Log(alog.TRACE, "Entering apiConnectGatewayServiceStatus(%s, %s, %s)", ip, podName, podNamespace)
	response, err := d.invokeRestMgmt(ip, "mgmt/config/apiconnect/APIConnectGatewayService")
	if err != nil {
		log.Log(alog.ERROR, err.Error())
		return
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Log(alog.ERROR, err.Error())
		return
	}

	defer response.Body.Close()

	var apiConnectGatewayService APIConnectGatewayServiceResponse
	err = json.Unmarshal(body, &apiConnectGatewayService)

	if err != nil {
		log.Log(alog.ERROR, err.Error())
		return
	}

	for _, target := range apiConnectGatewayService.APIConnectGatewayService.UserDefinedPolicies {
		fullPolicyName := target.Value
		re := regexp.MustCompile(`(\d+\.\d+\.\d+)`)
		version := re.FindString(fullPolicyName)
		policyNameWithoutVersion := strings.Replace(fullPolicyName, version, "", 1)
		policyNameWithoutVersion = strings.TrimRight(policyNameWithoutVersion, "_")
		d.metrics["user_defined_policies_info"].WithLabelValues(podName, podNamespace, policyNameWithoutVersion, version).Set(1)
	}
}

func (d *DataPower) invokeRestMgmt(ip string, path string) (*http.Response, error) {
	log.Log(alog.TRACE, "Entering invokeRestMgmt(%s,%s)", ip, path)
	secretPath := os.Getenv(("DP_CREDS"))
	username := ""
	// If username in config use this
	if d.Config.Username != "" {
		username = d.Config.Username
	}
	if username == "" {
		user_byte, err := os.ReadFile(filepath.Clean(secretPath + "/username"))
		if err != nil {
			log.Log(alog.ERROR, err.Error())
		} else {
			username = string(user_byte)
		}
	}
	password, err := os.ReadFile(filepath.Clean(secretPath + "/password"))
	if err != nil {
		log.Log(alog.ERROR, err.Error())
	}
	log.Log(alog.DEBUG, "Using username %s from %s", username, secretPath)
	client := &http.Client{
		Timeout: time.Second * time.Duration(d.Config.TimeOut),
	}

	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // #nosec G402 -- Only Insecure TLS allowed for in-cluster communications
		},
	}

	url := fmt.Sprintf("https://%s:5554/%s", ip, path)
	log.Log(alog.DEBUG, "Calling %s", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Log(alog.ERROR, err.Error())
		return nil, err
	}

	req.SetBasicAuth(string(username), string(password))

	response, err := client.Do(req)
	if err != nil {
		log.Log(alog.ERROR, err.Error())
		return nil, err
	}
	if response.StatusCode != 200 {
		//return nil, errors.New(fmt.Sprintf("Unexpected status - Got %s, expected 200", response.Status))
		log.Log(alog.ERROR, "Error invoking rest management with status %s", response.Status)
		return nil, errors.New(response.Status)
	}
	return response, nil
}

func (m *DataPower) BackgroundFishing() {
	m.registerMetrics()
	interval := m.Frequency
	ticker := time.NewTicker(interval)
	// Start the datapower loop
	for range ticker.C {
		if !m.Disabled {
			log.Log(alog.DEBUG, "Fishing for datapower")
			m.Fish()
		}
	}
}

func (d *DataPower) Fish() {
	dynamicClient := nets.GetDynamicKubeClient()

	err := d.findGW(*dynamicClient)
	if err != nil {
		log.Log(alog.FATAL, "disabled manager net")
		d.Disabled = true
	}
}
