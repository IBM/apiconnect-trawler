package manager

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/IBM/alchemy-logging/src/go/alog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var testLogger = alog.UseChannel("manager_tests")

var m Manager

// You can use testing.T, if you want to test the code without benchmarking
func setup() {
	m = Manager{}
	m.registerMetrics()
}

func TestInit(t *testing.T) {

	if len(m.metrics) == 0 {
		setup()
	}
	m.Disabled = false

	if m.Disabled {
		t.Errorf("got %t want %t", m.Disabled, false)
	}
}

func TestRegisterMetrics(t *testing.T) {
	assert := assert.New(t)
	if len(m.metrics) == 0 {
		setup()
	}
	assert.IsType(prometheus.GaugeVec{}, *m.metrics["cloudInfo"])
	assert.Equal(14, len(m.metrics))
}

func TestTopologyValues(t *testing.T) {
	assert := assert.New(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(r.URL.Path, "/api/cloud/topology")
		assert.Equal(r.Header.Get("Accept"), "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"cloud_id":"123445","cloud_name":"test-cloud","counts":{"provider_orgs":23}}`))
	}))
	defer server.Close()

	config := ManagerNetConfig{
		Host: server.URL,
	}
	m := Manager{Config: config}

	testLogger.Log(alog.DEBUG, "manager: %v", m)
	assert.Equal(server.Config.Addr, "")
	ti, err := m.getTopologyInfo(server.URL)
	testLogger.Log(alog.DEBUG, "cloud topology: %v", ti)
	assert.Nil(err)
	assert.Equal(float64(23), ti.Counts.ProviderOrgs)

}

func TestWebhookStats(t *testing.T) {
	assert := assert.New(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(r.URL.Path, "/api/catalogs/org/catalog/configured-gateway-services")
		assert.Equal(r.Header.Get("Accept"), "application/json")
		assert.Contains(r.Header.Get("Authorization"), "Bearer")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"total_results":1,"results":["name":"gateway1", "gateway_processing_status":{"service_up_to_date":true,"number_of_outstanding_sent_events":10, "number_of_outstanding_queued_events":10}]}`))
	}))
	defer server.Close()

	config := ManagerNetConfig{
		Host: server.URL,
	}
	m := Manager{Config: config}
	testLogger.Log(alog.DEBUG, "manager: %v", m)

	assert.Equal(server.Config.Addr, "")
	m.getWebhookStats(server.URL, "org", "catalog")
	assert.Empty("hllo")
	//count := testutil.CollectAndCount(m.metrics["outstandingSent"], "manager_gateway_processing_outstanding_sent_events")
	//testLogger.Log(alog.DEBUG, "collected count: %v", count)
	//assert.Equal(0, count)

}

func MockCustomResourceList(group, version, resource string) *unstructured.UnstructuredList {
	g := &unstructured.UnstructuredList{}
	g.SetUnstructuredContent(
		map[string]interface{}{
			"apiVersion": "management.apiconnect.ibm.com/v1beta1",
			"kind":       "ManagementClusterList"})
	m := unstructured.Unstructured{}
	m.SetUnstructuredContent(map[string]interface{}{
		"apiVersion": "management.apiconnect.ibm.com/v1beta1",
		"kind":       "ManagementCluster",
		"metadata": map[string]interface{}{
			"name":      "apim",
			"namespace": "default",
		},
		"spec": map[string]interface{}{
			"members": 3,
		},
		"status": map[string]interface{}{
			"versions": map[string]interface{}{
				"reconciled": "20.1.2.3",
			},
			"services": map[string]interface{}{
				"juhu": "juhu-address",
			},
		},
	})
	g.Items = append(g.Items, m)
	return g
}

func MockGetToken(url string) (string, error) {
	return "hello", nil
}

func MockInvokeAPI(url string, certPath string, token string) (*http.Response, error) {
	json := `{"access_token":"hello}`

	if strings.Contains(url, "topology") {
		json = `{"cloud_id":"123445","cloud_name":"test-cloud","counts":{"provider_orgs":23}}`
	}

	body := ioutil.NopCloser(bytes.NewReader([]byte(json)))
	r := http.Response{
		StatusCode: 200,
		Body:       body,
	}
	return &r, nil
}

func TestFindAPIM(t *testing.T) {
	assert := assert.New(t)
	if len(m.metrics) == 0 {
		setup()
	}

	crlList = MockCustomResourceList
	invokeAPI = MockInvokeAPI
	getToken = MockGetToken
	err := m.findAPIM()
	if err != nil {
		t.Error("expected error to be nil but got %v", err)
	}
	assert.Empty(err)

	assert.Empty("full")
	//assert.Equal("hello", m.token)
	//assert.Contains(err.Error(), "juhu-address")
	assert.True((true))
	// Expect to see counts but not webhook status
	assert.Equal(1, testutil.CollectAndCount(m.metrics["porgGauge"], "manager_provider_orgs_total"))
	assert.Equal(0, testutil.CollectAndCount(m.metrics["outstandingSent"], "manager_gateway_processing_outstanding_queued_events"))

	m.Config.ProcessOrgMetrics = true

	m.findAPIM()
	// Expect to see both counts and webhook status
	assert.Equal(1, testutil.CollectAndCount(m.metrics["porgGauge"], "manager_provider_orgs_total"))
	assert.Equal(1, testutil.CollectAndCount(m.metrics["outstandingSent"], "manager_gateway_processing_outstanding_queued_events"))

}
