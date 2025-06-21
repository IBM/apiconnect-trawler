package consumption

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/IBM/alchemy-logging/src/go/alog"
)

type Payload struct {
	Version int      `json:"version"`
	CrnMask string   `json:"crn_mask"`
	Health  []Health `json:"health"`
	Alert   *Alert   `json:"alert"`
}

type Health struct {
	Plan          string `json:"plan"`
	Status        int    `json:"status"`
	ResponseTime  int    `json:"responseTime"`
	ServiceInput  string `json:"serviceInput"`
	ServiceOutput string `json:"serviceOutput"`
}

type Alert struct {
	Severity          int    `json:"severity"`
	CustomerImpacting string `json:"customer_impacting"`
	Console           string `json:"console"`
	DisablePager      string `json:"disable_pager"`
	ShortDescription  string `json:"short_description"`
	LongDescription   string `json:"long_description"`
	ServiceName       string `json:"serviceName"`
}
type IAMResponse struct {
	AccessToken string `json:"access_token"`
}

func getIAMToken() (string, error) {

	form := url.Values{}
	form.Set("grant_type", "urn:ibm:params:oauth:grant-type:apikey")
	apiKeyPath := os.Getenv(("IAM_APIKEY_PATH"))
	IAM_URL := os.Getenv(("IAM_URL"))
	apiKey, _ := os.ReadFile(filepath.Clean(apiKeyPath + "/edbApikey"))
	form.Set("apikey", string(apiKey))
	log.Log(alog.INFO, "Received token from IAM")

	resp, err := http.Post(
		IAM_URL+"/identity/token",
		"application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get IAM token: %s", string(body))

	}
	var iamResp IAMResponse
	if err := json.Unmarshal(body, &iamResp); err != nil {
		return "", err
	}
	log.Log(alog.INFO, "Received token from IAM")
	return iamResp.AccessToken, nil
}

func SendMetrics(isSuccess bool) error {

	status := 0
	var alert *Alert
	serviceOutput := "Lifecycle: API Call traffic detected."

	if !isSuccess {
		status = 1
		alert = &Alert{
			Severity:          2,
			CustomerImpacting: "false",
			Console:           "toc",
			DisablePager:      "false",
			ShortDescription:  "not found",
			LongDescription:   "not found",
			ServiceName:       "apiconnect",
		}
		serviceOutput = "Lifecycle: No API Call traffic detected."
	}

	payload := Payload{
		Version: 1,
		CrnMask: os.Getenv(("crn")),
		Health: []Health{
			{
				Plan:          "reserved-instance",
				Status:        status,
				ResponseTime:  12323,
				ServiceInput:  "Lifecycle: API Call traffic recorded",
				ServiceOutput: serviceOutput,
			},
		},
		Alert: alert,
	}

	token, err := getIAMToken()
	if err != nil {
		return err
	}

	jsonPayload, _ := json.Marshal(payload)
	client := &http.Client{}
	log.Log(alog.INFO, "Payload before sending to edb:", string(jsonPayload))

	// Add query parameters
	params := url.Values{}
	mapId := os.Getenv(("mapID"))
	baseURL := "https://pnp-api-oss.cloud.ibm.com/edbingestor/api/v1/edb/data"
	params.Add("mapID", mapId)
	if os.Getenv("ibmCloudEnv") == "test" {
		baseURL = "https://pnp-api-oss.test.cloud.ibm.com/edbingestor/api/v1/edb/data"
	}

	// Construct the final URL with query parameters
	finalURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())

	// Create HTTP POST request
	req, err := http.NewRequest("POST", finalURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed sending payload to EDB: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	log.Log(alog.INFO, "Response Status Code:", resp.StatusCode)
	log.Log(alog.INFO, "Successfully sent payload to EDB:", string(body))
	return nil
}
