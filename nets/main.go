package nets

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/IBM/alchemy-logging/src/go/alog"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type Token struct {
	Token   string `json:"token"`
	Expires int    `json:"expires"`
}

type Client struct {
	Clientset kubernetes.Interface
}

type BaseNet struct {
	Name      string
	Disabled  bool
	Frequency time.Duration
}

func (b *BaseNet) String() string {
	return fmt.Sprintf("Base Net Name: %s || Base Net Disabled:  %t || Base net frequency: %d", b.Name, b.Disabled, b.Frequency)
}

type NetInterface interface {
	Fish()
}

type Netty struct {
	BaseNet
	NetInterface
}

var log = alog.UseChannel("nets")
var dynamicClient *dynamic.DynamicClient

func Enable(n BaseNet, frequency int) {
	log.Log(alog.INFO, "Enabling Base Net", n.String())

	net_frequency := time.Duration(5)
	if frequency != 0 {
		log.Log(alog.INFO, "net is enabled at %ds frequency", frequency)
		net_frequency = time.Duration(frequency)
	}
	n.Frequency = net_frequency * time.Second
	//n.BackgroundFishing()
}

func GetKubeConfig() (*rest.Config, error) {
	// Try and get the inClusterConfig first
	config, err := rest.InClusterConfig()
	if err != nil {
		// Failed to get inCluster config
		log.Log(alog.INFO, err.Error())
		// Attempt to get kubeconfig
		userHomeDir, err := os.UserHomeDir()
		if err != nil {
			log.Log(alog.FATAL, "error getting user home dir: %v\n", err)
			os.Exit(1)
		}
		kubeConfigPath := filepath.Join(userHomeDir, ".kube", "config")
		log.Log(alog.DEBUG, "Using kubeconfig: %s", kubeConfigPath)

		config, err = clientcmd.BuildConfigFromFlags("", kubeConfigPath)
		if err != nil {
			log.Log(alog.FATAL, "error getting Kubernetes config: %v", err)
			os.Exit(1)
		}
	}
	return config, nil
}
func GetDynamicKubeClient() *dynamic.DynamicClient {
	if dynamicClient != nil {
		return dynamicClient
	}
	config, _ := GetKubeConfig()
	var err error
	dynamicClient, err = dynamic.NewForConfig(config)
	if err != nil {
		log.Log(alog.FATAL, "error creating dynamic client: %v", err)
		os.Exit(1)
	}
	return dynamicClient
}

func InvokeAPI(url string, certPath string, token string) (*http.Response, error) {

	client := &http.Client{}

	if certPath != "" {
		// Create a HTTPS client and supply the certificates
		caCertPool := x509.NewCertPool()
		caCert, _ := os.ReadFile(filepath.Clean(certPath + "/ca.crt"))
		caCertPool.AppendCertsFromPEM(caCert)
		cert, err := tls.LoadX509KeyPair(
			fmt.Sprintf("%s/tls.crt", certPath),
			fmt.Sprintf("%s/tls.key", certPath),
		)
		if err != nil {
			log.Log(alog.ERROR, err.Error())
		}
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            caCertPool,
				Certificates:       []tls.Certificate{cert},
				InsecureSkipVerify: true, // #nosec G402 -- Only Insecure TLS allowed for in-cluster communications
				MinVersion:         tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				},
				PreferServerCipherSuites: true,
			},
		}
	} else {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // #nosec G402 -- Only Insecure TLS allowed for in-cluster communications
				MinVersion:         tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				},
				PreferServerCipherSuites: true,
			},
		}
	}

	if !strings.HasPrefix(url, "http") {
		url = fmt.Sprintf("https://%s", url)
	}
	log.Log(alog.DEBUG, "Calling %s", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Log(alog.ERROR, err.Error())
		return nil, err
	}
	req.Header.Add("Accept", "application/json")

	if token != "" {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	}
	response, err := client.Do(req)
	if err != nil {
		log.Log(alog.ERROR, err.Error())
		return nil, err
	}
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status - got %s, expected 200", response.Status)
	}

	return response, nil

}

func GetCustomResourceList(group, version, resource, namespace string) *unstructured.UnstructuredList {
	dynamicClient := GetDynamicKubeClient()
	gvr := schema.GroupVersionResource{
		Group:    group,
		Version:  version,
		Resource: resource,
	}

	items, err := dynamicClient.Resource(gvr).Namespace(namespace).List(context.Background(), v1.ListOptions{})
	if err != nil {
		log.Log(alog.ERROR, "Failed to find %s: %v", resource, err)
		return nil
	}
	return items
}

func GetToken(management_url string, secretPath string) (Token, error) {
	log.Log(alog.DEBUG, "Getting token using %s", secretPath)
	clientId, _ := os.ReadFile(filepath.Clean(secretPath + "/client_id"))
	clientSecret, _ := os.ReadFile(filepath.Clean(secretPath + "/client_secret"))
	apikey, _ := os.ReadFile(filepath.Clean(secretPath + "/apikey"))
	username, _ := os.ReadFile(filepath.Clean(secretPath + "/username"))
	password, _ := os.ReadFile(filepath.Clean(secretPath + "/password"))
	realm, _ := os.ReadFile(filepath.Clean(secretPath + "/realm"))
	var postBody []byte
	if (username != nil) && (password != nil) {
		log.Log(alog.DEBUG, "Using grant_type of password as username and password are set")
		postBody, _ = json.Marshal(map[string]string{
			"client_id":     string(clientId),
			"client_secret": string(clientSecret),
			"username":      string(username),
			"password":      string(password),
			"realm":         string(realm),
			"grant_type":    "password",
		})
	} else if apikey != nil {
		log.Log(alog.INFO, "Using grant_type of api_key")
		postBody, _ = json.Marshal(map[string]string{
			"client_id":     string(clientId),
			"api_key":       string(apikey),
			"client_secret": string(clientSecret),
			"grant_type":    "api_key",
		})
	} else {
		log.Log(alog.INFO, "Using grant_type of client_credentials")
		postBody, _ = json.Marshal(map[string]string{
			"client_id":     string(clientId),
			"client_secret": string(clientSecret),
			"grant_type":    "client_credentials",
		})
	}
	log.Log(alog.DEBUG, string(postBody))

	tokenRequest := bytes.NewBuffer(postBody)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // #nosec G402 -- Only Insecure TLS allowed for in-cluster communications
				MinVersion:         tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				},
				PreferServerCipherSuites: true,
			},
		},
	}

	url := fmt.Sprintf("%s/api/token", management_url)

	req, err := http.NewRequest("POST", url, tokenRequest)
	if err != nil {
		return Token{}, err
	} else {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		response, err := client.Do(req)
		if err != nil {
			log.Log(alog.ERROR, err.Error())
			return Token{}, err
		} else {
			defer response.Body.Close()
			if response.StatusCode != 200 {
				return Token{}, fmt.Errorf("unexpected status - got %s, expected 200", response.Status)
			} else {
				var bearerToken TokenResponse
				err = json.NewDecoder(response.Body).Decode(&bearerToken)
				if err != nil {
					log.Log(alog.ERROR, err.Error())
					return Token{}, err
				}

				return Token{
					Token:   bearerToken.AccessToken,
					Expires: int(time.Now().Unix()) + bearerToken.ExpiresIn}, nil
			}
		}
	}
}
