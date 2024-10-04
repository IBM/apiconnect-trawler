package nets

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
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

type Client struct {
	Clientset kubernetes.Interface
}

type BaseNet struct {
	Name      string
	Disabled  bool
	Frequency time.Duration
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
	fmt.Println(n)
	fmt.Println(frequency)
	log.Log(alog.INFO, "enabling %s", n.Name)
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
		caCert, _ := os.ReadFile(certPath + "/ca.crt")
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
				InsecureSkipVerify: true,
			},
		}
	} else {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}

	if !strings.HasPrefix(url, "http") {
		url = fmt.Sprintf("https://%s", url)
	}
	log.Log(alog.DEBUG, "Calling %s", url)

	req, _ := http.NewRequest("GET", url, nil)
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
		return nil, errors.New(fmt.Sprintf("Unexpected status - Got %s, expected 200", response.Status))
	}

	return response, nil

}

func GetCustomResourceList(group, version, resource string) *unstructured.UnstructuredList {
	dynamicClient := GetDynamicKubeClient()
	gvr := schema.GroupVersionResource{
		Group:    group,
		Version:  version,
		Resource: resource,
	}

	items, err := dynamicClient.Resource(gvr).List(context.Background(), v1.ListOptions{})
	if err != nil {
		log.Log(alog.ERROR, "Failed to find %s: %v", resource, err)
		return nil
	}
	return items
}

func GetToken(management_url string) (string, error) {
	return getNewToken(management_url)
}

func getNewToken(management_url string) (string, error) {
	secretPath := os.Getenv(("MGMT_CREDS"))
	clientId, _ := ioutil.ReadFile(secretPath + "/client_id")
	clientSecret, _ := ioutil.ReadFile(secretPath + "/client_secret")

	postBody, _ := json.Marshal(map[string]string{
		"client_id":     string(clientId),
		"client_secret": string(clientSecret),
		"grant_type":    "client_credentials",
	})
	tokenRequest := bytes.NewBuffer(postBody)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	url := fmt.Sprintf("%s/api/token", management_url)

	req, err := http.NewRequest("POST", url, tokenRequest)
	if err != nil {
		return "", err
	} else {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		response, err := client.Do(req)
		if err != nil {
			return "", err
		} else {
			defer response.Body.Close()
			if err != nil {
				log.Log(alog.ERROR, err.Error())
				return "", err
			}
			var bearerToken TokenResponse
			err = json.NewDecoder(response.Body).Decode(&bearerToken)
			if err != nil {
				log.Log(alog.ERROR, err.Error())
				return "", err
			}
			return bearerToken.AccessToken, nil
		}
	}
}
