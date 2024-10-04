package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"nets"
	"nets/analytics"
	"nets/apiconnect"
	"nets/consumption"
	"nets/datapower"
	"nets/manager"
	"os"
	"time"

	"github.com/IBM/alchemy-logging/src/go/alog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

var (
	promCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "myapp_processed_ops_total",
			Help: "The total number of processed events",
		},
		[]string{"collector"})
)

var log = alog.UseChannel("trawler")

type Config struct {
	Prometheus struct {
		Port    string `yaml:"port"`
		Enabled bool   `yaml:"enabled"`
	} `yaml:"prometheus"`
	Nets struct {
		APIConnect  apiconnect.APIConnectNetConfig   `yaml:"apiconnect"`
		Analytics   analytics.AnalyticsNetConfig     `yaml:"analytics"`
		Consumption consumption.ConsumptionNetConfig `yaml:"consumption"`
		DataPower   datapower.DataPowerNetConfig     `yaml:"datapower"`
		Manager     manager.ManagerNetConfig         `yaml:"manager"`
	} `yaml:"nets"`
}

type CertReloader struct {
	CertFile          string // path to the x509 certificate for https
	KeyFile           string // path to the x509 private key matching `CertFile`
	cachedCert        *tls.Certificate
	cachedCertModTime time.Time
}

func ReadConfig() Config {
	var config Config

	config_path := os.Getenv("CONFIG_PATH")
	if config_path == "" {
		config_path = "config.yaml"
	}

	log.Log(alog.INFO, "Loading config from %s ", config_path)

	// Open YAML file
	file, err := os.Open(config_path)
	if err != nil {
		log.Log(alog.ERROR, err.Error())
	}
	defer file.Close()

	// Decode YAML file to struct
	if file != nil {
		decoder := yaml.NewDecoder(file)
		if err := decoder.Decode(&config); err != nil {
			log.Log(alog.ERROR, err.Error())

		}
	}

	return config
}

func enableNet(frequency int, newNet nets.BaseNet) {
	net_frequency := time.Duration(5)
	if frequency != 0 {
		log.Log(alog.INFO, "net is enabled at %ds frequency", frequency)
		net_frequency = time.Duration(frequency)
	}
	newNet.Frequency = net_frequency * time.Second
	//newNet.BackgroundFishing()
}

func frequency(configFrequency int) time.Duration {
	if configFrequency == 0 {
		// Default is 10 seconds
		return time.Duration(10) * time.Second
	} else {
		return time.Duration(configFrequency) * time.Second
	}
}

func main() {
	// Set up logging

	alog.Config(alog.INFO, alog.ChannelMap{
		"trawler": alog.DEBUG,
		"apim":    alog.INFO,
		"apic":    alog.INFO,
		"a7s":     alog.INFO,
		"dp":      alog.INFO,
	})
	// Read config file...
	config := ReadConfig()

	// Initialise appropriate nets...
	if config.Nets.APIConnect.Enabled {
		a := apiconnect.APIConnect{}
		a.Config = config.Nets.APIConnect
		a.Frequency = frequency(config.Nets.APIConnect.Frequency)
		log.Log(alog.INFO, "Enabled apiconnect net with %s frequency", a.Frequency)
		go a.BackgroundFishing()
	}

	// Analytics net
	if config.Nets.Analytics.Enabled {
		a7s := analytics.Analytics{}
		a7s.Config = config.Nets.Analytics
		a7s.Frequency = frequency(config.Nets.Analytics.Frequency)
		log.Log(alog.INFO, "Enabled analytics net with %s frequency", a7s.Frequency)
		go a7s.BackgroundFishing()
	}

	// Consumption health net
	if config.Nets.Consumption.Enabled {
		c := consumption.Consumption{}
		c.Config = config.Nets.Consumption
		c.Frequency = frequency(config.Nets.Consumption.Frequency)
		log.Log(alog.INFO, "Enabled consumption net with %s frequency", c.Frequency)
		c.Fish()
		go c.BackgroundFishing()
	}
	// Manager net
	if config.Nets.Manager.Enabled {
		apim := manager.Manager{}
		apim.Config = config.Nets.Manager
		apim.Frequency = frequency(config.Nets.Manager.Frequency)
		log.Log(alog.INFO, "Enabled management net with %s frequency", apim.Frequency)
		go apim.BackgroundFishing()
	}

	// DataPower net (TODO implement)
	if config.Nets.DataPower.Enabled {
		dp := datapower.DataPower{}
		dp.Config = config.Nets.DataPower
		dp.Frequency = frequency(config.Nets.DataPower.Frequency)
		log.Log(alog.INFO, "Enabled datapower net with %s frequency", dp.Frequency)
		go dp.BackgroundFishing()
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})

	listenPort := "63512"
	if config.Prometheus.Port != "" {
		listenPort = config.Prometheus.Port
	}

	_, err := ListenAndServe(mux, listenPort)
	if err != nil {
		log.Log(alog.ERROR, "Server Failed to Listen")
	}

}

func ListenAndServe(mux *http.ServeMux, listenPort string) (*http.Server, error) {
	srv := &http.Server{}
	if os.Getenv("SECURE") != "true" {
		srv := &http.Server{
			Addr:    ":" + listenPort,
			Handler: mux,
		}
		log.Log(alog.INFO, "Listening insecurely on http://0.0.0.0:%s/metrics", listenPort)
		err := srv.ListenAndServe()
		if err != nil {
			log.Log(alog.FATAL, "failed to run insecure server: %s\n", err)
			return nil, err
		}

	} else {

		srv := &http.Server{
			Addr:    ":" + listenPort,
			Handler: mux,
		}
		certPath := os.Getenv("CERT_PATH")
		certReloader := CertReloader{
			CertFile: certPath + "/tls.crt",
			KeyFile:  certPath + "/tls.key",
		}

		caFile := certPath + "/ca.crt"

		var certPool *x509.CertPool = x509.NewCertPool()
		caBytes, err := os.ReadFile(caFile)
		if err != nil {
			log.Log(alog.FATAL, "failed loading caFile: %v", err)
			return nil, err
		}
		ok := certPool.AppendCertsFromPEM(caBytes)
		if !ok {
			log.Log(alog.FATAL, "could not parse certificate file: %v", caFile)
			return nil, err
		}

		tlsConfig := tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: certReloader.GetCertificate,
			ClientAuth:     tls.RequireAndVerifyClientCert, // pragma: allowlist secret
			ClientCAs:      certPool,
			RootCAs:        certPool,
		}
		srv.TLSConfig = &tlsConfig
		log.Log(alog.INFO, "Listening securely on https://0.0.0.0:%s/metrics", listenPort)
		err = srv.ListenAndServeTLS(certReloader.CertFile, certReloader.KeyFile)
		if err != nil {
			log.Log(alog.FATAL, "failed to run secure server: %s\n", err)
			return nil, err
		}
	}
	return srv, nil
}

// Implementation for tls.Config.GetCertificate useful when using
// Kubernetes Secrets which update the filesystem at runtime.
func (cr *CertReloader) GetCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	stat, err := os.Stat(cr.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed checking key file modification time: %w", err)
	}

	if cr.cachedCert == nil || stat.ModTime().After(cr.cachedCertModTime) {
		log.Log(alog.INFO, "Re-loading certs from file as updated since cached time: %v", cr.cachedCertModTime)
		pair, err := tls.LoadX509KeyPair(cr.CertFile, cr.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed loading tls key pair: %w", err)
		}

		cr.cachedCert = &pair
		cr.cachedCertModTime = stat.ModTime()
	}

	return cr.cachedCert, nil
}