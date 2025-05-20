package certs

import (
	"context"
	x509 "crypto/x509"
	"encoding/pem"
	"nets"
	"time"

	"github.com/IBM/alchemy-logging/src/go/alog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	coreV1Types "k8s.io/client-go/kubernetes/typed/core/v1"
)

var secretsClient coreV1Types.SecretInterface

type Certs struct {
	nets.BaseNet
	Config CertsNetConfig
}

type CertsNetConfig struct {
	Enabled   bool `yaml:"enabled"`
	Frequency int  `yaml:"frequency"`
}

var certExpiry = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "cert_remaining_seconds",
		Help: "Seconds remaining before expiry of certificate"}, []string{"secret", "namespace", "cert"})

var log = alog.UseChannel("cert")

func (a *Certs) findCerts(clientset kubernetes.Clientset) error {
	coreV1Client := clientset.CoreV1()
	secrets, err := coreV1Client.Secrets("").List(context.Background(), v1.ListOptions{})
	if err != nil {
		log.Log(alog.FATAL, err.Error())
	}
	for _, secret := range secrets.Items {
		// If tls.crt exists we will process certificate data
		if _, ok := secret.Data["tls.crt"]; ok {
			block, _ := pem.Decode(secret.Data["tls.crt"])
			if block == nil {
				log.Log(alog.INFO, "Failed to decode PEM block")
				continue
			}
			tlCert, errC := x509.ParseCertificate(block.Bytes)
			if errC != nil {
				log.Log(alog.INFO, errC.Error())
				continue
			}

			log.Log(alog.DEBUG, "Certificate %s expires on %s", secret.Name, tlCert.NotAfter)
			certExpiry.With(prometheus.Labels{"secret": secret.Name, "namespace": secret.Namespace, "cert": "tls.crt"}).Set(float64(tlCert.NotAfter.Unix() - time.Now().Unix()))

			if _, ok := secret.Data["ca.crt"]; ok {
				block, _ := pem.Decode(secret.Data["ca.crt"])
				if block == nil {
					log.Log(alog.INFO, "Failed to decode PEM block")
					continue
				}
				tlCert, errC := x509.ParseCertificate(block.Bytes)
				if errC != nil {
					log.Log(alog.INFO, errC.Error())
					continue
				}

				certExpiry.With(prometheus.Labels{"secret": secret.Name, "namespace": secret.Namespace, "cert": "ca.crt"}).Set(float64(tlCert.NotAfter.Unix() - time.Now().Unix()))
			}
		}
	}
	return nil
}

func (c *Certs) Fish() {
	config, _ := nets.GetKubeConfig()
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Log(alog.FATAL, err.Error())
	}
	err = c.findCerts(*clientset)
	if err != nil {
		log.Log(alog.FATAL, "disabled certs net")
		c.Disabled = true
	}
}

func (c *Certs) BackgroundFishing() {
	interval := c.Frequency
	ticker := time.NewTicker(interval)
	for range ticker.C {
		if !c.Disabled {
			log.Log(alog.DEBUG, "Fishing for certs")
			c.Fish()
		}
	}
}
