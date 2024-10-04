package apiconnect

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

func TestInit(t *testing.T) {

	a := APIConnect{}
	a.Disabled = false

	if a.Disabled {
		t.Errorf("got %t want %t", a.Disabled, false)
	}
}

func TestRegisterMetrics(t *testing.T) {
	assert := assert.New(t)
	a := APIConnect{}
	a.registerMetrics()
	assert.IsType(prometheus.GaugeVec{}, *a.metrics["gwCrdStatus"])
	// 4 metrics registered, one for each subsystem
	assert.Equal(4, len(a.metrics))
}
