package nets

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/IBM/alchemy-logging/src/go/alog"
	"github.com/stretchr/testify/assert"
)

var testLogger = alog.UseChannel("main_tests")

func TestGetToken(t *testing.T) {
	assert := assert.New(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(r.URL.Path, "/api/token")
		assert.Equal(r.Header.Get("Accept"), "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"access_token":"123445"}`))
	}))
	defer server.Close()

	token, err := GetToken(server.URL)

	testLogger.Log(alog.DEBUG, "fetched token: %s", token)
	assert.Nil(err)
	assert.Equal("123445", token)
}
