package nets

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

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

	fmt.Println(token)
	assert.Nil(err)
	assert.Equal("123445", token)

}
