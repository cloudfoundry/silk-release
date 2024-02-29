package testsupport

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"

	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/grouper"
	"github.com/tedsuo/ifrit/http_server"
	"github.com/tedsuo/ifrit/sigmon"
)

type FakePolicyServer struct {
	Server      ifrit.Process
	ReturnedTag string
}

func (f *FakePolicyServer) Start(listenAddr string, tlsConfig *tls.Config) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/networking/v1/internal/tags":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf(`{
					"id": "some-id",
					"type": "some-type",
					"tag": %q
				}`, f.ReturnedTag)))
		}
	})

	someServer := http_server.NewTLSServer(listenAddr, handler, tlsConfig)

	members := grouper.Members{{
		Name:   "http_server",
		Runner: someServer,
	}}
	group := grouper.NewOrdered(os.Interrupt, members)
	f.Server = ifrit.Invoke(sigmon.New(group))
}

func (f *FakePolicyServer) Stop() {
	f.Server.Signal(os.Interrupt)
}
