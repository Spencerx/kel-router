package datasources

import (
	"github.com/kelproject/router/reverseproxy"
	"github.com/kelproject/router/server"

	"golang.org/x/net/context"
)

type fileDataStore struct {
}

func NewFileDataStore() (*fileDataStore, error) {
	return &fileDataStore{}, nil
}

func (ds *fileDataStore) Watch(ctx context.Context, sh SyncHandler) {
	rp := reverseproxy.NewHTTPReverseProxy()
	vhm := &server.VirtualHostMatcher{
		Vhosts: []*server.VirtualHost{
			{
				Backends: []reverseproxy.Backend{
					{
						Addr:           "localhost:4000",
						ConnectTimeout: 10000,
					},
				},
				ReverseProxy: rp,
			},
		},
	}
	sh.SetHost("localhost", vhm)
}
