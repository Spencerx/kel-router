package datasources

import (
	"golang.org/x/net/context"
	"github.com/kelproject/router/server"
)

// DataStore ...
type DataStore interface {
	Watch(ctx context.Context, sh SyncHandler)
}

// SyncHandler ...
type SyncHandler interface {
	SetHost(host string, vhm *server.VirtualHostMatcher)
	RemoveHost(host string)
}
