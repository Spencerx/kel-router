package server

import (
	"crypto/tls"
	"regexp"

	"github.com/kelproject/router/reverseproxy"
)

type VirtualHostMatcher struct {
	Vhosts []*VirtualHost
}

func (vhm *VirtualHostMatcher) Match(host string) *VirtualHost {
	if len(vhm.Vhosts) == 1 && vhm.Vhosts[0].Regex == nil {
		return vhm.Vhosts[0]
	}
	for _, vh := range vhm.Vhosts {
		if vh.Regex.MatchString(host) {
			return vh
		}
	}
	return nil
}

type VirtualHost struct {
	Regex        *regexp.Regexp
	Backends     []reverseproxy.Backend
	ReverseProxy reverseproxy.ReverseProxy
	TLSConfig    *tls.Config

	strategy reverseproxy.BackendStrategy
}

func (vh *VirtualHost) GetStrategy() reverseproxy.BackendStrategy {
	if vh.strategy != nil {
		return vh.strategy
	}
	return &reverseproxy.RoundRobinStrategy{
		Backends: vh.Backends,
	}
}
