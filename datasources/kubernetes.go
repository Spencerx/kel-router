package datasources

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kelproject/router/reverseproxy"
	"github.com/kelproject/router/server"

	"golang.org/x/net/context"
	kapi "k8s.io/kubernetes/pkg/api"
	kcache "k8s.io/kubernetes/pkg/client/cache"
	kclient "k8s.io/kubernetes/pkg/client/unversioned"
	kclientcmd "k8s.io/kubernetes/pkg/client/unversioned/clientcmd"
	kframework "k8s.io/kubernetes/pkg/controller/framework"
	kSelector "k8s.io/kubernetes/pkg/fields"
)

const (
	// Resync period for the kube controller loop.
	resyncPeriod = 5 * time.Minute
)

type kubernetesServiceConfig struct {
	Hosts []string `json:"hosts,omitempty"`
	Mode  string   `json:"mode,omitempty"`
	TLS   struct {
		Key         []byte `json:"key"`
		Certificate []byte `json:"certificate"`
	} `json:"tls,omitempty"`
	Port int `json:"port"`
}

type kubernetesDataStore struct {
	kubClient *kclient.Client
	srvCache  []*kapi.Service
}

// NewKubernetesDataStore creates a data store capable of sync'ing Kubernetes
// services and pods.
func NewKubernetesDataStore() (DataStore, error) {
	overrides := &kclientcmd.ConfigOverrides{}
	rules := &kclientcmd.ClientConfigLoadingRules{}
	config, err := kclientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		return nil, err
	}
	kubClient, err := kclient.New(config)
	if err != nil {
		return nil, err
	}
	return &kubernetesDataStore{
		kubClient: kubClient,
	}, nil
}

func (ds *kubernetesDataStore) createServiceLW() *kcache.ListWatch {
	return kcache.NewListWatchFromClient(ds.kubClient, "services", kapi.NamespaceAll, kSelector.Everything())
}

func (ds *kubernetesDataStore) createPodLW() *kcache.ListWatch {
	return kcache.NewListWatchFromClient(ds.kubClient, "pods", kapi.NamespaceAll, kSelector.Everything())
}

func (ds *kubernetesDataStore) Watch(ctx context.Context, sh SyncHandler) {
	go ds.watchServices(ctx, sh)
	go ds.watchPods(ctx, sh)
}

func (ds *kubernetesDataStore) watchServices(ctx context.Context, sh SyncHandler) {
	_, controller := kframework.NewInformer(
		ds.createServiceLW(),
		&kapi.Service{},
		resyncPeriod,
		kframework.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if s, ok := obj.(*kapi.Service); ok {
					ds.setService(s, sh)
				}
			},
			DeleteFunc: func(obj interface{}) {
				if s, ok := obj.(*kapi.Service); ok {
					ds.removeService(s, sh)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if s, ok := oldObj.(*kapi.Service); ok {
					ds.removeService(s, sh)
				}
				if s, ok := newObj.(*kapi.Service); ok {
					ds.setService(s, sh)
				}
			},
		},
	)
	controller.Run(ctx.Done())
}

func (ds *kubernetesDataStore) watchPods(ctx context.Context, sh SyncHandler) {
	_, controller := kframework.NewInformer(
		ds.createPodLW(),
		&kapi.Pod{},
		resyncPeriod,
		kframework.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if p, ok := obj.(*kapi.Pod); ok {
					ds.setPod(p, sh)
				}
			},
			DeleteFunc: func(obj interface{}) {
				if p, ok := obj.(*kapi.Pod); ok {
					ds.removePod(p, sh)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if p, ok := oldObj.(*kapi.Pod); ok {
					ds.removePod(p, sh)
				}
				if p, ok := newObj.(*kapi.Pod); ok {
					ds.setPod(p, sh)
				}
			},
		},
	)
	controller.Run(ctx.Done())
}

func (ds *kubernetesDataStore) setConfig(config *kubernetesServiceConfig, sh SyncHandler, ip string) error {
	var tlsConfig *tls.Config
	if len(config.TLS.Key) > 0 && len(config.TLS.Certificate) > 0 {
		cert, err := tls.X509KeyPair(config.TLS.Certificate, config.TLS.Key)
		if err != nil {
			return err
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	}
	for i := range config.Hosts {
		host := config.Hosts[i]
		var rp reverseproxy.ReverseProxy
		switch config.Mode {
		case "raw":
			rp = reverseproxy.NewRawReverseProxy()
			break
		default:
			rp = reverseproxy.NewHTTPReverseProxy()
		}
		vhm := &server.VirtualHostMatcher{
			Vhosts: []*server.VirtualHost{
				{
					Backends: []reverseproxy.Backend{
						{
							Addr:           fmt.Sprintf("%s:%d", ip, config.Port),
							ConnectTimeout: 10000,
						},
					},
					ReverseProxy: rp,
					TLSConfig:    tlsConfig,
				},
			},
		}
		sh.SetHost(host, vhm)
	}
	return nil
}

func (ds *kubernetesDataStore) removeConfig(config *kubernetesServiceConfig, sh SyncHandler) error {
	for i := range config.Hosts {
		sh.RemoveHost(config.Hosts[i])
	}
	return nil
}

func (ds *kubernetesDataStore) setService(service *kapi.Service, sh SyncHandler) error {
	if _, ok := service.Annotations["router"]; !ok {
		return nil
	}
	var res kubernetesServiceConfig
	if err := json.Unmarshal([]byte(service.Annotations["router"]), &res); err != nil {
		return nil
	}
	if len(service.Spec.Ports) == 0 {
		return nil
	}
	if res.Port == 0 {
		res.Port = service.Spec.Ports[0].Port
	}
	if err := ds.setConfig(&res, sh, service.Spec.ClusterIP); err != nil {
		return err
	}
	return nil
}

func (ds *kubernetesDataStore) removeService(service *kapi.Service, sh SyncHandler) error {
	if _, ok := service.Annotations["router"]; !ok {
		return nil
	}
	var res kubernetesServiceConfig
	if err := json.Unmarshal([]byte(service.Annotations["router"]), &res); err != nil {
		return nil
	}
	if err := ds.removeConfig(&res, sh); err != nil {
		return err
	}
	return nil
}

func (ds *kubernetesDataStore) setPod(pod *kapi.Pod, sh SyncHandler) error {
	if _, ok := pod.Annotations["router"]; !ok {
		return nil
	}
	var res kubernetesServiceConfig
	if err := json.Unmarshal([]byte(pod.Annotations["router"]), &res); err != nil {
		return nil
	}
	if err := ds.setConfig(&res, sh, pod.Status.PodIP); err != nil {
		return err
	}
	return nil
}

func (ds *kubernetesDataStore) removePod(pod *kapi.Pod, sh SyncHandler) error {
	if _, ok := pod.Annotations["router"]; !ok {
		return nil
	}
	var res kubernetesServiceConfig
	if err := json.Unmarshal([]byte(pod.Annotations["router"]), &res); err != nil {
		return nil
	}
	if err := ds.removeConfig(&res, sh); err != nil {
		return err
	}
	return nil
}
