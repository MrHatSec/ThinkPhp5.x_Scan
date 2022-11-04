package requests

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

func DefaultTransport() *http.Transport {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   time.Second * 5,
			KeepAlive: time.Second * 5,
		}).DialContext,
		MaxConnsPerHost:     5,
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     time.Second * 5,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: time.Second * 5,
		DisableKeepAlives:   false,
	}
	return transport
}
