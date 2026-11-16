// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Bugs5382/go-mtls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// MTLSFromEnv builds the mutual TLS provider from MTLS_CERT_FILE,
// MTLS_KEY_FILE and MTLS_CA_FILE. With none of them set it returns nil, nil:
// the service stays plaintext, which is how turning the chart switch off rolls
// back. With some but not all set, or with a file that cannot be read, it
// returns an error so the service refuses to start; it never falls back to
// plaintext on its own.
func MTLSFromEnv(getenv func(string) string) (*mtls.Provider, error) {
	f := mtls.Files{Cert: getenv(mtls.EnvCertFile), Key: getenv(mtls.EnvKeyFile), CA: getenv(mtls.EnvCAFile)}
	if f.Cert == "" && f.Key == "" && f.CA == "" {
		return nil, nil
	}
	var missing []string
	for _, v := range []struct{ name, val string }{{mtls.EnvCertFile, f.Cert}, {mtls.EnvKeyFile, f.Key}, {mtls.EnvCAFile, f.CA}} {
		if v.val == "" {
			missing = append(missing, v.name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("mutual TLS is partly configured; also set %s, or unset the others to run without it", strings.Join(missing, ", "))
	}
	p, err := mtls.NewProvider(f)
	if err != nil {
		return nil, fmt.Errorf("mutual TLS files: %w", err)
	}
	return p, nil
}

// MTLSDialOption is the transport option for an outbound gRPC connection:
// the service certificate and CA of p, or plaintext when p is nil.
func MTLSDialOption(p *mtls.Provider) grpc.DialOption {
	if p == nil {
		return grpc.WithTransportCredentials(insecure.NewCredentials())
	}
	return p.DialOption()
}

// BootPort is where the boot health service listens while a service waits for
// its dependencies: the service port, or the plain health port when mutual TLS
// is on (p not nil), because the service port then refuses a caller without a
// certificate and the kubelet's probe has none.
func BootPort(p *mtls.Provider, grpcPort, healthPort string) string {
	if p != nil {
		return healthPort
	}
	return grpcPort
}

// RequireHealthPort refuses mutual TLS without HEALTH_PORT: the kubelet probe
// cannot present a certificate, so health needs its own plain port.
func RequireHealthPort(p *mtls.Provider, healthPort string) error {
	if p != nil && healthPort == "" {
		return errors.New("mutual TLS is on and HEALTH_PORT is not set: health needs its own plain port")
	}
	return nil
}
