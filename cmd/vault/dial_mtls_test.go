// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bugs5382/go-mtls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// testProvider writes a throwaway CA and one certificate valid for localhost
// and returns a provider over them.
func testProvider(t *testing.T) *mtls.Provider {
	t.Helper()
	dir := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"}, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "vault"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	f := mtls.Files{Cert: filepath.Join(dir, "tls.crt"), Key: filepath.Join(dir, "tls.key"), CA: filepath.Join(dir, "ca.crt")}
	for path, b := range map[string]*pem.Block{f.Cert: {Type: "CERTIFICATE", Bytes: der}, f.Key: {Type: "EC PRIVATE KEY", Bytes: keyDER}, f.CA: {Type: "CERTIFICATE", Bytes: caDER}} {
		if err := os.WriteFile(path, pem.EncodeToMemory(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	p, err := mtls.NewProvider(f)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// healthServer serves the health service on a local port, over mutual TLS when
// p is not nil, and returns its address.
func healthServer(t *testing.T, p *mtls.Provider) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var opts []grpc.ServerOption
	if p != nil {
		opts = append(opts, p.ServerOption())
	}
	s := grpc.NewServer(opts...)
	healthpb.RegisterHealthServer(s, health.NewServer())
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	return "localhost:" + lis.Addr().(*net.TCPAddr).AddrPort().String()[len("127.0.0.1:"):]
}

func callHealth(t *testing.T, addr string, opts []grpc.DialOption) error {
	t.Helper()
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	return err
}

func TestDialOptions_PlaintextWithoutAProvider(t *testing.T) {
	t.Setenv("WORKLOAD_TOKEN_FILE", "")
	opts, err := dialOptions(nil, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if err := callHealth(t, healthServer(t, nil), opts); err != nil {
		t.Fatalf("plaintext dial to a plaintext server: %v", err)
	}
}

func TestDialOptions_MutualTLSWithAProvider(t *testing.T) {
	p := testProvider(t)
	opts, err := dialOptions(p, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if err := callHealth(t, healthServer(t, p), opts); err != nil {
		t.Fatalf("mutual TLS dial to a mutual TLS server: %v", err)
	}
	if err := callHealth(t, healthServer(t, nil), opts); err == nil {
		t.Fatal("a mutual TLS client reached a plaintext server")
	}
}
