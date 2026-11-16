// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package mtlstest is test support for code that dials or serves gRPC over
// mutual TLS: a throwaway CA and certificate, a health server, and a health
// call. Tests only; nothing in a binary imports it.
package mtlstest

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
	"strconv"
	"testing"
	"time"

	"github.com/Bugs5382/go-mtls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// Files writes a throwaway CA and one certificate for localhost, valid for
// server and client use, and returns the three file paths.
func Files(t *testing.T) mtls.Files {
	t.Helper()
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"}, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "svc"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	f := mtls.Files{Cert: filepath.Join(dir, "tls.crt"), Key: filepath.Join(dir, "tls.key"), CA: filepath.Join(dir, "ca.crt")}
	for path, b := range map[string]*pem.Block{f.Cert: {Type: "CERTIFICATE", Bytes: der}, f.Key: {Type: "EC PRIVATE KEY", Bytes: keyDER}, f.CA: {Type: "CERTIFICATE", Bytes: caDER}} {
		if err := os.WriteFile(path, pem.EncodeToMemory(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// Env is the MTLS_* environment for f.
func Env(f mtls.Files) func(string) string {
	m := map[string]string{mtls.EnvCertFile: f.Cert, mtls.EnvKeyFile: f.Key, mtls.EnvCAFile: f.CA}
	return func(k string) string { return m[k] }
}

// Provider is a provider over a fresh throwaway CA and certificate.
func Provider(t *testing.T) *mtls.Provider {
	t.Helper()
	p, err := mtls.NewProvider(Files(t))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// HealthServer serves the health service on a local port, over mutual TLS when
// p is not nil, and returns the address to dial (host name localhost).
func HealthServer(t *testing.T, p *mtls.Provider) string {
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
	return "localhost:" + strconv.Itoa(lis.Addr().(*net.TCPAddr).Port)
}

// CallHealth makes one health check on a new connection with opts.
func CallHealth(t *testing.T, addr string, opts ...grpc.DialOption) error {
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
