// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

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
	"strings"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/Bugs5382/go-mtls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// mtlsFiles writes a throwaway CA and one leaf certificate valid for localhost
// (server and client use) and returns the three file paths.
func mtlsFiles(t *testing.T, ca *testCA) mtls.Files {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "vault"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	f := mtls.Files{Cert: filepath.Join(dir, "tls.crt"), Key: filepath.Join(dir, "tls.key"), CA: filepath.Join(dir, "ca.crt")}
	writePEM(t, f.Cert, "CERTIFICATE", der)
	writePEM(t, f.Key, "EC PRIVATE KEY", keyDER)
	writePEM(t, f.CA, "CERTIFICATE", ca.cert.Raw)
	return f
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: c, key: key}
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mtlsEnvOf(f mtls.Files) func(string) string {
	m := map[string]string{"MTLS_CERT_FILE": f.Cert, "MTLS_KEY_FILE": f.Key, "MTLS_CA_FILE": f.CA}
	return func(k string) string { return m[k] }
}

func TestMTLSFromEnv_UnsetStaysPlaintext(t *testing.T) {
	p, err := MTLSFromEnv(func(string) string { return "" })
	if err != nil || p != nil {
		t.Fatalf("p=%v err=%v, want nil, nil so the switch can roll back", p, err)
	}
}

func TestMTLSFromEnv_PartialSettingRefusesToStart(t *testing.T) {
	f := mtlsFiles(t, newTestCA(t))
	env := mtlsEnvOf(f)
	partial := func(k string) string {
		if k == "MTLS_CA_FILE" {
			return ""
		}
		return env(k)
	}
	p, err := MTLSFromEnv(partial)
	if err == nil || p != nil {
		t.Fatalf("p=%v err=%v, want an error: a half-set switch must not fall back to plaintext", p, err)
	}
	if !strings.Contains(err.Error(), "MTLS_CA_FILE") {
		t.Fatalf("error %q should name the missing variable", err)
	}
}

func TestMTLSFromEnv_MissingFileRefusesToStart(t *testing.T) {
	f := mtlsFiles(t, newTestCA(t))
	f.Key = filepath.Join(t.TempDir(), "absent.key")
	if p, err := MTLSFromEnv(mtlsEnvOf(f)); err == nil || p != nil {
		t.Fatalf("p=%v err=%v, want a refusal naming the unreadable file", p, err)
	}
}

// mtlsServer runs RunWithHealthTLS and returns the TLS port and the plain health port.
func mtlsServer(t *testing.T, p *mtls.Provider) (port, healthPort string) {
	t.Helper()
	port, healthPort = freePort(t), freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunWithHealthTLS(ctx, port, healthPort, p, log.Nop(), nil, func(*grpc.Server) {}) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	})
	waitDial(t, "127.0.0.1:"+healthPort)
	waitDial(t, "127.0.0.1:"+port)
	return port, healthPort
}

func waitDial(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never listened", addr)
}

func checkHealth(conn *grpc.ClientConn) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	return err
}

func TestRunWithHealthTLS_ServesOnlyMutualTLSOnTheServicePort(t *testing.T) {
	ca := newTestCA(t)
	p, err := mtls.NewProvider(mtlsFiles(t, ca))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := mtlsServer(t, p)

	good, err := grpc.NewClient("localhost:"+port, p.DialOption())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = good.Close() }()
	if err := checkHealth(good); err != nil {
		t.Fatalf("a caller with a certificate from the CA was refused: %v", err)
	}

	plain, err := grpc.NewClient("localhost:"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = plain.Close() }()
	if err := checkHealth(plain); err == nil {
		t.Fatal("a plaintext caller reached the service port")
	}

	// A caller whose certificate another CA signed is refused at the handshake.
	other, err := mtls.NewProvider(mtlsFiles(t, newTestCA(t)))
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := grpc.NewClient("localhost:"+port, other.DialOption())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stranger.Close() }()
	if err := checkHealth(stranger); err == nil {
		t.Fatal("a caller signed by another CA reached the service port")
	}
}

func TestRunWithHealthTLS_HealthPortIsPlainAndHealthOnly(t *testing.T) {
	p, err := mtls.NewProvider(mtlsFiles(t, newTestCA(t)))
	if err != nil {
		t.Fatal(err)
	}
	_, healthPort := mtlsServer(t, p)

	conn, err := grpc.NewClient("127.0.0.1:"+healthPort, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := checkHealth(conn); err != nil {
		t.Fatalf("kubelet-style plaintext health check failed: %v", err)
	}
	// Only the health service lives here: reflection must not be served.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = conn.Invoke(ctx, "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", &healthpb.HealthCheckRequest{}, &healthpb.HealthCheckResponse{})
	if err == nil {
		t.Fatal("the health port served something other than health")
	}
}

func TestRunWithHealthTLS_RequiresAHealthPort(t *testing.T) {
	p, err := mtls.NewProvider(mtlsFiles(t, newTestCA(t)))
	if err != nil {
		t.Fatal(err)
	}
	err = RunWithHealthTLS(context.Background(), freePort(t), "", p, log.Nop(), nil, func(*grpc.Server) {})
	if err == nil || !strings.Contains(err.Error(), "HEALTH_PORT") {
		t.Fatalf("err=%v, want a refusal naming HEALTH_PORT: probes cannot present a certificate", err)
	}
}

func TestRunWithHealthTLS_NilProviderIsPlaintext(t *testing.T) {
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunWithHealthTLS(ctx, port, "", nil, log.Nop(), nil, func(*grpc.Server) {}) }()
	waitDial(t, "127.0.0.1:"+port)
	conn, err := grpc.NewClient("127.0.0.1:"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := checkHealth(conn); err != nil {
		t.Fatalf("plaintext mode broke: %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestBootPort(t *testing.T) {
	if got := BootPort(nil, "9090", "9091"); got != "9090" {
		t.Fatalf("plaintext: %q, want the service port", got)
	}
	if got := BootPort(&mtls.Provider{}, "9090", "9091"); got != "9091" {
		t.Fatalf("mutual TLS: %q, want the plain health port", got)
	}
}

func TestRequireHealthPort(t *testing.T) {
	if err := RequireHealthPort(nil, ""); err != nil {
		t.Fatalf("plaintext needs no health port: %v", err)
	}
	if err := RequireHealthPort(&mtls.Provider{}, ""); err == nil || !strings.Contains(err.Error(), "HEALTH_PORT") {
		t.Fatalf("err=%v, want a refusal naming HEALTH_PORT", err)
	}
	if err := RequireHealthPort(&mtls.Provider{}, "9091"); err != nil {
		t.Fatal(err)
	}
}
