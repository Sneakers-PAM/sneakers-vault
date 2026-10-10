// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"io"
	"net"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	postgres "github.com/Bugs5382/go-postgres"
)

// proxy forwards TCP to target until cut, which closes the listener and every
// open connection: from the client's side the database is gone. resume
// listens again on the same address.
type proxy struct {
	t      *testing.T
	addr   string
	target string
	mu     sync.Mutex
	ln     net.Listener
	conns  []net.Conn
}

func newProxy(t *testing.T, target string) *proxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{t: t, addr: ln.Addr().String(), target: target}
	p.serve(ln)
	t.Cleanup(p.cut)
	return p
}

func (p *proxy) serve(ln net.Listener) {
	p.mu.Lock()
	p.ln = ln
	p.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", p.target)
			if err != nil {
				_ = c.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, c, up)
			p.mu.Unlock()
			go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
			go func() { _, _ = io.Copy(c, up); _ = c.Close() }()
		}
	}()
}

func (p *proxy) cut() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln != nil {
		_ = p.ln.Close()
		p.ln = nil
	}
	for _, c := range p.conns {
		_ = c.Close()
	}
	p.conns = nil
}

func (p *proxy) resume() {
	ln, err := net.Listen("tcp", p.addr)
	if err != nil {
		p.t.Fatal(err)
	}
	p.serve(ln)
}

// TestPostgres_ReadinessFollowsARealDatabase runs against TEST_DATABASE_DSN
// through a proxy the test cuts mid-test.
func TestPostgres_ReadinessFollowsARealDatabase(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("TEST_DATABASE_DSN not set")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	p := newProxy(t, u.Host)
	u.Host = p.addr
	ctx := context.Background()
	db, err := postgres.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ch := refreshed(t, newTestChecker(t, Postgres(db)))
	if r := ch.Report(ctx); r.Status != health.StateOK || r.Dependencies[0].Version == "unknown" {
		t.Fatalf("database up: %+v", r)
	}
	p.cut()
	time.Sleep(2 * testTTL)
	r := ch.Report(ctx)
	if r.Status != health.StateDown || r.Ready || r.Dependencies[0].Error == "" {
		t.Fatalf("database gone: %+v", r)
	}
	p.resume()
	deadline := time.Now().Add(15 * time.Second)
	for {
		time.Sleep(testTTL)
		r := ch.Report(ctx)
		if r.Status == health.StateOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("database back: %+v", r)
		}
	}
}
