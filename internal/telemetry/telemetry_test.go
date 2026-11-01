// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	otel "github.com/Bugs5382/go-otel"
	"github.com/Sneakers-PAM/sneakers-vault/internal/server"
	otelapi "go.opentelemetry.io/otel"
	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/prototext"
)

const canary = "canary-value-7f3a"

type logCollector struct {
	collogs.UnimplementedLogsServiceServer
	mu   sync.Mutex
	wire strings.Builder
}

func (c *logCollector) Export(_ context.Context, r *collogs.ExportLogsServiceRequest) (*collogs.ExportLogsServiceResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wire.WriteString(prototext.Format(r))
	return &collogs.ExportLogsServiceResponse{}, nil
}

func (c *logCollector) text() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wire.String()
}

func startCollector(t *testing.T) (*logCollector, string) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &logCollector{}
	s := grpc.NewServer()
	collogs.RegisterLogsServiceServer(s, c)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	return c, "http://" + lis.Addr().String()
}

func env(values map[string]string) func(string) string {
	return func(k string) string { return values[k] }
}

func shutdownWithin(t *testing.T, stop func(context.Context) error, d time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	_ = stop(ctx)
}

func TestOutputUnsetIsStdout(t *testing.T) {
	if got := Output(env(nil)); got != os.Stdout {
		t.Fatalf("Output with no env = %v, want os.Stdout", got)
	}
	for _, v := range []string{"1", "TRUE", "yes", "false"} {
		if got := Output(env(map[string]string{EnvLogsEnabled: v})); got != os.Stdout {
			t.Errorf("%s=%s changed the output", EnvLogsEnabled, v)
		}
	}
}

func TestOutputTrueAddsTheExporter(t *testing.T) {
	if got := Output(env(map[string]string{EnvLogsEnabled: "true"})); got == os.Stdout {
		t.Fatal("logs on must add the export writer")
	}
}

func TestLogsOffExportsNothing(t *testing.T) {
	c, endpoint := startCollector(t)
	stop, err := otel.InitWithOptions(context.Background(), "vault", endpoint, Options(env(nil))...)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = otel.LogWriter().Write([]byte(`{"level":"error","service":"vault","time":"2026-10-31T12:00:00Z","message":"held back"}` + "\n"))
	shutdownWithin(t, stop, 5*time.Second)
	if got := c.text(); got != "" {
		t.Fatalf("logs left with the switch off: %s", got)
	}
}

// A real service logger, so the proof covers what zerolog actually writes.
func TestOnlyAllowedFieldsReachTheCollector(t *testing.T) {
	c, endpoint := startCollector(t)
	on := env(map[string]string{EnvLogsEnabled: "true"})
	var stdout bytes.Buffer
	stop, err := otel.InitWithOptions(context.Background(), "vault", endpoint, Options(on)...)
	if err != nil {
		t.Fatal(err)
	}
	lg := log.NewLoggerWithOptions("vault", log.WithOutput(io.MultiWriter(&stdout, otel.LogWriter())), log.WithDefaultFormat(log.FormatJSON))
	token := "snk_" + canary

	lg.Error(errors.New(canary+"-err"), "export check",
		log.F("secret_id", "sec-1"),
		log.F("port", token),
		log.F("reason", canary+"-reason"),
		log.F("subject", "sec-1#"+canary+"-subject"),
		log.F("field_key", canary+"-field"),
		log.F("trigger", canary+"-trigger"),
		log.F("added", canary+"-added"),
		log.F("panic", canary+"-panic"),
		log.F("stack", canary+"-stack"),
		log.F("unlisted", canary+"-unlisted"))
	shutdownWithin(t, stop, 5*time.Second)

	got := c.text()
	if !strings.Contains(got, "export check") || !strings.Contains(got, "sec-1") {
		t.Fatalf("the allowed part did not arrive: %s", got)
	}
	if strings.Contains(got, canary) {
		t.Fatalf("a canary reached the collector: %s", got)
	}
	if !strings.Contains(stdout.String(), canary+"-reason") {
		t.Fatalf("stdout must keep every field: %s", stdout.String())
	}
}

func TestLoggersBeforeInitAreSafe(t *testing.T) {
	lg, zl := NewLoggers("vault", env(map[string]string{EnvLogsEnabled: "true"}))
	lg.Info("before init")
	zl.Info().Msg("before init")
}

func TestSkipVerifyKeepsLogsOff(t *testing.T) {
	_, endpoint := startCollector(t)
	stop, err := otel.InitWithOptions(context.Background(), "vault", endpoint,
		Options(env(map[string]string{EnvLogsEnabled: "true", EnvInsecureSkipVerify: "true"}))...)
	if err != nil {
		t.Fatal(err)
	}
	defer shutdownWithin(t, stop, time.Second)
	if otel.ExportState().Logs.Disabled == "" {
		t.Fatal("logs must stay off while certificate checks are skipped")
	}
}

func TestDependencyOnlyWithAnEndpoint(t *testing.T) {
	for _, endpoint := range []string{"", "   "} {
		if got := Dependencies(endpoint, env(nil)); len(got) != 0 {
			t.Errorf("endpoint %q: dependencies = %v", endpoint, got)
		}
	}
	got := Dependencies("https://collector.example.test:4317", env(nil))
	if len(got) != 1 || got[0].Name != "otlp" || got[0].Required {
		t.Fatalf("dependencies = %+v", got)
	}
}

func TestOTLPDownFollowsTheNewestOutcome(t *testing.T) {
	old, recent := time.Unix(100, 0), time.Unix(200, 0)
	failing := otel.SignalStatus{LastSuccess: old, LastErrorAt: recent}
	healthy := otel.SignalStatus{LastSuccess: recent, LastErrorAt: old}
	cases := []struct {
		name string
		st   otel.ExportStatus
		logs bool
		want bool
	}{
		{"nothing yet", otel.ExportStatus{}, true, false},
		{"recovered", otel.ExportStatus{Traces: healthy, Metrics: healthy, Logs: healthy}, true, false},
		{"traces", otel.ExportStatus{Traces: failing}, false, true},
		{"metrics", otel.ExportStatus{Metrics: failing}, false, true},
		{"logs on", otel.ExportStatus{Logs: failing}, true, true},
		{"logs off", otel.ExportStatus{Logs: failing}, false, false},
	}
	for _, tc := range cases {
		if got := exportDown(tc.st, tc.logs); got != tc.want {
			t.Errorf("%s: down = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestFailingCollectorDegradesButStaysReady(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "http://" + lis.Addr().String()
	_ = lis.Close()

	stop, err := otel.InitWithOptions(context.Background(), "vault", endpoint, Options(env(nil))...)
	if err != nil {
		t.Fatal(err)
	}
	_, span := otelapi.Tracer("test").Start(context.Background(), "doomed")
	span.End()
	shutdownWithin(t, stop, 3*time.Second)

	c, err := server.NewChecker(log.Nop(), Dependencies(endpoint, env(nil)), health.WithTTL(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	var rep health.Report
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if rep = c.Report(ctx); rep.Status == health.StateDegraded {
			break
		}
	}
	if rep.Status != health.StateDegraded || !rep.Ready {
		t.Fatalf("report = %+v, want degraded and ready", rep)
	}
	for _, d := range rep.Dependencies {
		if strings.Contains(d.Error, lis.Addr().String()) {
			t.Fatalf("the endpoint leaked into health: %+v", d)
		}
	}
}

func TestExportErrorsLeaveOutEndpointAndHeaders(t *testing.T) {
	var buf bytes.Buffer
	HandleErrors(log.NewLoggerWithOptions("vault", log.WithOutput(&buf), log.WithDefaultFormat(log.FormatJSON)))
	otelapi.Handle(errors.New("post https://user:" + canary + "@collector.example.test: authorization=" + canary))
	got := buf.String()
	if !strings.Contains(got, "otel export error") {
		t.Fatalf("no line logged: %q", got)
	}
	if strings.Contains(got, canary) || strings.Contains(got, "collector.example.test") {
		t.Fatalf("raw error logged: %q", got)
	}
}
