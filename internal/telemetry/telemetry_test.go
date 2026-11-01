// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"bytes"
	"context"
	"errors"
	"io"
	stdlog "log"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	otel "github.com/Bugs5382/go-otel"
	"github.com/Sneakers-PAM/sneakers-vault/internal/server"
	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5"
	otelapi "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/metric"
	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetric "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

const canary = "canary-value-7f3a"

type collector struct {
	collogs.UnimplementedLogsServiceServer
	mu    sync.Mutex
	logs  strings.Builder
	other strings.Builder
}

func (c *collector) Export(_ context.Context, r *collogs.ExportLogsServiceRequest) (*collogs.ExportLogsServiceResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logs.WriteString(prototext.Format(r))
	return &collogs.ExportLogsServiceResponse{}, nil
}

func (c *collector) record(m proto.Message) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.other.WriteString(prototext.Format(m))
}

// text is what arrived on the logs signal.
func (c *collector) text() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.logs.String()
}

// everything is what arrived on all three signals.
func (c *collector) everything() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.logs.String() + c.other.String()
}

type traceCollector struct {
	coltrace.UnimplementedTraceServiceServer
	c *collector
}

func (s traceCollector) Export(_ context.Context, r *coltrace.ExportTraceServiceRequest) (*coltrace.ExportTraceServiceResponse, error) {
	s.c.record(r)
	return &coltrace.ExportTraceServiceResponse{}, nil
}

type metricCollector struct {
	colmetric.UnimplementedMetricsServiceServer
	c *collector
}

func (s metricCollector) Export(_ context.Context, r *colmetric.ExportMetricsServiceRequest) (*colmetric.ExportMetricsServiceResponse, error) {
	s.c.record(r)
	return &colmetric.ExportMetricsServiceResponse{}, nil
}

func startCollector(t *testing.T) (*collector, string) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &collector{}
	s := grpc.NewServer()
	collogs.RegisterLogsServiceServer(s, c)
	coltrace.RegisterTraceServiceServer(s, traceCollector{c: c})
	colmetric.RegisterMetricsServiceServer(s, metricCollector{c: c})
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
		log.F("outcome", canary+"-outcome"),
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
	_, endpoint := startCollector(t)
	stop, err := otel.InitWithOptions(context.Background(), "vault", endpoint, Options(env(nil))...)
	if err != nil {
		t.Fatal(err)
	}
	defer shutdownWithin(t, stop, time.Second)

	var buf bytes.Buffer
	stdlog.SetOutput(&buf)
	defer stdlog.SetOutput(os.Stderr)
	otelapi.Handle(errors.New("post https://user:" + canary + "@collector.example.test: authorization=" + canary))
	if got := buf.String(); strings.Contains(got, canary) || strings.Contains(got, "collector.example.test") {
		t.Fatalf("raw error logged: %q", got)
	}
}

func TestOutcomeStaysOffTheAllowList(t *testing.T) {
	if slices.Contains(AllowFields, "outcome") {
		t.Fatal("outcome carries err.Error() from go-workload-identity")
	}
}

func unaryDesc(service, method string, h func(context.Context) (any, error)) *grpc.ServiceDesc {
	return &grpc.ServiceDesc{
		ServiceName: service,
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{{
			MethodName: method,
			Handler: func(_ any, ctx context.Context, dec func(any) error, intercept grpc.UnaryServerInterceptor) (any, error) {
				if err := dec(&emptypb.Empty{}); err != nil {
					return nil, err
				}
				return intercept(ctx, &emptypb.Empty{}, &grpc.UnaryServerInfo{FullMethod: "/" + service + "/" + method},
					func(ctx context.Context, _ any) (any, error) { return h(ctx) })
			},
		}},
	}
}

// Real RPCs through the service's own server and client handlers, plus a query
// through the service's own database tracer options.
func TestCanariesStayOffEverySignal(t *testing.T) {
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment="+canary+"-resource")
	c, endpoint := startCollector(t)
	stop, err := otel.InitWithOptions(context.Background(), "vault", endpoint, Options(env(nil))...)
	if err != nil {
		t.Fatal(err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(lis.Addr().String())
	_ = lis.Close()

	var baggageSeen atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		served <- server.RunWithHealth(ctx, port, log.Nop(), nil, func(s *grpc.Server) {
			s.RegisterService(unaryDesc("sneakers.vault.v1.VaultService", "Fail", func(ctx context.Context) (any, error) {
				baggageSeen.Add(int32(baggage.FromContext(ctx).Len()))
				return nil, status.Error(codes.Internal, canary+"-status")
			}), nil)
			s.RegisterService(unaryDesc("sneakers.vault.v1.VaultService2", "Panic", func(context.Context) (any, error) {
				panic(errors.New(canary + "-exception"))
			}), nil)
		})
	}()

	conn, err := grpc.NewClient("127.0.0.1:"+port, grpc.WithTransportCredentials(insecure.NewCredentials()), server.ClientStatsHandler())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	call := func(method string) {
		callCtx := metadata.AppendToOutgoingContext(context.Background(), "baggage", "key="+canary+"-baggage")
		_ = conn.Invoke(callCtx, method, &emptypb.Empty{}, &emptypb.Empty{}, grpc.WaitForReady(true))
	}
	call("/sneakers.vault.v1.VaultService/Fail")
	call("/sneakers.vault.v1.VaultService2/Panic")
	call("/sneakers.vault.v1.VaultService/" + canary + "-method")

	counter, err := otelapi.Meter("test").Int64Counter("canary.count")
	if err != nil {
		t.Fatal(err)
	}
	counter.Add(context.Background(), 1, metric.WithAttributes(attribute.String("label", canary+"-metric")))

	tracer := otelpgx.NewTracer(dbTracing()...)
	parent, span := otelapi.Tracer("test").Start(context.Background(), "parent")
	qctx := tracer.TraceQueryStart(parent, nil, pgx.TraceQueryStartData{SQL: "SELECT '" + canary + "-sql' FROM secrets"})
	tracer.TraceQueryEnd(qctx, nil, pgx.TraceQueryEndData{})
	span.End()

	cancel()
	<-served
	shutdownWithin(t, stop, 5*time.Second)

	got := c.everything()
	for _, want := range []string{"sneakers.vault.v1.VaultService/Fail", "rpc.response.status_code", "query SELECT", "[span]"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q did not arrive", want)
		}
	}
	if strings.Contains(got, canary) {
		t.Fatalf("a canary reached the collector: %s", got)
	}
	if n := baggageSeen.Load(); n != 0 {
		t.Fatalf("handler saw %d baggage members", n)
	}
}
