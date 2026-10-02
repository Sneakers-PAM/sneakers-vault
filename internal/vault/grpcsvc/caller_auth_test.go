// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"net"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/workloadid/oidctest"
	"github.com/Sneakers-PAM/sneakers-vault/internal/workloadauth"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

// The vault behind the workload-auth interceptors, over a real gRPC
// connection: the caller is known from its token, not from what it sends.

const authNS = "sneakers"

type authFixture struct {
	s      *Server
	ca     *capAudit
	iss    *oidctest.Issuer
	client vaultv1.VaultServiceClient
	secret string
	folder string
}

func newAuthFixture(t *testing.T) *authFixture {
	t.Helper()
	iss := oidctest.NewIssuer(t)
	var allowed []string
	for _, c := range []string{"gateway", "workflow", "sshbroker", "connector", "mcp"} {
		allowed = append(allowed, authNS+"/sneakers-"+c)
	}
	v, err := workloadauth.NewVerifier(workloadauth.Config{Issuer: iss.URL, CAFile: iss.CAFile, AllowedServiceAccounts: allowed}, log.Nop())
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)
	created, err := s.CreateSecret(context.Background(), &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "api token", FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "Sup3r$ecret"},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer(grpc.ChainUnaryInterceptor(
		RequestContextUnary,
		workloadauth.UnaryServerInterceptor(v, CallerPolicy(), log.Nop(), workloadauth.WithDenyHook(s.AuditDenial)),
		s.SelfActorUnary,
	))
	vaultv1.RegisterVaultServiceServer(gs, s)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &authFixture{s: s, ca: ca, iss: iss, client: vaultv1.NewVaultServiceClient(conn), secret: created.GetSecret().GetId(), folder: fid}
}

// as returns a context carrying a valid token for the service account
// sneakers-<caller>.
func (f *authFixture) as(t *testing.T, caller string) context.Context {
	t.Helper()
	tok := f.iss.Sign(t, "rsa-1", "rsa-1", jwt.SigningMethodRS256,
		oidctest.ServiceAccountClaims(f.iss.URL, workloadauth.DefaultAudience, authNS, "sneakers-"+caller, time.Now()))
	return metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+tok)
}

func (f *authFixture) reveal(ctx context.Context, actor *vaultv1.ActorContext) (*vaultv1.RevealSecretFieldResponse, error) {
	return f.client.RevealSecretField(ctx, &vaultv1.RevealSecretFieldRequest{Actor: actor, Id: f.secret, FieldKey: "password"})
}

func TestCallerAuth_UnlistedPodIsRefusedEvenWithAValidToken(t *testing.T) {
	f := newAuthFixture(t)
	_, err := f.reveal(f.as(t, "mcp"), &vaultv1.ActorContext{UserId: "made-up", IsRoot: true})
	wantCode(t, err, codes.PermissionDenied)
	ev := f.ca.find("rpc.denied")
	if ev == nil {
		t.Fatal("the refusal was not audited")
	}
	a := ev.Attributes
	if ev.ActorUserID != "service:mcp" || a["method"] != vaultv1.VaultService_RevealSecretField_FullMethodName ||
		a["claimed_user_id"] != "made-up" || a["claimed_root"] != "true" || a["code"] != codes.PermissionDenied.String() {
		t.Fatalf("audit = %+v", ev)
	}
	if ev.Subject == "made-up" {
		t.Fatal("the refusal must not be recorded under the claimed user")
	}
}

func TestCallerAuth_GatewayPassesTheUser(t *testing.T) {
	f := newAuthFixture(t)
	rev, err := f.reveal(f.as(t, "gateway"), &vaultv1.ActorContext{UserId: "user-carol"})
	if err != nil || rev.GetValue() != "Sup3r$ecret" {
		t.Fatalf("gateway reveal: %v %q", err, rev.GetValue())
	}
	_, err = f.reveal(f.as(t, "gateway"), &vaultv1.ActorContext{UserId: "user-nobody"})
	wantCode(t, err, codes.PermissionDenied)
}

func TestCallerAuth_SSHBrokerPassesTheSessionUser(t *testing.T) {
	f := newAuthFixture(t)
	if _, err := f.reveal(f.as(t, "sshbroker"), &vaultv1.ActorContext{UserId: "user-carol"}); err != nil {
		t.Fatalf("sshbroker reveal: %v", err)
	}
	_, err := f.client.ListFolders(f.as(t, "sshbroker"), &vaultv1.ListFoldersRequest{Actor: &vaultv1.ActorContext{UserId: "user-carol"}})
	wantCode(t, err, codes.PermissionDenied)
}

func TestCallerAuth_WorkflowActsOnlyAsItself(t *testing.T) {
	f := newAuthFixture(t)
	_, err := f.client.GetSecretRuleset(f.as(t, "workflow"), &vaultv1.GetSecretRulesetRequest{
		Actor: &vaultv1.ActorContext{UserId: "system", IsRoot: true}, SecretId: f.secret,
	})
	wantCode(t, err, codes.PermissionDenied)
	if ev := f.ca.find("rpc.denied"); ev == nil || ev.Attributes["reason"] != workloadauth.ReasonActorNotAllowed {
		t.Fatalf("audit = %+v", ev)
	}

	rs, err := f.client.GetSecretRuleset(f.as(t, "workflow"), &vaultv1.GetSecretRulesetRequest{SecretId: f.secret})
	if err != nil {
		t.Fatalf("workflow as itself: %v", err)
	}
	if _, err := f.client.SetSecretRuleset(f.as(t, "workflow"), &vaultv1.SetSecretRulesetRequest{
		SecretId: f.secret, Rules: append(rs.GetRules(), &vaultv1.RaciRule{
			SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-dave", Grants: map[string]string{"C": "allow"},
		}),
	}); err != nil {
		t.Fatalf("workflow grant: %v", err)
	}
	if _, err := f.reveal(f.as(t, "gateway"), &vaultv1.ActorContext{UserId: "user-dave"}); err != nil {
		t.Fatalf("the workflow's grant did not apply: %v", err)
	}

	_, err = f.reveal(f.as(t, "workflow"), nil)
	wantCode(t, err, codes.PermissionDenied)
}

func TestCallerAuth_ConnectorOnlyReachesThePullAPI(t *testing.T) {
	f := newAuthFixture(t)
	_, err := f.reveal(f.as(t, "connector"), nil)
	wantCode(t, err, codes.PermissionDenied)
}

func TestCallerAuth_NoTokenIsUnauthenticated(t *testing.T) {
	f := newAuthFixture(t)
	_, err := f.reveal(context.Background(), &vaultv1.ActorContext{UserId: "user-carol"})
	wantCode(t, err, codes.Unauthenticated)
	if ev := f.ca.find("rpc.denied"); ev == nil || ev.ActorUserID != "service:unauthenticated" {
		t.Fatalf("audit = %+v", ev)
	}
}

func TestCallerAuth_ServiceAccountOffTheListIsUnauthenticated(t *testing.T) {
	f := newAuthFixture(t)
	_, err := f.reveal(f.as(t, "identity"), &vaultv1.ActorContext{UserId: "user-carol", IsRoot: true})
	wantCode(t, err, codes.Unauthenticated)
	if ev := f.ca.find("rpc.denied"); ev == nil || ev.Attributes["claimed_root"] != "true" {
		t.Fatalf("audit = %+v", ev)
	}
}
