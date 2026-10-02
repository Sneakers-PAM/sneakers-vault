// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strings"
	"testing"
	"time"

	postgres "github.com/Bugs5382/go-postgres"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
)

// A machine may change a secret's type into or out of a
// rotation/heartbeat type or the certificate type. The value rules (no silent
// discard, sensitive only into sensitive, version history, audit) still hold,
// and the automation follows defined rules:
//   - into a rotation type: rotation is opted out until explicitly enabled;
//   - heartbeat follows the type only when the secret has a reachable target;
//   - out of a rotation/heartbeat type: its schedule rows (and their claims) go;
//   - a target stays when the new type takes one, otherwise it is detached;
//   - into the certificate type: the cert/key fields must parse as an import's.

type retypeFixture struct {
	s      *Server
	ca     *capAudit
	pool   *postgres.DB
	folder string
	target string
}

func newRetypeFixture(t *testing.T) *retypeFixture {
	t.Helper()
	_, pool := organizeFreshDB(t)
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	s.SetHeartbeat(pool, nil)
	s.SetRotation(pool, nil)
	s.vers = newVersionStore(pool)
	f := authorFolder(t, s)
	tgt, _ := reachableTarget(t, s)
	return &retypeFixture{s: s, ca: ca, pool: pool, folder: f, target: tgt}
}

func (fx *retypeFixture) rows(t *testing.T, table, id string) int {
	t.Helper()
	var n int
	if err := fx.pool.Querier().QueryRow(context.Background(), `SELECT count(*) FROM `+table+` WHERE secret_id=$1`, id).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func attachTarget(t *testing.T, s *Server, id, target string) {
	t.Helper()
	if _, err := s.SetSecretTargetForPrincipal(context.Background(), &vaultv1.SetSecretTargetForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), SecretId: id, TargetId: target,
	}); err != nil {
		t.Fatalf("attach target: %v", err)
	}
}

func intoAD(t *testing.T, s *Server, id string) *vaultv1.ChangeSecretTypeForPrincipalResponse {
	t.Helper()
	resp, err := s.ChangeSecretTypeForPrincipal(context.Background(), &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: "type-active-directory",
		Fields: map[string]string{"domain": "corp.example.test"},
	})
	if err != nil {
		t.Fatalf("into active-directory: %v", err)
	}
	return resp
}

func TestChangeSecretType_IntoADMapsValuesAndLeavesRotationOff(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	f := authorFolder(t, s)
	tgt, _ := reachableTarget(t, s)
	id := mutSecret(t, s, f)
	attachTarget(t, s, id, tgt)

	resp := intoAD(t, s, id)

	want := map[string]string{"username": mutUser, "password": mutPass, "notes": mutNote, "domain": "corp.example.test"}
	if got := openFields(t, s, id); !stringMapsEqual(got, want) {
		t.Fatalf("stored fields = %v, want %v", keysOf(got), keysOf(want))
	}
	sec := resp.GetSecret()
	if sec.GetTypeId() != "type-active-directory" || !sec.GetRotationOptOut() || sec.GetHeartbeatOptOut() {
		t.Fatalf("secret after retype: type=%q rotation_opt_out=%v heartbeat_opt_out=%v", sec.GetTypeId(), sec.GetRotationOptOut(), sec.GetHeartbeatOptOut())
	}
	if sec.GetTargetId() != tgt {
		t.Fatalf("target = %q, want it kept (%q)", sec.GetTargetId(), tgt)
	}
	ev := ca.find("secret.type_change.principal")
	if ev == nil {
		t.Fatal("expected a secret.type_change.principal audit event")
	}
	for k, v := range map[string]string{"rotation": "off", "heartbeat": "scheduled", "target": "kept", "target_id": tgt} {
		if ev.Attributes[k] != v {
			t.Fatalf("audit %s = %q, want %q (all: %v)", k, ev.Attributes[k], v, ev.Attributes)
		}
	}
}

func TestChangeSecretType_OutOfADIsAllowedAndDetachesTarget(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	f := authorFolder(t, s)
	tgt, _ := reachableTarget(t, s)
	id := retypeSecret(t, s, f, "type-active-directory", map[string]string{"domain": "corp.example.test", "username": mutUser, "password": mutPass, "notes": mutNote})
	attachTarget(t, s, id, tgt)

	resp, err := s.ChangeSecretTypeForPrincipal(context.Background(), &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: "type-password",
	})
	if err != nil {
		t.Fatalf("out of active-directory: %v", err)
	}
	if resp.GetSecret().GetTypeId() != "type-password" || resp.GetSecret().GetTargetId() != "" {
		t.Fatalf("type=%q target=%q, want type-password with the target detached", resp.GetSecret().GetTypeId(), resp.GetSecret().GetTargetId())
	}
	got := openFields(t, s, id)
	if got["username"] != mutUser || got["password"] != mutPass || !strings.Contains(got["notes"], `[moved from domain]: "corp.example.test"`) {
		t.Fatalf("values not carried: keys %v", keysOf(got))
	}
	ev := ca.find("secret.type_change.principal")
	if ev == nil || ev.Attributes["target"] != "detached" || ev.Attributes["from_target_id"] != tgt ||
		ev.Attributes["rotation"] != "none" || ev.Attributes["heartbeat"] != "none" {
		t.Fatalf("audit = %+v", ev)
	}
}

func TestChangeSecretType_ValueRulesStillHoldForManagedTypes(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	f := authorFolder(t, s)
	ctx := context.Background()
	sa := agentGroupActor("sa-1")
	// netbios has no field under type-windows-domain, which has no notes field.
	id := retypeSecret(t, s, f, "type-active-directory", map[string]string{"domain": "corp.example.test", "netbios": "CORP", "username": mutUser, "password": mutPass})

	cases := []struct {
		name string
		req  *vaultv1.ChangeSecretTypeForPrincipalRequest
	}{
		{"sensitive value into a non-sensitive field", &vaultv1.ChangeSecretTypeForPrincipalRequest{
			Actor: sa, Id: id, NewTypeId: "type-password", FieldMapping: map[string]string{"password": "notes"},
			Fields: map[string]string{"password": "replacement"},
		}},
		{"unmapped value under the refuse policy", &vaultv1.ChangeSecretTypeForPrincipalRequest{
			Actor: sa, Id: id, NewTypeId: "type-password",
			UnmappedFields: vaultv1.UnmappedFieldPolicy_UNMAPPED_FIELD_POLICY_REFUSE,
		}},
		{"unmapped value with no notes field to receive it", &vaultv1.ChangeSecretTypeForPrincipalRequest{
			Actor: sa, Id: id, NewTypeId: "type-windows-domain",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.ChangeSecretTypeForPrincipal(ctx, tc.req)
			if code(err) != codes.FailedPrecondition {
				t.Fatalf("want FailedPrecondition, got %v", err)
			}
			assertNoValueLeak(t, err)
			if s.findSecret(id).GetTypeId() != "type-active-directory" || ca.find("secret.type_change.principal") != nil {
				t.Fatal("a refused type change must not change or audit anything")
			}
		})
	}
}

// ---- certificate type --------------------------------------------------------

func TestChangeSecretType_IntoCertificateValidatesLikeImport(t *testing.T) {
	s := newServer(t)
	ca := &capAudit{}
	s.audit = ca
	f := authorFolder(t, s)
	tc := makeCertTestChain(t)
	certPEM, keyPEM := string(tc.leafPEM()), string(tc.keyPEM(t))
	id := retypeSecret(t, s, f, "type-password", map[string]string{"username": mutUser, "password": keyPEM, "notes": certPEM})

	resp, err := s.ChangeSecretTypeForPrincipal(context.Background(), &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: certSecretTypeID,
		FieldMapping: map[string]string{"notes": "certificate", "password": "privateKey"},
	})
	if err != nil {
		t.Fatalf("into certificate: %v", err)
	}
	got := openFields(t, s, id)
	if got["certificate"] != certPEM || got["privateKey"] != keyPEM {
		t.Fatal("certificate and key must be carried verbatim")
	}
	if got["subject"] == "" || !strings.Contains(got["subject"], "leaf.example.com") || got["hasPrivateKey"] != "true" || got["notAfter"] == "" {
		t.Fatalf("derived metadata missing: subject=%q hasPrivateKey=%q notAfter=%q", got["subject"], got["hasPrivateKey"], got["notAfter"])
	}
	if !strings.Contains(got["notes"], "[moved from username]") {
		t.Fatalf("unmapped username must move into notes, notes=%q", got["notes"])
	}
	if exp := resp.GetSecret().GetExpiresAt(); exp != tc.LeafCert.NotAfter.UTC().Format(time.RFC3339) {
		t.Fatalf("expires_at = %q, want the certificate's NotAfter", exp)
	}
	if ca.find("secret.type_change.principal") == nil {
		t.Fatal("expected a secret.type_change.principal audit event")
	}
}

func TestChangeSecretType_IntoCertificateRefusesBadMaterial(t *testing.T) {
	tc := makeCertTestChain(t)
	certPEM, keyPEM := string(tc.leafPEM()), string(tc.keyPEM(t))
	cases := []struct {
		name       string
		cert, key  string
		wantCode   codes.Code
		wantInText string
	}{
		{"certificate is not a certificate", "not a certificate", keyPEM, codes.InvalidArgument, "certificate"},
		{"key is not a private key", certPEM, "not a key", codes.InvalidArgument, "privateKey"},
		{"key field holds a certificate", certPEM, certPEM, codes.InvalidArgument, "privateKey"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newServer(t)
			ca := &capAudit{}
			s.audit = ca
			f := authorFolder(t, s)
			id := retypeSecret(t, s, f, "type-password", map[string]string{"username": mutUser, "password": c.key, "notes": c.cert})
			_, err := s.ChangeSecretTypeForPrincipal(context.Background(), &vaultv1.ChangeSecretTypeForPrincipalRequest{
				Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: certSecretTypeID,
				FieldMapping: map[string]string{"notes": "certificate", "password": "privateKey"},
			})
			if code(err) != c.wantCode || !strings.Contains(err.Error(), c.wantInText) {
				t.Fatalf("want %v naming %q, got %v", c.wantCode, c.wantInText, err)
			}
			if strings.Contains(err.Error(), "BEGIN") || strings.Contains(err.Error(), mutUser) {
				t.Fatalf("error leaks a value: %v", err)
			}
			if s.findSecret(id).GetTypeId() != "type-password" || ca.find("secret.type_change.principal") != nil {
				t.Fatal("a refused type change must not change or audit anything")
			}
		})
	}
}

func TestChangeSecretType_OutOfCertificateKeepsKeyProtected(t *testing.T) {
	s, _, fid := newCertTestServer(t)
	grantGroup(t, s, orgCarol, fid, "R")
	ctx := context.Background()
	tc := makeCertTestChain(t)
	keyPEM := string(tc.keyPEM(t))
	id := importedCertSecret(t, s, fid, tc, append(tc.leafPEM(), tc.keyPEM(t)...), "")

	// A less-protected home for the super-sensitive key is refused.
	if _, err := s.ChangeSecretTypeForPrincipal(ctx, &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: "type-secure-note",
	}); code(err) != codes.FailedPrecondition {
		t.Fatalf("cert -> secure note: want FailedPrecondition, got %v", err)
	}

	pem, err := s.CreateSecretType(ctx, &vaultv1.CreateSecretTypeRequest{Actor: &vaultv1.ActorContext{UserId: "user-carol", IsSiteAdmin: true}, Type: &vaultv1.SecretType{
		Name: "PEM bundle", Fields: []*vaultv1.SecretFieldDef{
			{Key: "certificate", Kind: vaultv1.FieldKind_FIELD_KIND_MULTILINE},
			{Key: "privateKey", Kind: vaultv1.FieldKind_FIELD_KIND_SENSITIVE, Sensitive: true, SuperSensitive: true},
			{Key: "notes", Kind: vaultv1.FieldKind_FIELD_KIND_MULTILINE},
		},
	}})
	if err != nil {
		t.Fatalf("CreateSecretType: %v", err)
	}
	if _, err := s.ChangeSecretTypeForPrincipal(ctx, &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: pem.GetType().GetId(),
	}); err != nil {
		t.Fatalf("cert -> PEM bundle: %v", err)
	}
	got := openFields(t, s, id)
	if got["privateKey"] != keyPEM || !strings.Contains(got["certificate"], "BEGIN CERTIFICATE") {
		t.Fatal("PEM and key must be kept")
	}
	if !strings.Contains(got["notes"], "[moved from subject]") {
		t.Fatalf("derived metadata must move into notes, notes=%q", got["notes"])
	}
}

// ---- schedules (Postgres) ----------------------------------------------------

func TestChangeSecretType_IntoADWithTargetHeartbeatsButDoesNotRotate_Postgres(t *testing.T) {
	fx := newRetypeFixture(t)
	ctx := context.Background()
	id := mutSecret(t, fx.s, fx.folder)
	attachTarget(t, fx.s, id, fx.target)

	intoAD(t, fx.s, id)

	if n := fx.rows(t, "rotation_schedule", id); n != 0 {
		t.Fatalf("rotation_schedule rows = %d, want 0 until rotation is enabled", n)
	}
	if n := fx.rows(t, "heartbeat_schedule", id); n != 1 {
		t.Fatalf("heartbeat_schedule rows = %d, want 1 (the secret has a target)", n)
	}
	if _, err := fx.s.SetSecretAutomationForPrincipal(ctx, &vaultv1.SetSecretAutomationForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), SecretId: id,
	}); err != nil {
		t.Fatalf("enable rotation: %v", err)
	}
	if n := fx.rows(t, "rotation_schedule", id); n != 1 {
		t.Fatalf("rotation_schedule rows after opting in = %d, want 1", n)
	}
}

func TestChangeSecretType_IntoADWithoutTargetSchedulesNothing_Postgres(t *testing.T) {
	fx := newRetypeFixture(t)
	id := mutSecret(t, fx.s, fx.folder)

	resp := intoAD(t, fx.s, id)

	if n := fx.rows(t, "heartbeat_schedule", id); n != 0 {
		t.Fatalf("heartbeat_schedule rows = %d, want 0 for a secret with no target", n)
	}
	if n := fx.rows(t, "rotation_schedule", id); n != 0 {
		t.Fatalf("rotation_schedule rows = %d, want 0", n)
	}
	if !resp.GetSecret().GetRotationOptOut() {
		t.Fatal("rotation must be opted out after converting into a rotation type")
	}
	ev := fx.ca.find("secret.type_change.principal")
	if ev == nil || ev.Attributes["heartbeat"] != "no_target" || ev.Attributes["target"] != "none" {
		t.Fatalf("audit = %+v", ev)
	}
}

func TestChangeSecretType_OutOfADRemovesSchedulesAndClaims_Postgres(t *testing.T) {
	fx := newRetypeFixture(t)
	ctx := context.Background()
	c, err := fx.s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: orgCarol, Name: "ad", FolderId: fx.folder, TypeId: "type-active-directory", TargetId: fx.target,
		Fields: map[string]string{"domain": "corp.example.test", "username": mutUser, "password": mutPass},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	id := c.GetSecret().GetId()
	if fx.rows(t, "rotation_schedule", id) != 1 || fx.rows(t, "heartbeat_schedule", id) != 1 {
		t.Fatal("precondition: an AD secret with a target is rotation- and heartbeat-scheduled")
	}
	// A heartbeat claim in flight: the row (and with it the claim) must go.
	if _, err := fx.pool.Querier().Exec(ctx, `UPDATE heartbeat_schedule SET claimed_until = now() + interval '5 minutes' WHERE secret_id=$1`, id); err != nil {
		t.Fatal(err)
	}

	if _, err := fx.s.ChangeSecretTypeForPrincipal(ctx, &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: "type-password",
	}); err != nil {
		t.Fatalf("out of active-directory: %v", err)
	}
	if n := fx.rows(t, "rotation_schedule", id); n != 0 {
		t.Fatalf("rotation_schedule rows = %d, want 0", n)
	}
	if n := fx.rows(t, "heartbeat_schedule", id); n != 0 {
		t.Fatalf("heartbeat_schedule rows = %d, want 0", n)
	}
}

func TestChangeSecretType_RefusedWhileARotationIsInFlight_Postgres(t *testing.T) {
	fx := newRetypeFixture(t)
	ctx := context.Background()
	c, err := fx.s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: orgCarol, Name: "ad", FolderId: fx.folder, TypeId: "type-active-directory", TargetId: fx.target,
		Fields: map[string]string{"domain": "corp.example.test", "username": mutUser, "password": mutPass},
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	id := c.GetSecret().GetId()
	if _, err := fx.pool.Querier().Exec(ctx, `UPDATE rotation_schedule SET claimed_until = now() + interval '5 minutes' WHERE secret_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	_, err = fx.s.ChangeSecretTypeForPrincipal(ctx, &vaultv1.ChangeSecretTypeForPrincipalRequest{
		Actor: agentGroupActor("sa-1"), Id: id, NewTypeId: "type-password",
	})
	if code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "rotation") {
		t.Fatalf("want FailedPrecondition naming the rotation, got %v", err)
	}
	if fx.s.findSecret(id).GetTypeId() != "type-active-directory" || fx.rows(t, "rotation_schedule", id) != 1 {
		t.Fatal("a refused type change must leave the secret and its schedule untouched")
	}
}

func TestChangeSecretType_KeepsVersionHistory_Postgres(t *testing.T) {
	fx := newRetypeFixture(t)
	ctx := context.Background()
	id := mutSecret(t, fx.s, fx.folder)

	intoAD(t, fx.s, id)

	prev, ok, err := fx.s.vers.LoadVersion(ctx, id, 1)
	if err != nil || !ok {
		t.Fatalf("LoadVersion(1): ok=%v err=%v", ok, err)
	}
	old, err := fx.s.crypt.OpenAll(prev)
	if err != nil {
		t.Fatalf("open v1: %v", err)
	}
	if old["password"] != mutPass || old["domain"] != "" {
		t.Fatal("version 1 must hold the values from before the type change")
	}
	cur, ok, err := fx.s.vers.ActiveRecord(ctx, id)
	if err != nil || !ok {
		t.Fatalf("ActiveRecord: ok=%v err=%v", ok, err)
	}
	now, err := fx.s.crypt.OpenAll(cur)
	if err != nil || now["domain"] != "corp.example.test" || now["password"] != mutPass {
		t.Fatalf("active version after the type change is wrong (err=%v)", err)
	}
}
