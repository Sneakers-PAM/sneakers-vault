// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strings"
	"testing"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"github.com/Sneakers-PAM/sneakers-vault/internal/vault/audit"
	"github.com/google/uuid"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Prior values sit behind the recovery role plus a fresh MFA: an old
// password may still work on a target that wasn't rotated.

var recoveryNow = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func recoveryUser(id string) *vaultv1.ActorContext {
	return &vaultv1.ActorContext{UserId: id, IsRecovery: true, MfaVerifiedAtUnix: recoveryNow.Add(-time.Minute).Unix()}
}

type recoveryFixture struct {
	s   *Server
	ra  *recordingAuditor
	sid string
}

// newRecoveryFixture: carol owns a secret with two versions, v1 password
// "old-pw" and v2 (current) "new-pw".
func newRecoveryFixture(t *testing.T) recoveryFixture {
	t.Helper()
	s := newServerWithVersions(t)
	ra := &recordingAuditor{}
	s.audit = ra
	s.now = func() time.Time { return recoveryNow }
	ctx := context.Background()
	carol := &vaultv1.ActorContext{UserId: "user-carol"}
	fid := newSharedFolder(t, s)
	created, err := s.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor: carol, Name: "db-" + uuid.NewString(), FolderId: fid, TypeId: "type-password",
		Fields: map[string]string{"username": "svc", "password": "old-pw"},
	})
	if err != nil {
		t.Fatal(err)
	}
	sid := created.GetSecret().GetId()
	if _, err := s.UpdateSecret(ctx, &vaultv1.UpdateSecretRequest{Actor: carol, Id: sid, Fields: map[string]string{"password": "new-pw"}}); err != nil {
		t.Fatal(err)
	}
	return recoveryFixture{s: s, ra: ra, sid: sid}
}

func reasonOf(t *testing.T, err error, want codes.Code) string {
	t.Helper()
	if status.Code(err) != want {
		t.Fatalf("err %v, want %v", err, want)
	}
	for _, d := range status.Convert(err).Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetDomain() == "sneakers.vault" {
			return info.GetReason()
		}
	}
	t.Fatalf("no sneakers.vault ErrorInfo on %v", err)
	return ""
}

func refusedRecoveryActors() map[string]struct {
	actor  *vaultv1.ActorContext
	reason string
} {
	stale := recoveryUser("user-carol")
	stale.MfaVerifiedAtUnix = recoveryNow.Add(-31 * time.Minute).Unix()
	noMFA := recoveryUser("user-carol")
	noMFA.MfaVerifiedAtUnix = 0
	future := recoveryUser("user-carol")
	future.MfaVerifiedAtUnix = recoveryNow.Add(10 * time.Minute).Unix()
	admin := &vaultv1.ActorContext{UserId: "user-carol", IsSiteAdmin: true, IsRoot: true, MfaVerifiedAtUnix: recoveryNow.Unix()}
	sa := recoveryUser("")
	sa.PrincipalKind, sa.PrincipalId = vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, "sa-x"
	tok := recoveryUser("user-carol")
	tok.PrincipalKind = vaultv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN
	noID := recoveryUser("")
	return map[string]struct {
		actor  *vaultv1.ActorContext
		reason string
	}{
		"ordinary reader":     {&vaultv1.ActorContext{UserId: "user-carol", MfaVerifiedAtUnix: recoveryNow.Unix()}, ReasonRecoveryRoleRequired},
		"site admin and root": {admin, ReasonRecoveryRoleRequired},
		"service account":     {sa, ReasonRecoveryRoleRequired},
		"user token":          {tok, ReasonRecoveryRoleRequired},
		"no user id":          {noID, ReasonRecoveryRoleRequired},
		"stale MFA":           {stale, ReasonStepUpRequired},
		"no MFA":              {noMFA, ReasonStepUpRequired},
		"MFA in the future":   {future, ReasonStepUpRequired},
	}
}

func TestRevealingAPriorVersionNeedsRecoveryAndFreshMFA(t *testing.T) {
	fx := newRecoveryFixture(t)
	ctx := context.Background()
	for name, c := range refusedRecoveryActors() {
		_, err := fx.s.RevealSecretVersionField(ctx, &vaultv1.RevealSecretVersionFieldRequest{Actor: c.actor, SecretId: fx.sid, VersionNo: 1, FieldKey: "password"})
		if got := reasonOf(t, err, codes.PermissionDenied); got != c.reason {
			t.Fatalf("%s: reason %q, want %s", name, got, c.reason)
		}
		ev := fx.ra.find("recovery.denied")
		if ev == nil || ev.Attributes["reason"] != c.reason || ev.Attributes["method"] != "RevealSecretVersionField" {
			t.Fatalf("%s: audit = %+v", name, ev)
		}
		fx.ra.events = nil
	}
	rev, err := fx.s.RevealSecretVersionField(ctx, &vaultv1.RevealSecretVersionFieldRequest{Actor: recoveryUser("user-carol"), SecretId: fx.sid, VersionNo: 1, FieldKey: "password"})
	if err != nil || rev.GetValue() != "old-pw" {
		t.Fatalf("recovery reveal = %q, %v", rev.GetValue(), err)
	}
	ev := fx.ra.find("secret.version.reveal")
	if ev == nil || ev.Tier != audit.TierAudit || !ev.Sensitive {
		t.Fatalf("reveal audit = %+v, want the audit tier, sensitive", ev)
	}
}

func TestRecoveryStillNeedsReadOnTheSecret(t *testing.T) {
	fx := newRecoveryFixture(t)
	_, err := fx.s.RevealSecretVersionField(context.Background(), &vaultv1.RevealSecretVersionFieldRequest{
		Actor: recoveryUser("user-nobody"), SecretId: fx.sid, VersionNo: 1, FieldKey: "password"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err %v, want PermissionDenied", err)
	}
}

func TestOrdinaryReadersSeeTheChangeListWithoutValues(t *testing.T) {
	fx := newRecoveryFixture(t)
	list, err := fx.s.ListSecretVersions(context.Background(), &vaultv1.ListSecretVersionsRequest{Actor: &vaultv1.ActorContext{UserId: "user-carol"}, SecretId: fx.sid})
	if err != nil || len(list.GetVersions()) != 2 {
		t.Fatalf("list = %v, %v", list, err)
	}
	for _, v := range list.GetVersions() {
		if strings.Contains(v.String(), "pw") {
			t.Fatalf("a value leaked into the change list: %v", v)
		}
	}
	sa := &vaultv1.ActorContext{PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT, PrincipalId: "sa-x", IsSiteAdmin: true}
	if _, err := fx.s.ListSecretVersions(context.Background(), &vaultv1.ListSecretVersionsRequest{Actor: sa, SecretId: fx.sid}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("service account listed history: %v", err)
	}
}

func TestRestoreMakesAPriorVersionCurrent(t *testing.T) {
	fx := newRecoveryFixture(t)
	ctx := context.Background()
	fx.s.findSecret(fx.sid).TargetId = "target-x"
	resp, err := fx.s.RestoreSecretVersion(ctx, &vaultv1.RestoreSecretVersionRequest{Actor: recoveryUser("user-carol"), SecretId: fx.sid, VersionNo: 1})
	if err != nil {
		t.Fatal(err)
	}
	cur, err := fx.s.RevealSecretField(ctx, &vaultv1.RevealSecretFieldRequest{Actor: &vaultv1.ActorContext{UserId: "user-carol"}, Id: fx.sid, FieldKey: "password"})
	if err != nil || cur.GetValue() != "old-pw" {
		t.Fatalf("current after restore = %q, %v", cur.GetValue(), err)
	}
	list, _ := fx.s.ListSecretVersions(ctx, &vaultv1.ListSecretVersionsRequest{Actor: &vaultv1.ActorContext{UserId: "user-carol"}, SecretId: fx.sid})
	if v := list.GetVersions(); len(v) != 3 || v[0].GetVersionNo() != 3 || !v[0].GetActive() || v[0].GetCreatedBy() != "user-carol" {
		t.Fatalf("versions after restore = %v", v)
	}
	ev := fx.ra.find("secret.version.restore")
	if ev == nil || ev.Tier != audit.TierAudit || ev.ActorUserID != "user-carol" || ev.Subject != fx.sid ||
		ev.Attributes["version_no"] != "1" || ev.Attributes["new_version_no"] != "3" {
		t.Fatalf("restore audit = %+v", ev)
	}
	for k, v := range ev.Attributes {
		if strings.Contains(v, "pw") {
			t.Fatalf("a value leaked into the audit (%s=%s)", k, v)
		}
	}
	sec := resp.GetSecret()
	if sec.GetLastHeartbeatResult() != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNKNOWN || !strings.Contains(sec.GetLastHeartbeatDetail(), "restored") {
		t.Fatalf("target not marked out of sync: %v %q", sec.GetLastHeartbeatResult(), sec.GetLastHeartbeatDetail())
	}
}

func TestRestoreIsRefusedWithoutRecoveryOrFreshMFA(t *testing.T) {
	fx := newRecoveryFixture(t)
	for name, c := range refusedRecoveryActors() {
		_, err := fx.s.RestoreSecretVersion(context.Background(), &vaultv1.RestoreSecretVersionRequest{Actor: c.actor, SecretId: fx.sid, VersionNo: 1})
		if got := reasonOf(t, err, codes.PermissionDenied); got != c.reason {
			t.Fatalf("%s: reason %q, want %s", name, got, c.reason)
		}
		if ev := fx.ra.find("recovery.denied"); ev == nil || ev.Attributes["method"] != "RestoreSecretVersion" {
			t.Fatalf("%s: audit = %+v", name, ev)
		}
		fx.ra.events = nil
	}
	if fx.ra.find("secret.version.restore") != nil {
		t.Fatal("a refused restore was audited as done")
	}
}

func TestRestoreIsRefusedWhileARotationIsQueued(t *testing.T) {
	fx := newRecoveryFixture(t)
	fx.s.rot = newRotationStore(rotTestPool(t).Querier())
	if err := fx.s.rot.Enqueue(context.Background(), fx.sid, "manual", 0); err != nil {
		t.Fatal(err)
	}
	_, err := fx.s.RestoreSecretVersion(context.Background(), &vaultv1.RestoreSecretVersionRequest{Actor: recoveryUser("user-carol"), SecretId: fx.sid, VersionNo: 1})
	if got := reasonOf(t, err, codes.FailedPrecondition); got != ReasonRotationInProgress {
		t.Fatalf("reason %q", got)
	}
}

func TestRestoringTheCurrentOrAMissingVersion(t *testing.T) {
	fx := newRecoveryFixture(t)
	ctx := context.Background()
	if _, err := fx.s.RestoreSecretVersion(ctx, &vaultv1.RestoreSecretVersionRequest{Actor: recoveryUser("user-carol"), SecretId: fx.sid, VersionNo: 2}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("restore current: %v", err)
	}
	if _, err := fx.s.RestoreSecretVersion(ctx, &vaultv1.RestoreSecretVersionRequest{Actor: recoveryUser("user-carol"), SecretId: fx.sid, VersionNo: 99}); status.Code(err) != codes.NotFound {
		t.Fatalf("restore missing: %v", err)
	}
}
