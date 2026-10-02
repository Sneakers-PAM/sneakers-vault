// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"strconv"
	"time"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	seed "github.com/Bugs5382/go-seed"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// appLog is a package-level logger so it's addressable (go-log's Info/Fatal are
// pointer methods and cannot be called on a chained log.New(...) return value).
var appLog = log.New("seedbulk")

// sharedFolders is the fixed set of top-level shared folders the bulk secrets are
// spread across (distinct from the requests demo's "Production Servers" folder,
// which this tool never touches).
var sharedFolders = []string{
	"Production", "Staging", "Databases", "Network Devices", "Cloud",
	"Windows Servers", "Linux Servers", "Finance", "HR", "Kubernetes",
}

// the three seeded default connections, bound round-robin by the targets step.
var connIDs = []string{"conn-ssh-default", "conn-winrm-default", "conn-ldaps"}

const targetCount = 30

// seeder is the go-seed target: the gRPC client + Postgres pool plus the state earlier
// steps populate for later ones.
type seeder struct {
	vc     vaultv1.VaultServiceClient
	pool   postgres.Querier
	alan   *vaultv1.ActorContext
	rng    *mrand.Rand
	target int

	folderIDs  []string          // ids of the shared folders (order = sharedFolders)
	folderName map[string]string // folder id -> name (for plausible hostnames)
	targetIDs  []string          // ids of the created targets
	types      []*vaultv1.SecretType
	hbTypes    map[string]bool // type ids whose type heartbeats
	rotTypes   map[string]bool // type ids whose type rotates
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *seeder) pick(xs []string) string { return xs[s.rng.Intn(len(xs))] }

// ---- Step 1: shared folders -------------------------------------------------

func (s *seeder) findFolder(ctx context.Context, name string) (string, error) {
	resp, err := s.vc.ListFolders(ctx, &vaultv1.ListFoldersRequest{Actor: s.alan})
	if err != nil {
		return "", err
	}
	for _, f := range resp.GetFolders() {
		// Only match top-level shared folders (no parent, not personal-scoped).
		if f.GetName() == name && f.GetParentId() == "" && f.GetScope() != vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL {
			return f.GetId(), nil
		}
	}
	return "", nil
}

func folderStep(name string) seed.Step[*seeder] {
	return seed.Step[*seeder]{
		Name: "folder:" + name,
		Apply: func(ctx context.Context, s *seeder) error {
			id, err := s.findFolder(ctx, name)
			if err != nil {
				return err
			}
			if id == "" {
				r, err := s.vc.CreateFolder(ctx, &vaultv1.CreateFolderRequest{Actor: s.alan, Name: name})
				if err != nil {
					return err
				}
				id = r.GetFolder().GetId()
				if _, err := s.vc.SetFolderRuleset(ctx, &vaultv1.SetFolderRulesetRequest{
					Actor: s.alan, FolderId: id, Owners: []string{"user-turing"},
				}); err != nil {
					return err
				}
			}
			s.folderIDs = append(s.folderIDs, id)
			s.folderName[id] = name
			return nil
		},
		Assert: func(ctx context.Context, s *seeder) error {
			id, err := s.findFolder(ctx, name)
			if err != nil {
				return err
			}
			if id == "" {
				return fmt.Errorf("folder %q not created", name)
			}
			return nil
		},
	}
}

// ---- Step 2: targets --------------------------------------------------------

func (s *seeder) findTarget(ctx context.Context, name string) (string, error) {
	resp, err := s.vc.ListTargets(ctx, &vaultv1.ListTargetsRequest{Actor: s.alan})
	if err != nil {
		return "", err
	}
	for _, t := range resp.GetTargets() {
		if t.GetName() == name {
			return t.GetId(), nil
		}
	}
	return "", nil
}

// slug lowercases a folder name into a hostname-safe segment.
func slug(name string) string {
	out := make([]rune, 0, len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out = append(out, r)
		case r >= 'A' && r <= 'Z':
			out = append(out, r+('a'-'A'))
		case r == ' ' || r == '-' || r == '_':
			out = append(out, '-')
		}
	}
	if len(out) == 0 {
		return "host"
	}
	return string(out)
}

func targetStep(idx int) seed.Step[*seeder] {
	name := fmt.Sprintf("bulk-target-%02d", idx)
	return seed.Step[*seeder]{
		Name: "target:" + name,
		Apply: func(ctx context.Context, s *seeder) error {
			id, err := s.findTarget(ctx, name)
			if err != nil {
				return err
			}
			if id == "" {
				folder := slug(s.folderName[s.pick(s.folderIDs)])
				host := fmt.Sprintf("host-%02d.%s.example.com", idx, folder)
				conn := connIDs[idx%len(connIDs)]
				kind := "unix"
				switch conn {
				case "conn-winrm-default":
					kind = "windows"
				case "conn-ldaps":
					kind = "directory"
				}
				r, err := s.vc.SaveTarget(ctx, &vaultv1.SaveTargetRequest{
					Actor: s.alan,
					Target: &vaultv1.Target{
						Name:         name,
						Hostname:     host,
						ConnectionId: conn,
						Kind:         kind,
						Domain:       "corp.example.com",
						Description:  "Bulk seed target for volume testing.",
					},
				})
				if err != nil {
					return err
				}
				id = r.GetTarget().GetId()
			}
			s.targetIDs = append(s.targetIDs, id)
			return nil
		},
		Assert: func(ctx context.Context, s *seeder) error {
			id, err := s.findTarget(ctx, name)
			if err != nil {
				return err
			}
			if id == "" {
				return fmt.Errorf("target %q not created", name)
			}
			return nil
		},
	}
}

// ---- Step 3: bulk secrets ---------------------------------------------------

// countSecrets sums the actor's secrets across the shared folders.
func (s *seeder) countSecrets(ctx context.Context) (int, error) {
	total := 0
	for _, fid := range s.folderIDs {
		resp, err := s.vc.ListSecretsInFolder(ctx, &vaultv1.ListSecretsInFolderRequest{Actor: s.alan, FolderId: fid})
		if err != nil {
			return 0, err
		}
		total += len(resp.GetSecrets())
	}
	return total, nil
}

var (
	words   = []string{"atlas", "orion", "vega", "nova", "titan", "helix", "delta", "echo", "falcon", "quartz", "cobalt", "ember", "onyx", "cipher", "raptor", "zephyr"}
	engines = []string{"PostgreSQL", "MySQL / MariaDB", "SQL Server", "Oracle", "MongoDB", "Other"}
)

func (s *seeder) word() string { return s.pick(words) }

// fieldValue returns a plausible random value for one field def, by kind (and a
// light key heuristic so text fields read sensibly).
func (s *seeder) fieldValue(f *vaultv1.SecretFieldDef) string {
	switch f.GetKind() {
	case vaultv1.FieldKind_FIELD_KIND_PASSWORD:
		return "Pw-" + randHex(8) + "!" + strconv.Itoa(s.rng.Intn(90)+10)
	case vaultv1.FieldKind_FIELD_KIND_SENSITIVE:
		return randHex(24)
	case vaultv1.FieldKind_FIELD_KIND_MULTILINE:
		return fmt.Sprintf("Auto-generated %s record for volume testing.\nManaged by the bulk seeder.", s.word())
	case vaultv1.FieldKind_FIELD_KIND_BOOLEAN:
		if s.rng.Intn(2) == 0 {
			return "true"
		}
		return "false"
	case vaultv1.FieldKind_FIELD_KIND_SELECT:
		if opts := f.GetOptions(); len(opts) > 0 {
			return opts[s.rng.Intn(len(opts))]
		}
		return ""
	case vaultv1.FieldKind_FIELD_KIND_FILE:
		return ""
	default: // TEXT
		return s.textValue(f.GetKey())
	}
}

func (s *seeder) textValue(key string) string {
	switch key {
	case "host", "server", "machine":
		return fmt.Sprintf("%s-%02d.example.com", s.word(), s.rng.Intn(100))
	case "domain":
		return "corp.example.com"
	case "username", "account", "onlineUsername", "cardholder", "holderName", "fullName":
		return "svc-" + s.word()
	case "url", "endpoint":
		return "https://" + s.word() + ".example.com/api"
	case "port":
		return s.pick([]string{"22", "443", "1433", "3306", "5432", "1521"})
	case "email":
		return s.word() + "@example.com"
	case "phone":
		return fmt.Sprintf("+1-555-%04d", s.rng.Intn(10000))
	case "engine":
		return s.pick(engines)
	case "service", "product", "bank", "city", "state":
		return s.word()
	case "zip":
		return fmt.Sprintf("%05d", s.rng.Intn(100000))
	default:
		return s.word() + "-" + randHex(3)
	}
}

// expiresAt returns an RFC3339 expiry drawn from the target distribution, or ""
// for none: ~15% already expired, ~15% within 30d, ~40% future >30d, ~30% none.
func (s *seeder) expiresAt(now time.Time) string {
	r := s.rng.Float64()
	switch {
	case r < 0.15: // already expired
		return now.Add(-time.Duration(s.rng.Intn(180)+1) * 24 * time.Hour).Format(time.RFC3339)
	case r < 0.30: // within 30 days
		return now.Add(time.Duration(s.rng.Intn(29)+1) * 24 * time.Hour).Format(time.RFC3339)
	case r < 0.70: // future > 30 days
		return now.Add(time.Duration(s.rng.Intn(700)+31) * 24 * time.Hour).Format(time.RFC3339)
	default: // none
		return ""
	}
}

func (s *seeder) createOne(ctx context.Context, now time.Time) error {
	t := s.types[s.rng.Intn(len(s.types))]
	fid := s.pick(s.folderIDs)
	fields := map[string]string{}
	for _, f := range t.GetFields() {
		if v := s.fieldValue(f); v != "" {
			fields[f.GetKey()] = v
		}
	}
	var targetID string
	if (t.GetHeartbeat() || t.GetCheckout()) && len(s.targetIDs) > 0 {
		targetID = s.pick(s.targetIDs)
	}
	name := fmt.Sprintf("%s %s-%s", t.GetName(), s.word(), randHex(3))
	_, err := s.vc.CreateSecret(ctx, &vaultv1.CreateSecretRequest{
		Actor:     s.alan,
		Name:      name,
		FolderId:  fid,
		TypeId:    t.GetId(),
		TargetId:  targetID,
		ExpiresAt: s.expiresAt(now),
		Fields:    fields,
	})
	return err
}

func bulkSecretsStep() seed.Step[*seeder] {
	return seed.Step[*seeder]{
		Name: "bulk-secrets",
		Apply: func(ctx context.Context, s *seeder) error {
			now := time.Now()
			have, err := s.countSecrets(ctx)
			if err != nil {
				return err
			}
			for have < s.target {
				if err := s.createOne(ctx, now); err != nil {
					return err
				}
				have++
				if have%50 == 0 {
					appLog.Info().Int("created_to", have).Int("target", s.target).Msg("bulk create progress")
				}
			}
			return nil
		},
		Assert: func(ctx context.Context, s *seeder) error {
			have, err := s.countSecrets(ctx)
			if err != nil {
				return err
			}
			if have < s.target {
				return fmt.Errorf("expected >= %d secrets, found %d", s.target, have)
			}
			return nil
		},
	}
}

// ---- Step 4: randomize output-only status (pgx) -----------------------------

func (s *seeder) recentTS(now time.Time, maxDays int) string {
	return now.Add(-time.Duration(s.rng.Intn(maxDays*24*3600)) * time.Second).Format(time.RFC3339)
}

func (s *seeder) heartbeatResult() string {
	switch r := s.rng.Float64(); {
	case r < 0.65:
		return "HEARTBEAT_RESULT_OK"
	case r < 0.80:
		return "HEARTBEAT_RESULT_FAILED"
	case r < 0.90:
		return "HEARTBEAT_RESULT_UNREACHABLE"
	default:
		return "HEARTBEAT_RESULT_UNKNOWN"
	}
}

func (s *seeder) rotationResult() string {
	switch r := s.rng.Float64(); {
	case r < 0.70:
		return "ROTATION_STATE_OK"
	case r < 0.85:
		return "ROTATION_STATE_FAILED"
	case r < 0.93:
		return "ROTATION_STATE_DEGRADED"
	default:
		return "ROTATION_STATE_ROTATING"
	}
}

// randomizeStep rewrites the whole data jsonb per row (preserving all existing
// keys) so the modified status fields survive the vault's protojson round-trip.
//
//nolint:gocognit,gocyclo // pre-existing complexity
func randomizeStep() seed.Step[*seeder] {
	return seed.Step[*seeder]{
		Name: "randomize-status",
		Apply: func(ctx context.Context, s *seeder) error {
			now := time.Now()
			rows, err := s.pool.Query(ctx, `SELECT id, data FROM secrets WHERE data->>'folderId' = ANY($1)`, s.folderIDs)
			if err != nil {
				return err
			}
			type row struct {
				id  string
				doc map[string]any
			}
			var todo []row
			for rows.Next() {
				var id string
				var raw []byte
				if err := rows.Scan(&id, &raw); err != nil {
					rows.Close()
					return err
				}
				var doc map[string]any
				if err := json.Unmarshal(raw, &doc); err != nil {
					rows.Close()
					return err
				}
				todo = append(todo, row{id: id, doc: doc})
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}

			for _, r := range todo {
				typeID, _ := r.doc["typeId"].(string)
				changed := false
				if s.hbTypes[typeID] && s.rng.Float64() < 0.85 {
					r.doc["lastHeartbeatResult"] = s.heartbeatResult()
					r.doc["verifiedAt"] = s.recentTS(now, 14)
					changed = true
				}
				if s.rotTypes[typeID] && s.rng.Float64() < 0.80 {
					res := s.rotationResult()
					r.doc["lastRotationResult"] = res
					if res == "ROTATION_STATE_OK" {
						r.doc["rotatedAt"] = s.recentTS(now, 60)
					}
					changed = true
				}
				if s.rng.Float64() < 0.40 {
					r.doc["viewCount"] = s.rng.Intn(80) + 1
					r.doc["lastAccessedAt"] = s.recentTS(now, 21)
					changed = true
				}
				if !changed {
					continue
				}
				out, err := json.Marshal(r.doc)
				if err != nil {
					return err
				}
				if _, err := s.pool.Exec(ctx, `UPDATE secrets SET data = $2 WHERE id = $1`, r.id, out); err != nil {
					return err
				}
			}
			return nil
		},
		Assert: func(ctx context.Context, s *seeder) error {
			var hb, vc int
			if err := s.pool.QueryRow(ctx,
				`SELECT count(*) FROM secrets WHERE data->>'folderId' = ANY($1) AND coalesce(data->>'lastHeartbeatResult','') <> ''`,
				s.folderIDs).Scan(&hb); err != nil {
				return err
			}
			if err := s.pool.QueryRow(ctx,
				`SELECT count(*) FROM secrets WHERE data->>'folderId' = ANY($1) AND coalesce((data->>'viewCount')::int,0) > 0`,
				s.folderIDs).Scan(&vc); err != nil {
				return err
			}
			if hb == 0 || vc == 0 {
				return fmt.Errorf("randomize incomplete: heartbeat-set=%d viewCount>0=%d", hb, vc)
			}
			return nil
		},
	}
}

// seedBulk fills the vault with a large, randomized secret population so the
// dashboard, folder tree and secret lists can be exercised at volume. It creates
// ~10 shared folders, ~30 targets, and enough randomized secrets to hit
// SECRET_TARGET (default 550) spread across those folders, then randomizes the
// output-only status fields (heartbeat/rotation results, view counts, access
// timestamps) directly in Postgres.
//
// It is idempotent + asserted via go-seed: every step is check-before-create and
// re-running only creates the shortfall, so it converges on the target instead of
// duplicating. Secrets are created through the vault gRPC API (so their sensitive
// fields seal correctly); the status fields the CreateSecret RPC cannot set are
// randomized directly in the secrets jsonb over the go-postgres pool.
//
// IMPORTANT: the running vault holds its state in memory and persists a full
// snapshot on every mutation, so a direct DB edit is only reflected after a
// restart AND only if nothing mutates the vault in between (which would persist
// the stale in-memory state back over the DB edit). The caller must therefore
// restart the vault after this tool completes and ensure no other writer (e.g.
// the connector) touches the vault during the DB pass -> restart window.
//
// DEV/QA-ONLY. Env: VAULT_ADDR (default vault:9091), DATABASE_DSN (required),
// SECRET_TARGET (default 550).
func seedBulk(ctx context.Context, db *postgres.DB) error {
	logger := appLog

	targetN := 550
	if v := env("SECRET_TARGET", ""); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			targetN = n
		}
	}

	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()

	vc := vaultv1.NewVaultServiceClient(dial(env("VAULT_ADDR", "vault:9091")))

	s := &seeder{
		vc:         vc,
		pool:       db.Querier(),
		alan:       &vaultv1.ActorContext{UserId: "user-turing", IsSiteAdmin: true, IsRoot: true},
		rng:        mrand.New(mrand.NewSource(time.Now().UnixNano())), // #nosec G404 -- non-crypto demo/faker data, not security-sensitive
		target:     targetN,
		folderName: map[string]string{},
		hbTypes:    map[string]bool{},
		rotTypes:   map[string]bool{},
	}

	// Load the built-in SYSTEM secret types (skip EXTENSION packs) up front — the
	// bulk step draws random types from this set and the randomize step uses the
	// heartbeat/rotation capability flags.
	tresp, err := vc.ListSecretTypes(ctx, &vaultv1.ListSecretTypesRequest{})
	if err != nil {
		return fmt.Errorf("list secret types: %w", err)
	}
	for _, t := range tresp.GetTypes() {
		if t.GetOrigin() != vaultv1.TypeOrigin_TYPE_ORIGIN_SYSTEM {
			continue
		}
		s.types = append(s.types, t)
		if t.GetHeartbeat() {
			s.hbTypes[t.GetId()] = true
		}
		if t.GetRotation() {
			s.rotTypes[t.GetId()] = true
		}
	}
	if len(s.types) == 0 {
		return fmt.Errorf("no built-in SYSTEM secret types found")
	}

	runner := seed.New(s)
	for _, name := range sharedFolders {
		runner.Add(folderStep(name))
	}
	for i := 1; i <= targetCount; i++ {
		runner.Add(targetStep(i))
	}
	runner.Add(bulkSecretsStep())
	runner.Add(randomizeStep())

	if err := runner.Run(ctx); err != nil {
		return fmt.Errorf("seedbulk: %w", err)
	}

	total, _ := s.countSecrets(ctx)
	logger.Info().
		Int("system_types", len(s.types)).
		Int("folders", len(s.folderIDs)).
		Int("targets", len(s.targetIDs)).
		Int("secrets_in_shared_folders", total).
		Msg("seedbulk complete (restart the vault to hydrate the randomized status)")
	return nil
}
