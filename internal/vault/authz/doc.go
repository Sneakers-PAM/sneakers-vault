// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package authz is Sneakers' shared firewall-RACI authorization library — the
// single source of truth for evaluating who may do what across the project's
// services (currently the vault; reusable by any service that needs
// category/folder-style ordered-rule access control).
//
// Model: four governed actions — C (read/consulted), I (informed/ack), A
// (approve/accountable), R (author/manage/responsible). A Rule is one ordered
// "firewall row": a Subject (everyone | group | user) with a per-action Grant
// (allow | deny | blank/fall-through). A CategoryRuleset carries owners + an
// ordered list of Rules. Resolve(subject, chain) evaluates a chain of rulesets
// most-specific-first (target then ancestors):
//
//   - site-admin / root read all; owners in the chain auto-get C+A+R (never I);
//   - per action, the first non-blank allow/deny down the chain wins;
//   - implications R⇒C and A⇒C (I never implies C); read gates the rest;
//   - default deny. Group match is case-insensitive; user match is exact.
//
// Resolve is pure and total, so the same function doubles as the "what-if"
// simulator: pass a draft chain (unsaved rules) to preview a decision. Each
// decision carries a human-readable reason for auditing/UX.
//
// This package has no I/O and no service dependencies — callers build the
// chain (from their own store) and interpret the result (e.g. the vault maps
// C→reveal, R→create/edit/rotate, A→approve requests, I→informed/notify).
package authz
