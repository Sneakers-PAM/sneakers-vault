// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package buildinfo holds the version and commit stamped into the binary at
// build time:
//
//	go build -ldflags "-X github.com/Sneakers-PAM/sneakers-vault/internal/buildinfo.Version=v0.1.0 \
//	  -X github.com/Sneakers-PAM/sneakers-vault/internal/buildinfo.Commit=<sha>"
package buildinfo

import "runtime/debug"

// Version and Commit are set with -ldflags -X; the image build passes its
// VERSION and COMMIT build arguments.
var (
	Version = "dev"
	Commit  = ""
)

// Info returns the build's version and commit. An unstamped commit falls back
// to the VCS revision Go records when it builds from a git checkout, then to
// "unknown"; an unstamped version is "dev".
func Info() (version, commit string) {
	version, commit = Version, Commit
	if version == "" {
		version = "dev"
	}
	if commit == "" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" {
					commit = s.Value
				}
			}
		}
	}
	if commit == "" {
		commit = "unknown"
	}
	return version, commit
}
