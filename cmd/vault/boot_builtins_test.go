// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	log "github.com/Bugs5382/go-log"
)

func TestLogBootBuiltinsNamesWhatWasAddedAtInfo(t *testing.T) {
	t.Setenv("LOG_LEVEL", "info")
	t.Setenv("LOG_FORMAT", "json")
	var out bytes.Buffer
	lg := log.NewLoggerWithOptions("vault-test", log.WithOutput(&out))

	logBootBuiltins(context.Background(), lg, []string{"type:type-github-app", "extension:ext-aws-iam-key"})

	got := out.String()
	for _, want := range []string{`"level":"info"`, "type:type-github-app", "extension:ext-aws-iam-key", `"count":2`} {
		if !strings.Contains(got, want) {
			t.Errorf("log %q is missing %s", got, want)
		}
	}

	out.Reset()
	logBootBuiltins(context.Background(), lg, nil)
	if out.Len() != 0 {
		t.Errorf("nothing added should log nothing at info, got %q", out.String())
	}
}
