// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"fmt"
	"strings"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// maxDisabledMcpTools bounds the list of switched-off MCP functions, so one
	// setting can't grow without limit.
	maxDisabledMcpTools = 256
	// maxMcpToolNameBytes bounds one function name.
	maxMcpToolNameBytes = 128
)

// mcpToolsPlan is the disabled-MCP-functions change an update asks for, checked
// before any setting is touched so a refused request changes nothing.
type mcpToolsPlan struct {
	set   bool
	names []string
}

// planMcpTools validates the disabled_mcp_tools part of an update. Names are
// trimmed, empties and duplicates dropped, in the order given. The vault keeps
// the names as the gateway sent them and doesn't check them against the
// gateway's own list of functions.
func planMcpTools(req *vaultv1.UpdateSecuritySettingsRequest) (mcpToolsPlan, error) {
	if req.DisabledMcpTools == nil {
		return mcpToolsPlan{}, nil
	}
	in := req.GetDisabledMcpTools().GetNames()
	if len(in) > maxDisabledMcpTools {
		return mcpToolsPlan{}, status.Error(codes.InvalidArgument, fmt.Sprintf("at most %d disabled MCP functions", maxDisabledMcpTools))
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		name := strings.TrimSpace(raw)
		if len(name) > maxMcpToolNameBytes {
			return mcpToolsPlan{}, status.Error(codes.InvalidArgument, fmt.Sprintf("an MCP function name is at most %d bytes", maxMcpToolNameBytes))
		}
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return mcpToolsPlan{set: true, names: out}, nil
}

// apply stores the plan and returns the audit attributes for what changed.
func (p mcpToolsPlan) apply(st *vaultv1.SecuritySettings) map[string]string {
	if !p.set {
		return nil
	}
	attrs := map[string]string{
		"disabled_mcp_tools.from": strings.Join(st.GetDisabledMcpTools(), ","),
		"disabled_mcp_tools.to":   strings.Join(p.names, ","),
	}
	st.DisabledMcpTools = p.names
	return attrs
}
