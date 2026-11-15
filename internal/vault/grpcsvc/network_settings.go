// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// maxAllowedNetworks bounds the internal-only allow-list, so one setting can't
// grow without limit.
const maxAllowedNetworks = 64

// networkPlan is the internal-only change an update asks for, checked before
// any setting is touched so a refused request changes nothing.
type networkPlan struct {
	setInternalOnly bool
	internalOnly    bool
	setNetworks     bool
	networks        []string
}

// planNetworkSettings validates the internal_only and allowed_networks parts of
// an update against what is stored. A network is a CIDR prefix or a bare
// address, stored as a canonical prefix with duplicates dropped. Internal-only
// can't be on with no network listed, whichever field the request changes, so
// an admin can't lock everyone out by accident.
func (s *Server) planNetworkSettings(req *vaultv1.UpdateSecuritySettingsRequest) (networkPlan, error) {
	p := networkPlan{setInternalOnly: req.InternalOnly != nil, internalOnly: s.settings.GetInternalOnly(), networks: s.settings.GetAllowedNetworks()}
	if req.InternalOnly != nil {
		p.internalOnly = req.GetInternalOnly()
	}
	if req.AllowedNetworks != nil {
		nets, err := canonicalNetworks(req.GetAllowedNetworks().GetCidrs())
		if err != nil {
			return networkPlan{}, err
		}
		p.setNetworks, p.networks = true, nets
	}
	if p.internalOnly && len(p.networks) == 0 {
		return networkPlan{}, status.Error(codes.InvalidArgument, "internal-only needs at least one allowed network")
	}
	return p, nil
}

func canonicalNetworks(in []string) ([]string, error) {
	if len(in) > maxAllowedNetworks {
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("at most %d allowed networks", maxAllowedNetworks))
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			a, aerr := netip.ParseAddr(raw)
			if aerr != nil {
				return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("%q is not a CIDR prefix or an address", raw))
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		c := p.Masked().String()
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out, nil
}

// apply stores the plan and returns the audit attributes for what changed.
func (p networkPlan) apply(st *vaultv1.SecuritySettings) map[string]string {
	attrs := map[string]string{}
	if p.setInternalOnly {
		attrs["internal_only.from"] = strconv.FormatBool(st.GetInternalOnly())
		attrs["internal_only.to"] = strconv.FormatBool(p.internalOnly)
		st.InternalOnly = p.internalOnly
	}
	if p.setNetworks {
		attrs["allowed_networks.from"] = strings.Join(st.GetAllowedNetworks(), ",")
		attrs["allowed_networks.to"] = strings.Join(p.networks, ",")
		st.AllowedNetworks = p.networks
	}
	return attrs
}

func mergeAttrs(dst, src map[string]string) map[string]string {
	if dst == nil {
		dst = map[string]string{}
	}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
