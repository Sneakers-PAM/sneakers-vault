// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"encoding/json"
	"strings"
)

type catalogueField struct {
	Key          string   `json:"key"`
	Label        string   `json:"label"`
	Kind         string   `json:"kind"`
	Required     bool     `json:"required,omitempty"`
	Sensitive    bool     `json:"sensitive,omitempty"`
	Options      []string `json:"options,omitempty"`
	DefaultValue string   `json:"defaultValue,omitempty"`
}

type catalogueType struct {
	ID     string           `json:"id"`
	Name   string           `json:"name"`
	Origin string           `json:"origin"`
	Fields []catalogueField `json:"fields"`
}

// CatalogueJSON renders the built-in types and the extension packs as stable,
// indented JSON: the file committed at gen/catalogue/types.json.
func CatalogueJSON() ([]byte, error) {
	all := append(BuiltinTypes(), ExtensionCatalog()...)
	out := struct {
		Types []catalogueType `json:"types"`
	}{Types: make([]catalogueType, 0, len(all))}
	for _, t := range all {
		ct := catalogueType{
			ID: t.GetId(), Name: t.GetName(),
			Origin: strings.TrimPrefix(t.GetOrigin().String(), "TYPE_ORIGIN_"),
			Fields: make([]catalogueField, 0, len(t.GetFields())),
		}
		for _, f := range t.GetFields() {
			ct.Fields = append(ct.Fields, catalogueField{
				Key: f.GetKey(), Label: f.GetLabel(),
				Kind:     strings.TrimPrefix(f.GetKind().String(), "FIELD_KIND_"),
				Required: f.GetRequired(), Sensitive: f.GetSensitive(),
				Options: f.GetOptions(), DefaultValue: f.GetDefaultValue(),
			})
		}
		out.Types = append(out.Types, ct)
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
