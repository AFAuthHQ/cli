package main

import (
	"reflect"
	"testing"
)

func TestNormalizeArgs(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"empty", nil, []string{}},
		{"posix help unchanged", []string{"--help"}, []string{"--help"}},
		{"short help unchanged", []string{"-h"}, []string{"-h"}},
		{"go-style help rewritten", []string{"-help"}, []string{"--help"}},
		{"go-style version rewritten", []string{"-version"}, []string{"--version"}},
		{
			"subcommand help is rewritten in place",
			[]string{"signup", "-help"},
			[]string{"signup", "--help"},
		},
		{
			"unrelated flags untouched",
			[]string{"signup", "--explicit", "--terms-version", "2026-05-01"},
			[]string{"signup", "--explicit", "--terms-version", "2026-05-01"},
		},
		{
			"substring matches do not trigger rewrite",
			[]string{"-helpme", "-help=foo"},
			[]string{"-helpme", "-help=foo"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeArgs(tc.in)
			if tc.in == nil {
				// normalizeArgs preserves length; empty input → empty output.
				if len(got) != 0 {
					t.Fatalf("normalizeArgs(nil) = %v; want empty", got)
				}
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("normalizeArgs(%v) = %v; want %v", tc.in, got, tc.want)
			}
		})
	}
}
