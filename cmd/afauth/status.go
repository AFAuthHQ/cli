package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/afauthhq/cli/internal/accounts"
	"github.com/afauthhq/cli/internal/identity"
	"github.com/spf13/cobra"
)

// afauth status — the agent's identity + readiness dashboard.
//
// Where `whoami` prints the bare did:key for scripts, `status` answers
// the operational question an operator actually has: who am I, where
// does my key live, and — decisive for attested-only services (§9.2) —
// am I linked to a trust attestor and is that binding live?
//
// Everything here is read from local files (key.json, trust.json,
// accounts.json); status makes NO network calls. The link `state` is
// therefore a LOCAL judgment: it flags expired and orphaned bindings,
// but it cannot confirm the attestor hasn't revoked the binding
// server-side, nor that a given service accepts this attestor. A future
// `--refresh` would close that gap.

// bindingExpiringWindow is how close to expiry a live binding is
// reported as "expiring" rather than "live", to prompt a re-link before
// it lapses.
const bindingExpiringWindow = 48 * time.Hour

func newStatusCmd() *cobra.Command {
	var (
		keyPath string
		asJSON  bool
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show this agent's identity, key location, and trust-attestor linkage",
		Long: `Prints a local snapshot of the agent's identity and readiness: the
did:key, where the key lives, the trust-attestor binding (and whether
it is live), and a summary of known accounts.

status reads only local files and makes no network calls, so the link
state reflects what is knowable offline — it flags expired or orphaned
bindings but cannot confirm server-side revocation. Use --json for a
stable machine-readable object.

  afauth status
  afauth status --json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info, err := gatherStatus(keyPath)
			if err != nil {
				return err
			}
			if asJSON {
				out, err := json.MarshalIndent(info, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(out))
				return nil
			}
			renderStatusHuman(cmd.OutOrStdout(), info)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "key path (default $AFAUTH_HOME/key.json or ~/.afauth/key.json)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}

// statusInfo is the full local snapshot, shared by the human and JSON
// renderers so the two never drift.
type statusInfo struct {
	Initialized  bool             `json:"initialized"`
	DID          string           `json:"did,omitempty"`
	KeyPath      string           `json:"key_path,omitempty"`
	Algorithm    string           `json:"algorithm,omitempty"`
	PublicKeyHex string           `json:"public_key_hex,omitempty"`
	CreatedAt    string           `json:"created_at,omitempty"` // RFC3339, key-file mtime
	Link         *linkSummary     `json:"link,omitempty"`
	Accounts     *accountsSummary `json:"accounts,omitempty"`
}

// linkSummary is the local view of the trust-attestor binding. state is
// a local judgment (see file header) and is one of: unlinked, live,
// expiring, expired, orphaned.
type linkSummary struct {
	Linked             bool   `json:"linked"`
	State              string `json:"state"`
	Attestor           string `json:"attestor,omitempty"`
	BindingID          string `json:"binding_id,omitempty"`
	ExpiresAt          string `json:"expires_at,omitempty"`
	MatchesActiveKey   bool   `json:"matches_active_key"`
	Verification       string `json:"verification,omitempty"`
	VerificationSeenAt string `json:"verification_seen_at,omitempty"`
}

type accountsSummary struct {
	Services int            `json:"services"`
	ByState  map[string]int `json:"by_state,omitempty"`
	Stranded int            `json:"stranded,omitempty"`
}

// gatherStatus assembles the snapshot from local files. A missing key
// is reported as Initialized:false rather than an error (status is a
// diagnostic command); a key that exists but fails to load is a real
// error worth surfacing.
func gatherStatus(keyPath string) (*statusInfo, error) {
	path := keyPath
	if path == "" {
		p, err := identity.DefaultPath()
		if err != nil {
			return nil, err
		}
		path = p
	}
	id, err := identity.Load(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &statusInfo{Initialized: false, KeyPath: path}, nil
		}
		return nil, err
	}
	did, err := id.DID()
	if err != nil {
		return nil, err
	}
	info := &statusInfo{
		Initialized:  true,
		DID:          did,
		KeyPath:      path,
		Algorithm:    "ed25519",
		PublicKeyHex: hex.EncodeToString(id.PublicKey),
		Link:         loadLinkSummary(did),
		Accounts:     loadAccountsSummary(did),
	}
	if fi, statErr := os.Stat(path); statErr == nil {
		info.CreatedAt = fi.ModTime().UTC().Format(time.RFC3339)
	}
	return info, nil
}

// loadLinkSummary reads ~/.afauth/trust.json and classifies the binding
// relative to the active key's DID. A missing or unreadable binding is
// reported as unlinked rather than failing the command.
func loadLinkSummary(activeDID string) *linkSummary {
	st, err := loadTrustState()
	if err != nil || len(st.Bindings) == 0 {
		return &linkSummary{Linked: false, State: "unlinked"}
	}
	b := primaryBinding(st, activeDID)
	ls := &linkSummary{
		Linked:           true,
		Attestor:         b.BaseURL,
		BindingID:        b.BindingID,
		MatchesActiveKey: b.AgentDID == activeDID,
		Verification:     b.Verification,
		State:            linkState(b, activeDID),
	}
	if b.BindingTokenExpiresUnix > 0 {
		ls.ExpiresAt = time.Unix(b.BindingTokenExpiresUnix, 0).UTC().Format(time.RFC3339)
	}
	if b.VerificationSeenUnix > 0 {
		ls.VerificationSeenAt = time.Unix(b.VerificationSeenUnix, 0).UTC().Format(time.RFC3339)
	}
	return ls
}

// primaryBinding picks the binding `afauth status` summarizes when several
// exist: the first usable one (live, matches the active key), else the
// first binding so a stale/orphaned link is still surfaced. `afauth trust
// status` lists them all.
func primaryBinding(st *trustState, activeDID string) *trustBinding {
	if usable := st.usable(activeDID); len(usable) > 0 {
		return usable[0]
	}
	return st.Bindings[0]
}

// linkState classifies a binding. Orphaned (bound to a different key,
// e.g. after a rotation that left trust.json behind) takes priority over
// expiry, since the binding is unusable by the active key regardless.
func linkState(b *trustBinding, activeDID string) string {
	if bindingIsOrphaned(b, activeDID) {
		return "orphaned"
	}
	if b.BindingTokenExpiresUnix > 0 {
		exp := time.Unix(b.BindingTokenExpiresUnix, 0)
		now := time.Now()
		if now.After(exp) {
			return "expired"
		}
		if exp.Sub(now) < bindingExpiringWindow {
			return "expiring"
		}
	}
	return "live"
}

// loadAccountsSummary reads the local accounts ledger and tallies state.
// The ledger is keyed one entry per service, so the count is "services".
func loadAccountsSummary(activeDID string) *accountsSummary {
	path, err := accounts.DefaultPath()
	if err != nil {
		return nil
	}
	l, err := accounts.Load(path)
	if err != nil {
		return nil
	}
	entries := l.Sorted()
	sum := &accountsSummary{Services: len(entries)}
	if len(entries) == 0 {
		return sum
	}
	sum.ByState = map[string]int{}
	for _, e := range entries {
		state := e.State
		if state == "" {
			state = "UNKNOWN"
		}
		sum.ByState[state]++
		// An entry bound to a different DID was stranded by a key change
		// at this agent — the account lives under the old key until
		// re-rotated against that service.
		if e.AgentDID != "" && e.AgentDID != activeDID {
			sum.Stranded++
		}
	}
	return sum
}

func renderStatusHuman(w io.Writer, info *statusInfo) {
	if !info.Initialized {
		fmt.Fprintln(w, "no identity — run `afauth init`")
		return
	}
	fmt.Fprintf(w, "DID        %s\n", info.DID)
	fmt.Fprintf(w, "Key file   %s\n", info.KeyPath)
	fmt.Fprintf(w, "Algorithm  %s\n", info.Algorithm)
	if info.CreatedAt != "" {
		fmt.Fprintf(w, "Created    %s\n", info.CreatedAt)
	}
	fmt.Fprintf(w, "Link       %s\n", renderLinkLine(info.Link))
	fmt.Fprintf(w, "Accounts   %s\n", renderAccountsLine(info.Accounts))
}

func renderLinkLine(ls *linkSummary) string {
	if ls == nil || !ls.Linked {
		return "✗ not linked — attested-only services will reject signup; run `afauth trust link`"
	}
	host := attestorHost(ls.Attestor)
	switch ls.State {
	case "orphaned":
		return "⚠ binding is for a different key (rotated away) — re-link: `afauth trust link`"
	case "expired":
		return fmt.Sprintf("✗ %s · binding expired %s — re-link: `afauth trust link`", host, relTime(ls.ExpiresAt))
	case "expiring":
		return fmt.Sprintf("⚠ %s · expiring %s%s", host, relTime(ls.ExpiresAt), verifSuffix(ls))
	default: // live
		line := "✓ " + host + " · live"
		if r := relTime(ls.ExpiresAt); r != "" {
			line += ", expires " + r
		}
		return line + verifSuffix(ls)
	}
}

func renderAccountsLine(s *accountsSummary) string {
	if s == nil || s.Services == 0 {
		return "none — try `afauth signup <service-url>`"
	}
	keys := make([]string, 0, len(s.ByState))
	for k := range s.ByState {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", s.ByState[k], k))
	}
	noun := "services"
	if s.Services == 1 {
		noun = "service"
	}
	line := fmt.Sprintf("%d %s — %s", s.Services, noun, strings.Join(parts, ", "))
	if s.Stranded > 0 {
		line += fmt.Sprintf("; %d stranded under a previous key (re-rotate)", s.Stranded)
	}
	return line + "   → afauth accounts list"
}

// verifSuffix renders the cached verification method, e.g. " (email)".
func verifSuffix(ls *linkSummary) string {
	if ls.Verification == "" {
		return ""
	}
	return " (" + ls.Verification + ")"
}

// attestorHost reduces a base URL to its host for display, falling back
// to the raw value when it does not parse.
func attestorHost(base string) string {
	if base == "" {
		return "trust attestor"
	}
	if u, err := url.Parse(base); err == nil && u.Host != "" {
		return u.Host
	}
	return base
}

// relTime renders an RFC3339 instant relative to now: "in 12d" for the
// future, "8d ago" for the past, "" when empty or unparseable.
func relTime(rfc3339 string) string {
	if rfc3339 == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		return ""
	}
	d := time.Until(t)
	if d >= 0 {
		return "in " + humanizeDuration(d)
	}
	return humanizeDuration(-d) + " ago"
}

func humanizeDuration(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours())/24)
	case d >= time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
}
