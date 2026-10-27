// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/csnp/cryptoscan/pkg/patterns"
)

// noCertificateInput holds no certificate. It hashes with MD5 and SHA-1,
// creates RSA and EC keys and turns off certificate verification, and most of
// the findings it raises carry references, the list a trust rule's helpUri is
// taken from.
const noCertificateInput = `import hashlib
import ssl
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import ec

digest = hashlib.md5(data).hexdigest()
legacy = hashlib.sha1(data).hexdigest()
pair = RSA.generate(1024)
signer = ec.generate_private_key(ec.SECP256R1())
context.verify_mode = ssl.CERT_NONE
`

// trustResultKeys are the result properties a trust finding adds to a SARIF
// report: the seven trust data under their names, and patterns.TrustMetaRule,
// the metadata key the trust code writes the rule number under.
var trustResultKeys = []string{
	"kind", "matchedValue", "valueType", "issuerSpkiSha256", "keyUse", "trustRule", "distrustDate",
	patterns.TrustMetaRule,
}

// sarifKeyLog is the part of a SARIF log the trust key reads use: each rule
// with its keys, and each result's rule ID with its property keys.
type sarifKeyLog struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Rules []map[string]json.RawMessage `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID     string                     `json:"ruleId"`
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"results"`
	} `json:"runs"`
}

// sarifTrustKeys is what a SARIF report carries of the trust additions.
type sarifTrustKeys struct {
	rules, results int
	// linked are the IDs of the rules that carry a helpUri.
	linked []string
	// keyed maps the rule ID of each result that carries a trust key to the
	// trust keys it carries, in trustResultKeys order.
	keyed map[string][]string
}

// readSARIFTrustKeys reads which rules of the SARIF report in out carry a
// helpUri and which results carry trust keys in their properties.
func readSARIFTrustKeys(t *testing.T, out string) sarifTrustKeys {
	t.Helper()
	var log sarifKeyLog
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatalf("scan --format sarif printed output that is not JSON: %v", err)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("%d runs, want 1", len(log.Runs))
	}
	run := log.Runs[0]
	keys := sarifTrustKeys{
		rules:   len(run.Tool.Driver.Rules),
		results: len(run.Results),
		keyed:   map[string][]string{},
	}
	for _, rule := range run.Tool.Driver.Rules {
		if _, ok := rule["helpUri"]; !ok {
			continue
		}
		var id string
		if err := json.Unmarshal(rule["id"], &id); err != nil {
			t.Fatalf("rule id %s: %v", rule["id"], err)
		}
		keys.linked = append(keys.linked, id)
	}
	for _, r := range run.Results {
		for _, key := range trustResultKeys {
			if _, ok := r.Properties[key]; ok && !slices.Contains(keys.keyed[r.RuleID], key) {
				keys.keyed[r.RuleID] = append(keys.keyed[r.RuleID], key)
			}
		}
	}
	return keys
}

// A scan of input that holds no certificate adds nothing of the Trust
// patterns to its SARIF report: no rule carries a helpUri, and no result's
// properties carry a trust key. The same reads over the removed root's
// certificate find both, so the check is one that can fail.
func TestTrustSARIFKeysAbsentWithoutCertificate(t *testing.T) {
	t.Run("removed root certificate", func(t *testing.T) {
		out := runScanWith(t, filepath.Join(trustFixture, "root"), "--format", "sarif")
		if out.err != "" {
			t.Fatalf("scan --format sarif: exit %d, error %q", out.code, out.err)
		}
		keys := readSARIFTrustKeys(t, out.stdout)
		t.Logf("rules with helpUri: %v; results with trust keys: %v", keys.linked, keys.keyed)
		if !slices.ContainsFunc(keys.linked, func(id string) bool { return strings.HasPrefix(id, "TRUST-") }) {
			t.Errorf("no TRUST- rule carries a helpUri; rules with one: %v", keys.linked)
		}
		trust := 0
		for id, found := range keys.keyed {
			if !strings.HasPrefix(id, "TRUST-") {
				continue
			}
			trust++
			for _, key := range []string{"kind", "matchedValue", "valueType", "keyUse", patterns.TrustMetaRule} {
				if !slices.Contains(found, key) {
					t.Errorf("result %s: no %s property among %v", id, key, found)
				}
			}
		}
		if trust == 0 {
			t.Errorf("no TRUST- result carries a trust key; results with one: %v", keys.keyed)
		}
	})

	t.Run("no certificate", func(t *testing.T) {
		dir := writeFixture(t, "crypto_usage.py", noCertificateInput)
		out := runScanWith(t, dir, "--format", "sarif")
		if out.err != "" {
			t.Fatalf("scan --format sarif: exit %d, error %q", out.code, out.err)
		}
		keys := readSARIFTrustKeys(t, out.stdout)
		t.Logf("%d rules, %d results; rules with helpUri: %v; results with trust keys: %v",
			keys.rules, keys.results, keys.linked, keys.keyed)
		if keys.rules == 0 || keys.results == 0 {
			t.Fatalf("%d rules and %d results: the input raised no finding to check", keys.rules, keys.results)
		}
		if len(keys.linked) != 0 {
			t.Errorf("rules carry a helpUri: %v", keys.linked)
		}
		if len(keys.keyed) != 0 {
			t.Errorf("results carry trust properties: %v", keys.keyed)
		}

		// The file was read, and its findings carry references, so a helpUri
		// set from the references of any finding, not only a trust finding,
		// would have shown above.
		out = runScanWith(t, dir, "--format", "json")
		if out.err != "" {
			t.Fatalf("scan --format json: exit %d, error %q", out.code, out.err)
		}
		var report struct {
			FilesScanned int `json:"filesScanned"`
			Findings     []struct {
				ID         string   `json:"id"`
				References []string `json:"references"`
			} `json:"findings"`
		}
		if err := json.Unmarshal([]byte(out.stdout), &report); err != nil {
			t.Fatalf("scan --format json printed output that is not JSON: %v", err)
		}
		if report.FilesScanned != 1 {
			t.Errorf("filesScanned = %d, want 1", report.FilesScanned)
		}
		referenced := 0
		for _, f := range report.Findings {
			if len(f.References) > 0 {
				referenced++
			}
		}
		if referenced == 0 {
			t.Errorf("none of the %d findings carries references, so the helpUri check reads nothing a trust condition decides", len(report.Findings))
		}
	})
}
