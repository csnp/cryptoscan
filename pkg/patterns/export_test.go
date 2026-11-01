// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package patterns

import "testing"

// UseTrustTable makes every match read the key table in data in place of the
// embedded one until the test ends, for the tests outside the package that
// scan certificates signed by generated keys. Call it before the scan starts:
// the workers read the table, and the swap and the restore must not race
// with them.
func UseTrustTable(t testing.TB, data []byte) {
	t.Helper()
	table, err := parseTrustTable(data)
	if err != nil {
		t.Fatalf("test key table: %v", err)
	}
	embedded := trustKeys()
	defaultTrustTable = table
	t.Cleanup(func() { defaultTrustTable = embedded })
}
