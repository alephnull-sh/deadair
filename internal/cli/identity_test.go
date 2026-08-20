package cli

import "testing"

func TestBackendTargetIDIgnoresURLCredentials(t *testing.T) {
	a := backendTargetID("elastic", "https://alice:old@example.test:9200/", "https://kibana.example.test:5601", "default")
	b := backendTargetID("elastic", "https://bob:new@example.test:9200", "https://kibana.example.test:5601/", "default")
	if a != b {
		t.Fatalf("credential rotation changed target identity: %q != %q", a, b)
	}
	if a == backendTargetID("elastic", "https://other.example.test:9200", "https://kibana.example.test:5601", "default") {
		t.Fatal("different endpoint produced the same target identity")
	}
}
