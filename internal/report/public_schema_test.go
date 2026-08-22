package report

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishedSchemaCopiesMatch(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"report-v1.schema.json", "fleet-report-v1.schema.json"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			authoritative, err := os.ReadFile(filepath.Join("..", "..", "schemas", name))
			if err != nil {
				t.Fatalf("read authoritative schema: %v", err)
			}
			published, err := os.ReadFile(filepath.Join("..", "..", "docs", "schemas", name))
			if err != nil {
				t.Fatalf("read published schema: %v", err)
			}
			if !bytes.Equal(authoritative, published) {
				t.Fatalf("docs/schemas/%s differs from schemas/%s", name, name)
			}
		})
	}
}
