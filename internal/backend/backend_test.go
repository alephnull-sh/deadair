package backend

import (
	"strings"
	"testing"
)

func TestValidateRuleIDs(t *testing.T) {
	tests := []struct {
		name  string
		rules []Rule
		want  string
	}{
		{name: "unique", rules: []Rule{{ID: "one"}, {ID: "two"}}},
		{name: "empty", rules: []Rule{{ID: "one"}, {ID: "  "}}, want: "empty ID"},
		{name: "duplicate", rules: []Rule{{ID: "same"}, {ID: "same"}}, want: "duplicate rule ID"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRuleIDs(tt.rules)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("ValidateRuleIDs() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ValidateRuleIDs() error = %v, want %q", err, tt.want)
			}
		})
	}
}
