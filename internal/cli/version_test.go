package cli

import (
	"runtime/debug"
	"testing"
)

func TestVersionFromBuildInfo(t *testing.T) {
	module := func(path, version string) *debug.BuildInfo {
		return &debug.BuildInfo{Main: debug.Module{Path: path, Version: version}}
	}

	tests := []struct {
		name    string
		stamped string
		info    *debug.BuildInfo
		ok      bool
		want    string
	}{
		{name: "linker version wins", stamped: "v0.5.1", info: module("github.com/alephnull-sh/deadair", "v0.5.0"), ok: true, want: "v0.5.1"},
		{name: "module version", stamped: "dev", info: module("github.com/alephnull-sh/deadair", "v0.5.1"), ok: true, want: "v0.5.1"},
		{name: "development build", stamped: "dev", info: module("github.com/alephnull-sh/deadair", "(devel)"), ok: true, want: "dev"},
		{name: "different module", stamped: "dev", info: module("example.com/fork/deadair", "v0.5.1"), ok: true, want: "dev"},
		{name: "missing build info", stamped: "", info: nil, ok: false, want: "dev"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := versionFromBuildInfo(tt.stamped, tt.info, tt.ok); got != tt.want {
				t.Fatalf("versionFromBuildInfo() = %q, want %q", got, tt.want)
			}
		})
	}
}
