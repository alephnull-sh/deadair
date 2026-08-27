package exporter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type prometheusRuleFile struct {
	Groups []struct {
		Rules []struct {
			Alert string `yaml:"alert"`
			Expr  string `yaml:"expr"`
		} `yaml:"rules"`
	} `yaml:"groups"`
}

func TestBundledReportAlertsRequireCurrentInstanceHealth(t *testing.T) {
	path := filepath.Join("..", "..", "contrib", "prometheus-alerts.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var config prometheusRuleFile
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	expressions := make(map[string]string)
	for _, group := range config.Groups {
		for _, rule := range group.Rules {
			expressions[rule.Alert] = rule.Expr
		}
	}
	want := map[string]string{
		"DeadairDeadDetections":     "(deadair_detections_dead > 0) and on(instance) (deadair_instance_up == 1)",
		"DeadairImpairedDetections": "(deadair_detections_impaired > 0) and on(instance) (deadair_instance_up == 1)",
		"DeadairSourceStale":        "(deadair_source_freshness_seconds > 6 * 3600) and on(instance) (deadair_instance_up == 1)",
		"DeadairVolumeLow":          "(deadair_source_volume_low == 1) and on(instance) (deadair_instance_up == 1)",
		"DeadairSchemaDrift":        "(deadair_source_schema_drift == 1) and on(instance) (deadair_instance_up == 1)",
	}
	for alert, expected := range want {
		if got := expressions[alert]; got != expected {
			t.Errorf("%s expression = %q, want %q", alert, got, expected)
		}
	}

	instanceDown := expressions["DeadairInstanceScanFailing"]
	if instanceDown != "deadair_instance_up == 0" {
		t.Errorf("instance-down expression = %q, want ungated health check", instanceDown)
	}
	if strings.Contains(instanceDown, " and ") {
		t.Errorf("instance-down alert must not gate itself: %q", instanceDown)
	}
}
