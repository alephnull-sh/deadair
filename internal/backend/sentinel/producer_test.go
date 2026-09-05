package sentinel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
)

func TestProducerQueriesUseOnlyConfiguredIdentities(t *testing.T) {
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/tables") && r.Method == http.MethodGet:
			fmt.Fprint(w, `{"value":[{"name":"CommonSecurityLog","properties":{"plan":"Analytics","provisioningState":"Succeeded","schema":{"columns":[{"name":"TimeGenerated","type":"datetime"},{"name":"DeviceName","type":"string"},{"name":"DeviceVendor","type":"string"}]}}}]}`)
		case strings.HasSuffix(r.URL.Path, "/query") && r.Method == http.MethodPost:
			var request logsQueryRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
				return
			}
			queries = append(queries, request.Query)
			writeAllowedLogsResult(w, "CommonSecurityLog", fmt.Sprintf(`[{"name":"PrimaryResult","columns":[{"name":"LastEvent","type":"datetime"}],"rows":[[%q]]}]`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := fixtureClient(server.URL, &recordingCredential{})
	p := backend.ProducerExpectation{ID: "edge-fw", Source: "CommonSecurityLog", Match: map[string]string{"DeviceName": "fw-london-01"}, Basis: backend.FreshnessIngestionTime, MaxStale: 15 * time.Minute}
	rules := []backend.Rule{
		{ID: "device", Enabled: true, PredicateFreshness: []backend.PredicateFreshnessSelector{mustPredicateSelector(t, `CommonSecurityLog | where DeviceName == 'fw-london-01' and EventID == 123`)}},
		{ID: "vendor", Enabled: true, PredicateFreshness: []backend.PredicateFreshnessSelector{mustPredicateSelector(t, `CommonSecurityLog | where DeviceVendor == 'Palo Alto Networks'`)}},
		{ID: "disabled", Enabled: false, PredicateFreshness: []backend.PredicateFreshnessSelector{mustPredicateSelector(t, `CommonSecurityLog | where DeviceName == 'fw-london-01'`)}},
	}
	items, err := client.ProducerFreshnessEvidence(context.Background(), []backend.ProducerExpectation{p}, rules)
	if err != nil || len(items) != 1 || items[0].Freshness.Status != backend.EvidenceAssessed || strings.Join(items[0].ConfirmedRules, ",") != "device" {
		t.Fatalf("producer evidence: %+v, %v", items, err)
	}
	if len(queries) != 1 || !strings.Contains(queries[0], `DeviceName == 'fw-london-01'`) || !strings.Contains(queries[0], "ingestion_time()") || strings.Contains(queries[0], "EventID") || !strings.Contains(queries[0], "ago(") {
		t.Fatalf("unexpected producer query: %v", queries)
	}
	p.Match = map[string]string{"DeviceProduct": "PAN-OS"}
	items, err = client.ProducerFreshnessEvidence(context.Background(), []backend.ProducerExpectation{p}, nil)
	if err != nil || len(items) != 1 || items[0].Freshness.Status != backend.EvidenceUnavailable || len(queries) != 1 {
		t.Fatalf("missing identity column queried or reported fresh: %+v, %v", items, err)
	}
}

func TestProducerSelectorRequiresIdentityAndBounds(t *testing.T) {
	p := backend.ProducerExpectation{ID: "edge-fw", Source: "CommonSecurityLog", Match: map[string]string{"DeviceVendor": "Palo Alto Networks", "DeviceProduct": "PAN-OS", "DeviceName": "fw-london-01"}, MaxStale: 15 * time.Minute, Basis: backend.FreshnessIngestionTime}
	s, err := ProducerSelector(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Fields) != 3 {
		t.Fatalf("selector: %+v", s)
	}
	for _, field := range []string{"EventID", "OperationName", "DeviceName | take 1"} {
		bad := p
		bad.Match = map[string]string{field: "1"}
		if _, err := ProducerSelector(bad); err == nil {
			t.Fatalf("accepted non-identity field %q", field)
		}
	}
	for _, value := range []string{"", "bad\nvalue", "bad\x1bvalue"} {
		bad := p
		bad.Match = map[string]string{"DeviceName": value}
		if _, err := ProducerSelector(bad); err == nil {
			t.Fatalf("accepted unsafe identity %q", value)
		}
	}
	p.MaxStale = 48 * time.Hour
	if _, err := ProducerSelector(p); err == nil {
		t.Fatal("accepted threshold outside query window")
	}
}

func TestProducerDependencyRequiresIdentityConjunction(t *testing.T) {
	p := `DeviceProduct == "PAN-OS" and DeviceVendor == "Palo Alto Networks"`
	for _, query := range []string{
		`DeviceVendor == "Palo Alto Networks" and DeviceProduct == "PAN-OS"`,
		`DeviceVendor == "Palo Alto Networks" and EventID == 123 and DeviceProduct == "PAN-OS"`,
	} {
		if !producerFilterRequires(query, p) {
			t.Errorf("missed dependency: %s", query)
		}
	}
	for _, query := range []string{`DeviceVendor == "Palo Alto Networks"`, `DeviceProduct == "FortiGate"`, `DeviceProduct == "PAN-OS" or DeviceVendor == "Palo Alto Networks"`} {
		if producerFilterRequires(query, p) {
			t.Errorf("invented dependency: %s", query)
		}
	}
	if producerFilterRequires(`DeviceVendor == "Palo Alto Networks" and DeviceProduct == "PAN-OS"`, p+` and DeviceName == "fw-london-01"`) {
		t.Fatal("table/vendor consumer became device dependency")
	}
}
