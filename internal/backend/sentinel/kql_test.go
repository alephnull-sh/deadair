package sentinel

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/alephnull-sh/deadair/internal/backend"
)

func TestResolveKQLDependenciesResolved(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		query string
		want  []Dependency
	}{
		{
			name: "direct table ignores scalar text and comments",
			query: `// union CommentTable
SecurityEvent
| where Message == "workspace('other').FakeTable"
| extend Text = 'join HiddenTable on Key'`,
			want: []Dependency{{Name: "SecurityEvent", Kind: KindTable}},
		},
		{
			name:  "quoted table identifier",
			query: `["Security Event"] | where EventID == 4688`,
			want:  []Dependency{{Name: "Security Event", Kind: KindTable}},
		},
		{
			name:  "ordinary im prefixed table",
			query: `ImpersonationLogs | take 0`,
			want:  []Dependency{{Name: "ImpersonationLogs", Kind: KindTable}},
		},
		{
			name:  "native ASIM ingestion table",
			query: `ASimAuthenticationEventLogs | take 0`,
			want:  []Dependency{{Name: "ASimAuthenticationEventLogs", Kind: KindTable}},
		},
		{
			name:  "native ASIM activity ingestion table",
			query: `ASimUserManagementActivityLogs | take 0`,
			want:  []Dependency{{Name: "ASimUserManagementActivityLogs", Kind: KindTable}},
		},
		{
			name:  "custom ASIM ingestion table",
			query: `ASimAuthenticationEventLogs_CL | take 0`,
			want:  []Dependency{{Name: "ASimAuthenticationEventLogs_CL", Kind: KindTable}},
		},
		{
			name:  "union options order and deduplication",
			query: `union kind=outer withsource=SourceTable SecurityEvent, SigninLogs, SecurityEvent | count`,
			want: []Dependency{
				{Name: "SecurityEvent", Kind: KindTable},
				{Name: "SigninLogs", Kind: KindTable},
			},
		},
		{
			name: "join and lookup subqueries",
			query: `SecurityEvent
| join kind=inner (SigninLogs | where ResultType == 0) on Account
| lookup kind=leftouter IdentityInfo on Account`,
			want: []Dependency{
				{Name: "SecurityEvent", Kind: KindTable},
				{Name: "SigninLogs", Kind: KindTable},
				{Name: "IdentityInfo", Kind: KindTable},
			},
		},
		{
			name:  "nested union on join right side",
			query: `SecurityEvent | join (union SigninLogs, AADNonInteractiveUserSignInLogs | where ResultType == 0) on Account`,
			want: []Dependency{
				{Name: "SecurityEvent", Kind: KindTable},
				{Name: "SigninLogs", Kind: KindTable},
				{Name: "AADNonInteractiveUserSignInLogs", Kind: KindTable},
			},
		},
		{
			name: "simple let aliases and alias chain",
			query: `let Interactive = SigninLogs | where IsInteractive;
let Combined = union Interactive, AADNonInteractiveUserSignInLogs;
Combined | join (IdentityInfo) on AccountObjectId`,
			want: []Dependency{
				{Name: "SigninLogs", Kind: KindTable},
				{Name: "AADNonInteractiveUserSignInLogs", Kind: KindTable},
				{Name: "IdentityInfo", Kind: KindTable},
			},
		},
		{
			name:  "tabular in subquery",
			query: `SigninLogs | where UserPrincipalName in (IdentityInfo | project AccountUPN)`,
			want: []Dependency{
				{Name: "SigninLogs", Kind: KindTable},
				{Name: "IdentityInfo", Kind: KindTable},
			},
		},
		{
			name: "let bound tabular in subquery",
			query: `let Known = IdentityInfo | project AccountUPN;
SigninLogs | where UserPrincipalName in (Known)`,
			want: []Dependency{
				{Name: "SigninLogs", Kind: KindTable},
				{Name: "IdentityInfo", Kind: KindTable},
			},
		},
		{
			name:  "case insensitive tabular in subquery",
			query: `SigninLogs | where UserPrincipalName in~ (IdentityInfo | project AccountUPN)`,
			want: []Dependency{
				{Name: "SigninLogs", Kind: KindTable},
				{Name: "IdentityInfo", Kind: KindTable},
			},
		},
		{
			name:  "scalar membership list",
			query: `SecurityEvent | where EventID in (4624, 4625)`,
			want:  []Dependency{{Name: "SecurityEvent", Kind: KindTable}},
		},
		{
			name:  "mixed local dependencies remain in one resolution",
			query: `PresentTable | union MissingTable | join (OtherPresentTable) on Account`,
			want: []Dependency{
				{Name: "PresentTable", Kind: KindTable},
				{Name: "MissingTable", Kind: KindTable},
				{Name: "OtherPresentTable", Kind: KindTable},
			},
		},
		{
			name:  "unused let does not create evidence",
			query: `let Unused = SecurityEvent; SigninLogs | count`,
			want:  []Dependency{{Name: "SigninLogs", Kind: KindTable}},
		},
		{
			name:  "unused remote let does not change local resolution",
			query: `let Unused = workspace("other").SecurityEvent; SigninLogs | count`,
			want:  []Dependency{{Name: "SigninLogs", Kind: KindTable}},
		},
		{
			name:  "explicit search list",
			query: `search kind=case_sensitive in (SecurityEvent, SigninLogs) "failure"`,
			want: []Dependency{
				{Name: "SecurityEvent", Kind: KindTable},
				{Name: "SigninLogs", Kind: KindTable},
			},
		},
		{
			name:  "explicit find list",
			query: `find withsource=Source in (DeviceProcessEvents, DeviceNetworkEvents) where Timestamp > ago(1h)`,
			want: []Dependency{
				{Name: "DeviceProcessEvents", Kind: KindTable},
				{Name: "DeviceNetworkEvents", Kind: KindTable},
			},
		},
		{
			name:  "declare query parameters before direct source",
			query: `declare query_parameters(limit:long = 10); SecurityEvent | take limit`,
			want:  []Dependency{{Name: "SecurityEvent", Kind: KindTable}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ResolveKQLDependencies(tt.query)
			if got.Status != backend.ResolutionResolved {
				t.Fatalf("status = %q, want %q (reason: %s)", got.Status, backend.ResolutionResolved, got.Reason)
			}
			if !reflect.DeepEqual(got.Dependencies, tt.want) {
				t.Fatalf("dependencies = %#v, want %#v", got.Dependencies, tt.want)
			}
		})
	}
}

func TestResolveKQLDependenciesRetainsFuzzyUnionRequiredness(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		query string
		want  []Dependency
	}{
		{
			name:  "ordinary union legs remain required",
			query: `union SecurityEvent, SigninLogs`,
			want: []Dependency{
				{Name: "SecurityEvent", Kind: KindTable},
				{Name: "SigninLogs", Kind: KindTable},
			},
		},
		{
			name:  "fuzzy-only union legs are optional",
			query: `union kind=outer isfuzzy=true SecurityEvent, SigninLogs`,
			want: []Dependency{
				{Name: "SecurityEvent", Kind: KindTable, Optional: true},
				{Name: "SigninLogs", Kind: KindTable, Optional: true},
			},
		},
		{
			name:  "leading pipeline source remains required",
			query: `SecurityEvent | union isfuzzy=true SigninLogs, AuditLogs`,
			want: []Dependency{
				{Name: "SecurityEvent", Kind: KindTable},
				{Name: "SigninLogs", Kind: KindTable, Optional: true},
				{Name: "AuditLogs", Kind: KindTable, Optional: true},
			},
		},
		{
			name:  "required occurrence wins without reordering",
			query: `union isfuzzy=true SecurityEvent, SigninLogs | union SecurityEvent, AuditLogs`,
			want: []Dependency{
				{Name: "SecurityEvent", Kind: KindTable},
				{Name: "SigninLogs", Kind: KindTable, Optional: true},
				{Name: "AuditLogs", Kind: KindTable},
			},
		},
		{
			name:  "explicit false keeps all legs required",
			query: `union isfuzzy=false SecurityEvent, SigninLogs`,
			want: []Dependency{
				{Name: "SecurityEvent", Kind: KindTable},
				{Name: "SigninLogs", Kind: KindTable},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ResolveKQLDependencies(tt.query)
			if got.Status != backend.ResolutionResolved {
				t.Fatalf("status = %q, want resolved (reason: %s)", got.Status, got.Reason)
			}
			if !reflect.DeepEqual(got.Dependencies, tt.want) {
				t.Fatalf("dependencies = %#v, want %#v", got.Dependencies, tt.want)
			}
		})
	}
}

func TestResolveKQLDependenciesUsedScalarLetInputs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		query  string
		status backend.ResolutionStatus
		want   []Dependency
	}{
		{
			name:   "used toscalar exposes hidden table",
			query:  `let cutoff=toscalar(SecurityEvent | summarize max(TimeGenerated)); SigninLogs | where TimeGenerated > cutoff`,
			status: backend.ResolutionResolved,
			want: []Dependency{
				{Name: "SigninLogs", Kind: KindTable},
				{Name: "SecurityEvent", Kind: KindTable},
			},
		},
		{
			name:   "used scalar alias chain exposes hidden table",
			query:  `let base=toscalar(IdentityInfo | count); let cutoff=base + 1; SigninLogs | where RiskLevel > cutoff`,
			status: backend.ResolutionResolved,
			want: []Dependency{
				{Name: "SigninLogs", Kind: KindTable},
				{Name: "IdentityInfo", Kind: KindTable},
			},
		},
		{
			name:   "toscalar of used tabular alias exposes hidden table",
			query:  `let base=SecurityEvent | count; SigninLogs | where RiskLevel > toscalar(base)`,
			status: backend.ResolutionResolved,
			want: []Dependency{
				{Name: "SigninLogs", Kind: KindTable},
				{Name: "SecurityEvent", Kind: KindTable},
			},
		},
		{
			name:   "used scalar in join predicate exposes hidden table",
			query:  `let cutoff=toscalar(IdentityInfo | count); SigninLogs | join (AuditLogs) on Account, $left.RiskLevel > cutoff`,
			status: backend.ResolutionResolved,
			want: []Dependency{
				{Name: "SigninLogs", Kind: KindTable},
				{Name: "AuditLogs", Kind: KindTable},
				{Name: "IdentityInfo", Kind: KindTable},
			},
		},
		{
			name:   "unused toscalar does not create input",
			query:  `let cutoff=toscalar(SecurityEvent | count); SigninLogs | count`,
			status: backend.ResolutionResolved,
			want:   []Dependency{{Name: "SigninLogs", Kind: KindTable}},
		},
		{
			name:   "used literal scalar does not create input",
			query:  `let cutoff=5; SigninLogs | where RiskLevel > cutoff`,
			status: backend.ResolutionResolved,
			want:   []Dependency{{Name: "SigninLogs", Kind: KindTable}},
		},
		{
			name:   "used literal scalar subquery does not create input",
			query:  `let cutoff=toscalar(print value=5 | project value); SigninLogs | where RiskLevel > cutoff`,
			status: backend.ResolutionResolved,
			want:   []Dependency{{Name: "SigninLogs", Kind: KindTable}},
		},
		{
			name:   "dynamic hidden source makes assessment unsupported",
			query:  `let cutoff=toscalar(table(TableName) | count); SigninLogs | where RiskLevel > cutoff`,
			status: backend.ResolutionUnsupported,
			want:   []Dependency{{Name: "SigninLogs", Kind: KindTable}},
		},
		{
			name:   "hidden input inherits fuzzy optionality",
			query:  `let cutoff=toscalar(SecurityEvent | count); union isfuzzy=true (SigninLogs | where RiskLevel > cutoff), AuditLogs`,
			status: backend.ResolutionResolved,
			want: []Dependency{
				{Name: "SigninLogs", Kind: KindTable, Optional: true},
				{Name: "SecurityEvent", Kind: KindTable, Optional: true},
				{Name: "AuditLogs", Kind: KindTable, Optional: true},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ResolveKQLDependencies(tt.query)
			if got.Status != tt.status {
				t.Fatalf("status = %q, want %q (reason: %s)", got.Status, tt.status, got.Reason)
			}
			if !reflect.DeepEqual(got.Dependencies, tt.want) {
				t.Fatalf("dependencies = %#v, want %#v", got.Dependencies, tt.want)
			}
		})
	}
}

func TestResolveKQLDependenciesFunctionReferencesRemainUnsupported(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		query string
		want  []Dependency
	}{
		{
			name:  "function root",
			query: `NormalisedSecurityEvents("process") | where TimeGenerated > ago(1h)`,
			want:  []Dependency{{Name: "NormalisedSecurityEvents", Kind: KindFunction}},
		},
		{
			name:  "function mixed with direct table",
			query: `SecurityEvent | union IdentityFunction(), SigninLogs`,
			want: []Dependency{
				{Name: "SecurityEvent", Kind: KindTable},
				{Name: "IdentityFunction", Kind: KindFunction},
				{Name: "SigninLogs", Kind: KindTable},
			},
		},
		{
			name:  "bare built in ASIM alias omitted from workspace metadata",
			query: `imAuthentication | take 0`,
			want:  []Dependency{{Name: "imAuthentication", Kind: KindASIMBuiltin, Call: "imAuthentication"}},
		},
		{
			name:  "parameterized built in ASIM parser omitted from workspace metadata",
			query: `_Im_Authentication(starttime=ago(1d), endtime=now()) | take 0`,
			want:  []Dependency{{Name: "_Im_Authentication", Kind: KindASIMBuiltin, Call: "_Im_Authentication(starttime=ago(1d),endtime=now())"}},
		},
		{
			name:  "bare built in ASIM parser omitted from workspace metadata",
			query: `_Im_Authentication | take 0`,
			want:  []Dependency{{Name: "_Im_Authentication", Kind: KindASIMBuiltin, Call: "_Im_Authentication"}},
		},
		{
			name:  "legacy built in ASIM alias",
			query: `_ASim_Authentication | take 0`,
			want:  []Dependency{{Name: "_ASim_Authentication", Kind: KindASIMBuiltin, Call: "_ASim_Authentication"}},
		},
		{
			name:  "workspace custom ASIM alias absent from metadata",
			query: `Im_AuthenticationCustom | take 0`,
			want:  []Dependency{{Name: "Im_AuthenticationCustom", Kind: KindASIMBuiltin, Call: "Im_AuthenticationCustom"}},
		},
		{
			name:  "source specific ASIM parser absent from metadata",
			query: `vimAuthenticationContosoProduct | take 0`,
			want:  []Dependency{{Name: "vimAuthenticationContosoProduct", Kind: KindASIMBuiltin, Call: "vimAuthenticationContosoProduct"}},
		},
		{
			name:  "parameterless source specific ASIM parser absent from metadata",
			query: `ASimAuthenticationContosoProduct | take 0`,
			want:  []Dependency{{Name: "ASimAuthenticationContosoProduct", Kind: KindASIMBuiltin, Call: "ASimAuthenticationContosoProduct"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ResolveKQLDependencies(tt.query)
			if got.Status != backend.ResolutionUnsupported {
				t.Fatalf("status = %q, want %q (reason: %s)", got.Status, backend.ResolutionUnsupported, got.Reason)
			}
			if !reflect.DeepEqual(got.Dependencies, tt.want) {
				t.Fatalf("dependencies = %#v, want %#v", got.Dependencies, tt.want)
			}
			if tt.want[0].Kind == KindASIMBuiltin && !strings.Contains(got.Reason, "native dependency probe") {
				t.Fatalf("reason = %q, want native dependency probe detail", got.Reason)
			}
			if tt.want[0].Kind == KindASIMBuiltin && got.BlockingStatus != "" {
				t.Fatalf("blocking status = %q, want deferred native probe only", got.BlockingStatus)
			}
		})
	}
}

func TestResolveKQLDependenciesWithFunctions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		query     string
		functions map[string]WorkspaceFunction
		status    backend.ResolutionStatus
		want      []Dependency
	}{
		{
			name:  "zero parameter function",
			query: `NormalisedSecurityEvents() | where TimeGenerated > ago(1h)`,
			functions: map[string]WorkspaceFunction{
				"NormalisedSecurityEvents": {Body: `SecurityEvent | where EventID != 0`},
			},
			status: backend.ResolutionResolved,
			want: []Dependency{
				{Name: "NormalisedSecurityEvents", Kind: KindFunction},
				{Name: "SecurityEvent", Kind: KindTable},
			},
		},
		{
			name:  "bare zero parameter parser function",
			query: `Veeam_GetSecurityEvents | where instanceId == 23090`,
			functions: map[string]WorkspaceFunction{
				"Veeam_GetSecurityEvents": {Body: `VeeamSecurityEvents_CL`},
			},
			status: backend.ResolutionResolved,
			want: []Dependency{
				{Name: "Veeam_GetSecurityEvents", Kind: KindFunction},
				{Name: "VeeamSecurityEvents_CL", Kind: KindTable},
			},
		},
		{
			name:  "workspace body overrides built in ASIM fallback",
			query: `imAuthentication | where TimeGenerated > ago(1h)`,
			functions: map[string]WorkspaceFunction{
				"imAuthentication": {Body: `SigninLogs`},
			},
			status: backend.ResolutionResolved,
			want: []Dependency{
				{Name: "imAuthentication", Kind: KindFunction},
				{Name: "SigninLogs", Kind: KindTable},
			},
		},
		{
			name:  "nested functions and local let scope",
			query: `PrimaryEvents() | join (IdentityInfo) on Account`,
			functions: map[string]WorkspaceFunction{
				"PrimaryEvents": {
					Body: `let Base = SecurityEvent; Base | union SecondaryEvents()`,
				},
				"SecondaryEvents": {Body: `SigninLogs`},
			},
			status: backend.ResolutionResolved,
			want: []Dependency{
				{Name: "PrimaryEvents", Kind: KindFunction},
				{Name: "SecurityEvent", Kind: KindTable},
				{Name: "SecondaryEvents", Kind: KindFunction},
				{Name: "SigninLogs", Kind: KindTable},
				{Name: "IdentityInfo", Kind: KindTable},
			},
		},
		{
			name:  "function body can resolve remote",
			query: `RemoteEvents()`,
			functions: map[string]WorkspaceFunction{
				"RemoteEvents": {Body: `workspace("other").SecurityEvent`},
			},
			status: backend.ResolutionRemote,
			want: []Dependency{
				{Name: "RemoteEvents", Kind: KindFunction},
				{Name: "SecurityEvent", Kind: KindRemoteTable, ScopeKind: "workspace", Scope: "other", Target: "SecurityEvent"},
			},
		},
		{
			name:  "parameterized metadata expands with positional literal",
			query: `EventsByType("process")`,
			functions: map[string]WorkspaceFunction{
				"EventsByType": {
					Body:       `SecurityEvent`,
					Parameters: []string{"eventType:string"},
				},
			},
			status: backend.ResolutionResolved,
			want: []Dependency{
				{Name: "EventsByType", Kind: KindFunction},
				{Name: "SecurityEvent", Kind: KindTable},
			},
		},
		{
			name:  "bare parameterized metadata is not expanded",
			query: `EventsByType`,
			functions: map[string]WorkspaceFunction{
				"EventsByType": {
					Body:       `SecurityEvent`,
					Parameters: []string{"eventType:string"},
				},
			},
			status: backend.ResolutionUnsupported,
			want:   []Dependency{{Name: "EventsByType", Kind: KindFunction}},
		},
		{
			name:  "named and default scalar arguments",
			query: `EventsByType(endtime=now(), eventType="process")`,
			functions: map[string]WorkspaceFunction{
				"EventsByType": {
					Body:       `SecurityEvent`,
					Parameters: []string{`eventType:string="all", endtime:datetime=now()`},
				},
			},
			status: backend.ResolutionResolved,
			want: []Dependency{
				{Name: "EventsByType", Kind: KindFunction},
				{Name: "SecurityEvent", Kind: KindTable},
			},
		},
		{
			name:  "defaults allow empty call",
			query: `EventsByType()`,
			functions: map[string]WorkspaceFunction{
				"EventsByType": {
					Body:       `SecurityEvent`,
					Parameters: []string{`eventType:string="all"`},
				},
			},
			status: backend.ResolutionResolved,
			want: []Dependency{
				{Name: "EventsByType", Kind: KindFunction},
				{Name: "SecurityEvent", Kind: KindTable},
			},
		},
		{
			name:  "malformed parameter metadata is ambiguous",
			query: `EventsByType("process")`,
			functions: map[string]WorkspaceFunction{
				"EventsByType": {Body: `SecurityEvent`, Parameters: []string{"eventType"}},
			},
			status: backend.ResolutionAmbiguous,
			want:   []Dependency{{Name: "EventsByType", Kind: KindFunction}},
		},
		{
			name:  "argument bearing call is not expanded",
			query: `EventsByType("process")`,
			functions: map[string]WorkspaceFunction{
				"EventsByType": {Body: `SecurityEvent`},
			},
			status: backend.ResolutionUnsupported,
			want:   []Dependency{{Name: "EventsByType", Kind: KindFunction}},
		},
		{
			name:  "missing function metadata",
			query: `MissingFunction()`,
			functions: map[string]WorkspaceFunction{
				"OtherFunction": {Body: `SecurityEvent`},
			},
			status: backend.ResolutionUnsupported,
			want:   []Dependency{{Name: "MissingFunction", Kind: KindFunction}},
		},
		{
			name:  "function cycle",
			query: `FunctionA()`,
			functions: map[string]WorkspaceFunction{
				"FunctionA": {Body: `FunctionB()`},
				"FunctionB": {Body: `FunctionA()`},
			},
			status: backend.ResolutionAmbiguous,
			want: []Dependency{
				{Name: "FunctionA", Kind: KindFunction},
				{Name: "FunctionB", Kind: KindFunction},
			},
		},
		{
			name:  "malformed function body",
			query: `BrokenFunction()`,
			functions: map[string]WorkspaceFunction{
				"BrokenFunction": {Body: `SecurityEvent | join (SigninLogs`},
			},
			status: backend.ResolutionAmbiguous,
			want:   []Dependency{{Name: "BrokenFunction", Kind: KindFunction}},
		},
		{
			name:  "function used as tabular membership expression",
			query: `SigninLogs | where UserPrincipalName in (KnownIdentities())`,
			functions: map[string]WorkspaceFunction{
				"KnownIdentities": {Body: `IdentityInfo | project AccountUPN`},
			},
			status: backend.ResolutionResolved,
			want: []Dependency{
				{Name: "SigninLogs", Kind: KindTable},
				{Name: "KnownIdentities", Kind: KindFunction},
				{Name: "IdentityInfo", Kind: KindTable},
			},
		},
		{
			name:  "function expansion inherits fuzzy union optionality",
			query: `union isfuzzy=true ParserFunction(), AuditLogs`,
			functions: map[string]WorkspaceFunction{
				"ParserFunction": {Body: `SecurityEvent`},
			},
			status: backend.ResolutionResolved,
			want: []Dependency{
				{Name: "ParserFunction", Kind: KindFunction, Optional: true},
				{Name: "SecurityEvent", Kind: KindTable, Optional: true},
				{Name: "AuditLogs", Kind: KindTable, Optional: true},
			},
		},
		{
			name:  "nested scalar parameter forwarding",
			query: `Outer("process")`,
			functions: map[string]WorkspaceFunction{
				"Outer": {
					Body:       `Inner(kind)`,
					Parameters: []string{"kind:string"},
				},
				"Inner": {
					Body:       `SecurityEvent`,
					Parameters: []string{"eventType:string"},
				},
			},
			status: backend.ResolutionResolved,
			want: []Dependency{
				{Name: "Outer", Kind: KindFunction},
				{Name: "Inner", Kind: KindFunction},
				{Name: "SecurityEvent", Kind: KindTable},
			},
		},
		{
			name:  "row context argument remains unassessed",
			query: `EventsByType(EventType)`,
			functions: map[string]WorkspaceFunction{
				"EventsByType": {Body: `SecurityEvent`, Parameters: []string{"eventType:string"}},
			},
			status: backend.ResolutionUnsupported,
			want:   []Dependency{{Name: "EventsByType", Kind: KindFunction}},
		},
		{
			name:  "scalar parameter cannot select a table",
			query: `EventsByType("SecurityEvent")`,
			functions: map[string]WorkspaceFunction{
				"EventsByType": {Body: `eventType`, Parameters: []string{"eventType:string"}},
			},
			status: backend.ResolutionUnsupported,
			want:   []Dependency{{Name: "EventsByType", Kind: KindFunction}},
		},
		{
			name:  "dynamic table selection in body remains unassessed",
			query: `EventsByType("SecurityEvent")`,
			functions: map[string]WorkspaceFunction{
				"EventsByType": {Body: `table(eventType)`, Parameters: []string{"eventType:string"}},
			},
			status: backend.ResolutionUnsupported,
			want:   []Dependency{{Name: "EventsByType", Kind: KindFunction}},
		},
		{
			name:  "tabular parameter metadata remains ambiguous",
			query: `PassThrough(SecurityEvent)`,
			functions: map[string]WorkspaceFunction{
				"PassThrough": {Body: `T`, Parameters: []string{"T:(*)"}},
			},
			status: backend.ResolutionAmbiguous,
			want:   []Dependency{{Name: "PassThrough", Kind: KindFunction}},
		},
		{
			name:  "metadata backed ASIM parser expands normally",
			query: `_Im_Authentication(starttime=ago(1d))`,
			functions: map[string]WorkspaceFunction{
				"_Im_Authentication": {Body: `SigninLogs`, Parameters: []string{"starttime:datetime"}},
			},
			status: backend.ResolutionResolved,
			want: []Dependency{
				{Name: "_Im_Authentication", Kind: KindFunction},
				{Name: "SigninLogs", Kind: KindTable},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ResolveKQLDependenciesWithFunctions(tt.query, tt.functions)
			if got.Status != tt.status {
				t.Fatalf("status = %q, want %q (reason: %s)", got.Status, tt.status, got.Reason)
			}
			if !reflect.DeepEqual(got.Dependencies, tt.want) {
				t.Fatalf("dependencies = %#v, want %#v", got.Dependencies, tt.want)
			}
		})
	}
}

func TestResolveKQLDependenciesASIMProbeSafety(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		query string
		want  []Dependency
	}{
		{
			name:  "literal arguments produce canonical probe call",
			query: `_Im_Dns(starttime=ago(1d), domain_has_any=dynamic(["example.com"]))`,
			want:  []Dependency{{Name: "_Im_Dns", Kind: KindASIMBuiltin, Call: `_Im_Dns(starttime=ago(1d),domain_has_any=dynamic(["example.com"]))`}},
		},
		{
			name:  "literal dynamic object produces canonical probe call",
			query: `_Im_Dns(filter=dynamic({"enabled":true,"limit":2}))`,
			want:  []Dependency{{Name: "_Im_Dns", Kind: KindASIMBuiltin, Call: `_Im_Dns(filter=dynamic({"enabled":true,"limit":2}))`}},
		},
		{
			name:  "row context argument never produces probe call",
			query: `_Im_Dns(starttime=StartTime)`,
			want:  []Dependency{{Name: "_Im_Dns", Kind: KindASIMBuiltin}},
		},
		{
			name:  "row context inside scalar constructor never produces probe call",
			query: `_Im_Dns(starttime=datetime(StartTime))`,
			want:  []Dependency{{Name: "_Im_Dns", Kind: KindASIMBuiltin}},
		},
		{
			name:  "dynamic identifier never produces probe call",
			query: `_Im_Dns(domain_has_any=dynamic([DomainName]))`,
			want:  []Dependency{{Name: "_Im_Dns", Kind: KindASIMBuiltin}},
		},
		{
			name:  "nested dynamic call never produces probe call",
			query: `_Im_Dns(domain_has_any=dynamic(pack_array(DomainName)))`,
			want:  []Dependency{{Name: "_Im_Dns", Kind: KindASIMBuiltin}},
		},
		{
			name:  "duplicate named argument never produces probe call",
			query: `_Im_Dns(starttime=ago(1d), starttime=now())`,
			want:  []Dependency{{Name: "_Im_Dns", Kind: KindASIMBuiltin}},
		},
		{
			name:  "membership parser is recognized as tabular",
			query: `SigninLogs | where UserPrincipalName in (_Im_Authentication(starttime=ago(1d)))`,
			want: []Dependency{
				{Name: "SigninLogs", Kind: KindTable},
				{Name: "_Im_Authentication", Kind: KindASIMBuiltin, Call: `_Im_Authentication(starttime=ago(1d))`},
			},
		},
		{
			name:  "fuzzy parser dependency is optional",
			query: `union isfuzzy=true _Im_Dns(), SecurityEvent`,
			want: []Dependency{
				{Name: "_Im_Dns", Kind: KindASIMBuiltin, Optional: true, Call: `_Im_Dns()`},
				{Name: "SecurityEvent", Kind: KindTable, Optional: true},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ResolveKQLDependencies(tt.query)
			if got.Status != backend.ResolutionUnsupported {
				t.Fatalf("status = %q, want %q (reason: %s)", got.Status, backend.ResolutionUnsupported, got.Reason)
			}
			if !reflect.DeepEqual(got.Dependencies, tt.want) {
				t.Fatalf("dependencies = %#v, want %#v", got.Dependencies, tt.want)
			}
		})
	}
}

func TestResolveKQLDependenciesWithFunctionsDepthGuard(t *testing.T) {
	t.Parallel()
	functions := make(map[string]WorkspaceFunction, maxKQLFunctionExpansionDepth+2)
	for i := 0; i < maxKQLFunctionExpansionDepth+1; i++ {
		name := fmt.Sprintf("Function%d", i)
		next := fmt.Sprintf("Function%d()", i+1)
		functions[name] = WorkspaceFunction{Body: next}
	}
	functions[fmt.Sprintf("Function%d", maxKQLFunctionExpansionDepth+1)] = WorkspaceFunction{Body: `SecurityEvent`}

	got := ResolveKQLDependenciesWithFunctions(`Function0()`, functions)
	if got.Status != backend.ResolutionAmbiguous {
		t.Fatalf("status = %q, want %q (reason: %s)", got.Status, backend.ResolutionAmbiguous, got.Reason)
	}
	if !strings.Contains(got.Reason, "depth limit") {
		t.Fatalf("reason = %q, want depth limit detail", got.Reason)
	}
}

func TestResolveKQLDependenciesRemote(t *testing.T) {
	t.Parallel()
	for _, function := range []string{"workspace", "app", "resource"} {
		function := function
		t.Run(function, func(t *testing.T) {
			t.Parallel()
			query := function + `("remote-id").SecurityEvent | where TimeGenerated > ago(1h)`
			got := ResolveKQLDependencies(query)
			if got.Status != backend.ResolutionRemote {
				t.Fatalf("status = %q, want %q (reason: %s)", got.Status, backend.ResolutionRemote, got.Reason)
			}
			want := []Dependency{{
				Name: "SecurityEvent", Kind: KindRemoteTable,
				ScopeKind: function, Scope: "remote-id", Target: "SecurityEvent",
			}}
			if !reflect.DeepEqual(got.Dependencies, want) {
				t.Fatalf("dependencies = %#v, want %#v", got.Dependencies, want)
			}
		})
	}
	for _, function := range []string{"cluster", "adx", "arg"} {
		function := function
		t.Run(function, func(t *testing.T) {
			t.Parallel()
			got := ResolveKQLDependencies(function + `("remote-id").SecurityEvent`)
			if got.Status != backend.ResolutionRemote {
				t.Fatalf("status = %q, want %q (reason: %s)", got.Status, backend.ResolutionRemote, got.Reason)
			}
			want := []Dependency{{Name: function, Kind: KindRemote}}
			if !reflect.DeepEqual(got.Dependencies, want) {
				t.Fatalf("dependencies = %#v, want %#v", got.Dependencies, want)
			}
		})
	}
}

func TestResolveKQLDependenciesMixedRemoteIsNotResolved(t *testing.T) {
	t.Parallel()
	got := ResolveKQLDependencies(`SecurityEvent | union workspace("remote").SigninLogs`)
	if got.Status != backend.ResolutionRemote {
		t.Fatalf("status = %q, want %q (reason: %s)", got.Status, backend.ResolutionRemote, got.Reason)
	}
	want := []Dependency{
		{Name: "SecurityEvent", Kind: KindTable},
		{Name: "SigninLogs", Kind: KindRemoteTable, ScopeKind: "workspace", Scope: "remote", Target: "SigninLogs"},
	}
	if !reflect.DeepEqual(got.Dependencies, want) {
		t.Fatalf("dependencies = %#v, want %#v", got.Dependencies, want)
	}
}

func TestResolveKQLDependenciesMixedDeferredAndUnresolvedRemainBlocking(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		query     string
		functions map[string]WorkspaceFunction
		status    backend.ResolutionStatus
		blocking  backend.ResolutionStatus
		want      []Dependency
	}{
		{
			name:   "mapped workspace and dynamic table",
			query:  `workspace("mapped").SecurityEvent | union table(DynamicName)`,
			status: backend.ResolutionRemote, blocking: backend.ResolutionUnsupported,
			want: []Dependency{{Name: "SecurityEvent", Kind: KindRemoteTable, ScopeKind: "workspace", Scope: "mapped", Target: "SecurityEvent"}},
		},
		{
			name:      "ASIM and missing function",
			query:     `SecurityEvent | union _Im_Dns(), UnknownFunction()`,
			functions: map[string]WorkspaceFunction{},
			status:    backend.ResolutionUnsupported, blocking: backend.ResolutionUnsupported,
			want: []Dependency{
				{Name: "SecurityEvent", Kind: KindTable},
				{Name: "_Im_Dns", Kind: KindASIMBuiltin, Call: "_Im_Dns()"},
				{Name: "UnknownFunction", Kind: KindFunction},
			},
		},
		{
			name:   "watchlist and dynamic table",
			query:  `SecurityEvent | union _GetWatchlist("VIPs"), table(DynamicName)`,
			status: backend.ResolutionUnsupported, blocking: backend.ResolutionUnsupported,
			want: []Dependency{
				{Name: "SecurityEvent", Kind: KindTable},
				{Name: "VIPs", Kind: KindWatchlist},
			},
		},
		{
			name:  "watchlist and ambiguous function metadata",
			query: `union _GetWatchlist("VIPs"), Broken("value")`,
			functions: map[string]WorkspaceFunction{
				"Broken": {Body: `SecurityEvent`, Parameters: []string{"value"}},
			},
			status: backend.ResolutionAmbiguous, blocking: backend.ResolutionAmbiguous,
			want: []Dependency{
				{Name: "VIPs", Kind: KindWatchlist},
				{Name: "Broken", Kind: KindFunction},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ResolveKQLDependenciesWithFunctions(tt.query, tt.functions)
			if got.Status != tt.status || got.BlockingStatus != tt.blocking || strings.TrimSpace(got.BlockingReason) == "" {
				t.Fatalf("resolution = %+v, want status %s with blocking status %s", got, tt.status, tt.blocking)
			}
			if !reflect.DeepEqual(got.Dependencies, tt.want) {
				t.Fatalf("dependencies = %#v, want %#v", got.Dependencies, tt.want)
			}
		})
	}
}

func TestResolveKQLDependenciesWatchlists(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		query string
		want  []Dependency
	}{
		{
			name:  "watchlist source",
			query: `_GetWatchlist("VIPUsers") | where SearchKey != ""`,
			want:  []Dependency{{Name: "VIPUsers", Kind: KindWatchlist}},
		},
		{
			name:  "watchlist membership subquery",
			query: `SigninLogs | where UserPrincipalName in (_GetWatchlist("VIPUsers") | project SearchKey)`,
			want: []Dependency{
				{Name: "SigninLogs", Kind: KindTable},
				{Name: "VIPUsers", Kind: KindWatchlist},
			},
		},
		{
			name:  "escaped literal aliases are decoded",
			query: `_GetWatchlist('VIP''Users') | union _GetWatchlist("Ops\\Team")`,
			want: []Dependency{
				{Name: "VIP'Users", Kind: KindWatchlist},
				{Name: "Ops\\Team", Kind: KindWatchlist},
			},
		},
		{
			name:  "fuzzy watchlists are optional",
			query: `union isfuzzy=true _GetWatchlist("VIPUsers"), SecurityEvent`,
			want: []Dependency{
				{Name: "VIPUsers", Kind: KindWatchlist, Optional: true},
				{Name: "SecurityEvent", Kind: KindTable, Optional: true},
			},
		},
		{
			name:  "required duplicate wins",
			query: `union isfuzzy=true _GetWatchlist("VIPUsers"), SecurityEvent | union _GetWatchlist("VIPUsers")`,
			want: []Dependency{
				{Name: "VIPUsers", Kind: KindWatchlist},
				{Name: "SecurityEvent", Kind: KindTable, Optional: true},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ResolveKQLDependencies(tt.query)
			if got.Status != backend.ResolutionResolved {
				t.Fatalf("status = %q, want %q (reason: %s)", got.Status, backend.ResolutionResolved, got.Reason)
			}
			if !reflect.DeepEqual(got.Dependencies, tt.want) {
				t.Fatalf("dependencies = %#v, want %#v", got.Dependencies, tt.want)
			}
		})
	}
}

func TestResolveKQLDependenciesRemoteLiteralBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		query  string
		status backend.ResolutionStatus
		want   []Dependency
	}{
		{
			name:   "escaped scope is retained",
			query:  `workspace('tenant''s-workspace').SecurityEvent`,
			status: backend.ResolutionRemote,
			want: []Dependency{{
				Name: "SecurityEvent", Kind: KindRemoteTable, ScopeKind: "workspace",
				Scope: "tenant's-workspace", Target: "SecurityEvent",
			}},
		},
		{
			name:   "same table in different scopes remains distinct",
			query:  `union workspace("one").SecurityEvent, workspace("two").SecurityEvent`,
			status: backend.ResolutionRemote,
			want: []Dependency{
				{Name: "SecurityEvent", Kind: KindRemoteTable, ScopeKind: "workspace", Scope: "one", Target: "SecurityEvent"},
				{Name: "SecurityEvent", Kind: KindRemoteTable, ScopeKind: "workspace", Scope: "two", Target: "SecurityEvent"},
			},
		},
		{
			name:   "fuzzy remote source is optional",
			query:  `union isfuzzy=true workspace("one").SecurityEvent, SigninLogs`,
			status: backend.ResolutionRemote,
			want: []Dependency{
				{Name: "SecurityEvent", Kind: KindRemoteTable, Optional: true, ScopeKind: "workspace", Scope: "one", Target: "SecurityEvent"},
				{Name: "SigninLogs", Kind: KindTable, Optional: true},
			},
		},
		{
			name:   "computed scope is generic remote",
			query:  `workspace(WorkspaceId).SecurityEvent`,
			status: backend.ResolutionRemote,
			want:   []Dependency{{Name: "workspace", Kind: KindRemote}},
		},
		{
			name:   "member chain is not direct table evidence",
			query:  `workspace("one").database("db").SecurityEvent`,
			status: backend.ResolutionRemote,
			want:   []Dependency{{Name: "workspace", Kind: KindRemote}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ResolveKQLDependencies(tt.query)
			if got.Status != tt.status {
				t.Fatalf("status = %q, want %q (reason: %s)", got.Status, tt.status, got.Reason)
			}
			if !reflect.DeepEqual(got.Dependencies, tt.want) {
				t.Fatalf("dependencies = %#v, want %#v", got.Dependencies, tt.want)
			}
			for _, dependency := range got.Dependencies {
				if dependency.Call != "" {
					t.Fatalf("dynamic/remote dependency unexpectedly produced call %q", dependency.Call)
				}
			}
		})
	}
}

func TestResolveKQLDependenciesUnsupportedSources(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		query string
	}{
		{name: "wildcard union", query: `union Security*, SigninLogs`},
		{name: "wildcard quoted union", query: `union ['Security*']`},
		{name: "search all tables", query: `search "failed password"`},
		{name: "wildcard search list", query: `search in (Security*) "failed password"`},
		{name: "external data", query: `externaldata(value:string)["https://example.invalid/data.csv"]`},
		{name: "data table", query: `datatable(value:string)["sample"]`},
		{name: "watchlist alias", query: `_GetWatchlistAlias("VIPUsers")`},
		{name: "dynamic watchlist", query: `_GetWatchlist(WatchlistAlias)`},
		{name: "empty watchlist", query: `_GetWatchlist("")`},
		{name: "dynamic table", query: `table(TableName) | count`},
		{name: "dynamic membership subquery", query: `SigninLogs | where UserPrincipalName in (table(TableName) | project AccountUPN)`},
		{name: "materialize", query: `materialize(SecurityEvent | where EventID == 4688)`},
		{name: "invoke", query: `SecurityEvent | invoke EnrichAccount()`},
		{name: "evaluate", query: `SecurityEvent | evaluate autocluster()`},
		{name: "fork", query: `SecurityEvent | fork (where EventID == 1) (where EventID == 2)`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ResolveKQLDependencies(tt.query)
			if got.Status != backend.ResolutionUnsupported {
				t.Fatalf("status = %q, want %q (reason: %s, dependencies: %#v)", got.Status, backend.ResolutionUnsupported, got.Reason, got.Dependencies)
			}
		})
	}
}

func TestResolveKQLDependenciesInvokeExposesFunction(t *testing.T) {
	t.Parallel()
	got := ResolveKQLDependencies(`SecurityEvent | invoke EnrichAccount()`)
	if got.Status != backend.ResolutionUnsupported {
		t.Fatalf("status = %q, want %q (reason: %s)", got.Status, backend.ResolutionUnsupported, got.Reason)
	}
	want := []Dependency{
		{Name: "SecurityEvent", Kind: KindTable},
		{Name: "EnrichAccount", Kind: KindFunction},
	}
	if !reflect.DeepEqual(got.Dependencies, want) {
		t.Fatalf("dependencies = %#v, want %#v", got.Dependencies, want)
	}
}

func TestResolveKQLDependenciesRemoteMembershipSubqueryIsNotResolved(t *testing.T) {
	t.Parallel()
	got := ResolveKQLDependencies(`SigninLogs | where UserPrincipalName in (workspace("remote").IdentityInfo | project AccountUPN)`)
	if got.Status != backend.ResolutionRemote {
		t.Fatalf("status = %q, want %q (reason: %s)", got.Status, backend.ResolutionRemote, got.Reason)
	}
	want := []Dependency{
		{Name: "SigninLogs", Kind: KindTable},
		{Name: "IdentityInfo", Kind: KindRemoteTable, ScopeKind: "workspace", Scope: "remote", Target: "IdentityInfo"},
	}
	if !reflect.DeepEqual(got.Dependencies, want) {
		t.Fatalf("dependencies = %#v, want %#v", got.Dependencies, want)
	}
}

func TestResolveKQLDependenciesAmbiguous(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		query string
	}{
		{name: "unmatched open paren", query: `SecurityEvent | join (SigninLogs on Account`},
		{name: "unmatched close paren", query: `SecurityEvent)`},
		{name: "unterminated string", query: `SecurityEvent | where Message == "oops`},
		{name: "unterminated comment", query: `SecurityEvent /* no end`},
		{name: "operator without source", query: `where EventID == 4688`},
		{name: "empty quoted table", query: `[''] | count`},
		{name: "join without on", query: `SecurityEvent | join (SigninLogs)`},
		{name: "lookup without source", query: `SecurityEvent | lookup on Account`},
		{name: "empty union operand", query: `union SecurityEvent,`},
		{name: "nonliteral fuzzy option", query: `union isfuzzy=Maybe SecurityEvent, SigninLogs`},
		{name: "scalar let used as source", query: `let Source = 5; Source | count`},
		{name: "alias cycle", query: `let A = B; let B = A; A | count`},
		{name: "let only", query: `let Source = SecurityEvent;`},
		{name: "single unbound membership name", query: `SigninLogs | where UserPrincipalName in (IdentityInfo)`},
		{name: "scalar let used as membership source", query: `let Known = 5; SigninLogs | where EventID in (Known)`},
		{name: "unknown membership function", query: `SigninLogs | where UserPrincipalName in (KnownIdentities())`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ResolveKQLDependencies(tt.query)
			if got.Status != backend.ResolutionAmbiguous {
				t.Fatalf("status = %q, want %q (reason: %s, dependencies: %#v)", got.Status, backend.ResolutionAmbiguous, got.Reason, got.Dependencies)
			}
		})
	}
}

func TestResolveKQLDependenciesEmpty(t *testing.T) {
	t.Parallel()
	for _, query := range []string{"", "  \n\t", "// comment only", "/* comment only */"} {
		got := ResolveKQLDependencies(query)
		if got.Status != backend.ResolutionEmpty {
			t.Fatalf("query %q: status = %q, want %q (reason: %s)", query, got.Status, backend.ResolutionEmpty, got.Reason)
		}
		if len(got.Dependencies) != 0 {
			t.Fatalf("query %q: dependencies = %#v, want none", query, got.Dependencies)
		}
	}
}

func TestResolveKQLDependenciesDoesNotTreatScalarFunctionsAsSources(t *testing.T) {
	t.Parallel()
	got := ResolveKQLDependencies(`SecurityEvent | where Account has CustomScalar(UserName) and Message !has "datatable("`)
	if got.Status != backend.ResolutionResolved {
		t.Fatalf("status = %q, want %q (reason: %s)", got.Status, backend.ResolutionResolved, got.Reason)
	}
	want := []Dependency{{Name: "SecurityEvent", Kind: KindTable}}
	if !reflect.DeepEqual(got.Dependencies, want) {
		t.Fatalf("dependencies = %#v, want %#v", got.Dependencies, want)
	}
}
