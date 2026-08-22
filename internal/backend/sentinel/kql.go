package sentinel

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/alephnull-sh/deadair/internal/backend"
)

// DependencyKind identifies the kind of KQL source reference found in a rule.
type DependencyKind string

const (
	// KindTable is a direct local Log Analytics table reference.
	KindTable DependencyKind = "table"
	// KindFunction is a tabular function reference that needs workspace metadata
	// before it can be expanded safely.
	KindFunction DependencyKind = "function"
	// KindWatchlist is a literal Microsoft Sentinel watchlist alias.
	KindWatchlist DependencyKind = "watchlist"
	// KindRemoteTable is a direct table in a literal workspace, application,
	// or Azure resource scope. The client still has to allowlist and inventory
	// the scope before it can become graph evidence.
	KindRemoteTable DependencyKind = "remote_table"
	// KindASIMBuiltin is a recognized built-in ASIM parser that was not present
	// in workspace metadata and therefore needs a bounded native dependency
	// probe before its tables can be assessed.
	KindASIMBuiltin DependencyKind = "asim_builtin"
	// KindRemote is a source resolved outside the rule's local workspace.
	KindRemote DependencyKind = "remote"
)

// Dependency is one source reference extracted from a KQL query. Dependencies
// retain query order and are de-duplicated by kind and name.
type Dependency struct {
	Name      string
	Kind      DependencyKind
	Optional  bool
	ScopeKind string
	Scope     string
	Target    string
	// Call is populated only for a parser-generated, validated built-in ASIM
	// invocation. It is safe to use as the source of a zero-row native probe.
	Call string
}

// KQLResolution describes how far syntax and supplied workspace metadata can
// resolve a query's data dependencies. Dependencies retains local tables and
// the bounded non-table references that the client must verify separately.
// Callers must not turn a dependency into graph evidence until the relevant
// inventory or native probe has succeeded.
type KQLResolution struct {
	Status       backend.ResolutionStatus
	Dependencies []Dependency
	Reason       string
	// BlockingStatus is set only when an unresolved construct remains after
	// any literal workspace, watchlist, or built-in ASIM dependency is probed.
	// It keeps an independent dynamic or ambiguous query leg from inheriting
	// the deferred dependency's eventual result.
	BlockingStatus backend.ResolutionStatus
	BlockingReason string
}

// WorkspaceFunction is the metadata needed to expand a stored Log Analytics
// function. Parameters contains the raw parameter declaration returned by the
// workspace metadata API.
type WorkspaceFunction struct {
	Body string
	// Parameters retains the metadata API's raw comma-separated parameter
	// declaration. A slice is kept for compatibility with existing callers;
	// the analyzer parses the joined declaration before expanding the body.
	Parameters []string
}

// ResolveKQLDependencies extracts conservative source evidence from a Sentinel
// scheduled-rule query. It handles direct tables, explicit union/search lists,
// joins, lookups, and simple let-bound table aliases. Anything that needs Kusto
// metadata or could select data dynamically remains unassessed.
func ResolveKQLDependencies(query string) KQLResolution {
	return ResolveKQLDependenciesWithFunctions(query, nil)
}

// ResolveKQLDependenciesWithFunctions expands workspace functions whose
// signatures and calls use bounded scalar parameters. Missing, recursive,
// tabular, source-selecting, or runtime-dependent functions stay unassessed.
func ResolveKQLDependenciesWithFunctions(query string, functions map[string]WorkspaceFunction) KQLResolution {
	tokens, err := lexKQL(query)
	if err != nil {
		return KQLResolution{
			Status: backend.ResolutionAmbiguous,
			Reason: err.Error(),
		}
	}
	if len(tokens) == 0 {
		return KQLResolution{
			Status: backend.ResolutionEmpty,
			Reason: "KQL query is empty",
		}
	}
	if err := validateKQLParens(tokens); err != nil {
		return KQLResolution{
			Status: backend.ResolutionAmbiguous,
			Reason: err.Error(),
		}
	}

	a := &kqlAnalyzer{
		bindings:           make(map[string][]kqlToken),
		resolving:          make(map[string]bool),
		scalarResolving:    make(map[string]bool),
		functions:          functions,
		scalarParameters:   make(map[string]bool),
		resolvingFunctions: make(map[string]bool),
		seenDeps:           make(map[string]int),
		seenNotes:          make(map[string]struct{}),
		seenBlockingNotes:  make(map[string]struct{}),
	}
	a.parseProgram(tokens)
	return a.result()
}

type kqlTokenKind uint8

const (
	kqlIdentifier kqlTokenKind = iota
	kqlString
	kqlOther
)

type kqlToken struct {
	kind    kqlTokenKind
	text    string
	quoted  bool
	escaped bool
}

func lexKQL(query string) ([]kqlToken, error) {
	query = strings.TrimPrefix(query, "\ufeff")
	tokens := make([]kqlToken, 0, len(query)/4)
	for i := 0; i < len(query); {
		r, size := utf8.DecodeRuneInString(query[i:])
		if unicode.IsSpace(r) {
			i += size
			continue
		}
		if strings.HasPrefix(query[i:], "//") {
			if end := strings.IndexByte(query[i+2:], '\n'); end >= 0 {
				i += end + 3
			} else {
				i = len(query)
			}
			continue
		}
		if strings.HasPrefix(query[i:], "/*") {
			end := strings.Index(query[i+2:], "*/")
			if end < 0 {
				return nil, fmt.Errorf("KQL query contains an unterminated block comment")
			}
			i += end + 4
			continue
		}
		if query[i] == '\'' || query[i] == '"' {
			next, value, escaped, err := consumeKQLQuoted(query, i)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, kqlToken{kind: kqlString, text: value, escaped: escaped})
			i = next
			continue
		}
		if query[i] == '[' && i+1 < len(query) && (query[i+1] == '\'' || query[i+1] == '"') {
			next, text, escaped, err := consumeKQLQuoted(query, i+1)
			if err != nil {
				return nil, err
			}
			if next >= len(query) || query[next] != ']' {
				return nil, fmt.Errorf("KQL query contains an unterminated quoted identifier")
			}
			tokens = append(tokens, kqlToken{kind: kqlIdentifier, text: text, quoted: true, escaped: escaped})
			i = next + 1
			continue
		}
		if isKQLIdentifierStart(r) {
			start := i
			i += size
			for i < len(query) {
				r, size = utf8.DecodeRuneInString(query[i:])
				if !isKQLIdentifierContinue(r) {
					break
				}
				i += size
			}
			tokens = append(tokens, kqlToken{kind: kqlIdentifier, text: query[start:i]})
			continue
		}
		if unicode.IsDigit(r) {
			start := i
			i += size
			for i < len(query) {
				r, size = utf8.DecodeRuneInString(query[i:])
				if !unicode.IsDigit(r) && r != '.' {
					break
				}
				i += size
			}
			tokens = append(tokens, kqlToken{kind: kqlOther, text: query[start:i]})
			continue
		}
		tokens = append(tokens, kqlToken{kind: kqlOther, text: string(r)})
		i += size
	}
	return tokens, nil
}

func consumeKQLQuoted(query string, start int) (int, string, bool, error) {
	quote := query[start]
	var value strings.Builder
	escaped := false
	for i := start + 1; i < len(query); i++ {
		switch query[i] {
		case quote:
			if i+1 < len(query) && query[i+1] == quote {
				value.WriteByte(quote)
				i++
				continue
			}
			return i + 1, value.String(), escaped, nil
		case '\\':
			if i+1 < len(query) {
				escaped = true
				value.WriteByte(query[i+1])
				i++
				continue
			}
		}
		value.WriteByte(query[i])
	}
	return 0, "", escaped, fmt.Errorf("KQL query contains an unterminated string")
}

func isKQLIdentifierStart(r rune) bool {
	return r == '_' || r == '$' || unicode.IsLetter(r)
}

func isKQLIdentifierContinue(r rune) bool {
	return isKQLIdentifierStart(r) || unicode.IsDigit(r)
}

func validateKQLParens(tokens []kqlToken) error {
	depth := 0
	for _, token := range tokens {
		switch token.text {
		case "(":
			depth++
		case ")":
			depth--
			if depth < 0 {
				return fmt.Errorf("KQL query contains an unmatched closing parenthesis")
			}
		}
	}
	if depth != 0 {
		return fmt.Errorf("KQL query contains an unmatched opening parenthesis")
	}
	return nil
}

type kqlAnalyzer struct {
	bindings            map[string][]kqlToken
	resolving           map[string]bool
	scalarResolving     map[string]bool
	functions           map[string]WorkspaceFunction
	scalarParameters    map[string]bool
	resolvingFunctions  map[string]bool
	functionDepth       int
	deps                []Dependency
	seenDeps            map[string]int
	notes               []string
	seenNotes           map[string]struct{}
	blockingNotes       []string
	seenBlockingNotes   map[string]struct{}
	remote              bool
	unsupported         bool
	deferredUnsupported bool
	ambiguous           bool
	optionalDepth       int
}

const maxKQLFunctionExpansionDepth = 32

func (a *kqlAnalyzer) parseProgram(tokens []kqlToken) {
	statements := splitKQLTopLevel(tokens, ";")
	for len(statements) > 0 && len(statements[len(statements)-1]) == 0 {
		statements = statements[:len(statements)-1]
	}
	if len(statements) == 0 {
		return
	}

	var main []kqlToken
	for i, statement := range statements {
		statement = trimKQLTokens(statement)
		if len(statement) == 0 {
			continue
		}
		if kqlWord(statement[0], "let") {
			if len(statement) < 4 || statement[1].kind != kqlIdentifier || statement[2].text != "=" {
				a.markAmbiguous("KQL let binding is not a simple named assignment")
				continue
			}
			a.bindings[statement[1].text] = cloneKQLTokens(statement[3:])
			if i == len(statements)-1 {
				a.markAmbiguous("KQL query ends with a let binding and has no query expression")
			}
			continue
		}
		if kqlWord(statement[0], "declare") && i < len(statements)-1 {
			continue
		}
		if i != len(statements)-1 {
			a.markAmbiguous("KQL query contains an unsupported top-level statement")
			continue
		}
		main = statement
	}
	if len(main) > 0 {
		a.parseQuery(main)
	}
}

func cloneKQLTokens(tokens []kqlToken) []kqlToken {
	return append([]kqlToken(nil), tokens...)
}

func (a *kqlAnalyzer) parseQuery(tokens []kqlToken) {
	tokens = stripKQLOuterParens(trimKQLTokens(tokens))
	if len(tokens) == 0 {
		a.markAmbiguous("KQL source expression is empty")
		return
	}
	// parseQuery can run while a fuzzy-union operand is optional. Its deferred
	// scan must retain that context after parseUnion restores optionalDepth.
	scanOptionalDepth := a.optionalDepth
	defer func() {
		currentOptionalDepth := a.optionalDepth
		a.optionalDepth = scanOptionalDepth
		a.scanUnsupportedCalls(tokens)
		a.optionalDepth = currentOptionalDepth
	}()

	firstPipe := findKQLTopLevel(tokens, 0, "|")
	headEnd := len(tokens)
	if firstPipe >= 0 {
		headEnd = firstPipe
	}
	head := tokens[:headEnd]
	if len(head) > 0 && !kqlWord(head[0], "union") {
		a.parseScalarBindingReferences(head)
	}
	a.parseSourceSegment(head)

	for pos := firstPipe; pos >= 0 && pos < len(tokens); {
		next := findKQLTopLevel(tokens, pos+1, "|")
		end := len(tokens)
		if next >= 0 {
			end = next
		}
		a.parsePipelineSegment(trimKQLTokens(tokens[pos+1 : end]))
		pos = next
	}
}

func (a *kqlAnalyzer) parseSourceSegment(tokens []kqlToken) {
	tokens = trimKQLTokens(tokens)
	if len(tokens) == 0 {
		a.markAmbiguous("KQL source expression is empty")
		return
	}

	switch {
	case kqlWord(tokens[0], "union"):
		a.parseUnion(tokens)
		return
	case kqlWord(tokens[0], "search"), kqlWord(tokens[0], "find"):
		a.parseSearch(tokens)
		return
	case kqlWord(tokens[0], "externaldata"):
		a.markUnsupported("externaldata sources are not assessed")
		return
	case kqlWord(tokens[0], "datatable"):
		a.markUnsupported("datatable sources are not assessed")
		return
	case kqlWord(tokens[0], "print"), kqlWord(tokens[0], "range"):
		a.markUnsupported(fmt.Sprintf("%s queries do not identify a local table source", strings.ToLower(tokens[0].text)))
		return
	}

	consumed := a.parseOneSource(tokens)
	if consumed == 0 {
		return
	}
	if consumed != len(tokens) {
		a.markAmbiguous("KQL source expression is not a direct table, alias, or tabular function")
	}
}

func (a *kqlAnalyzer) parseOneSource(tokens []kqlToken) int {
	tokens = trimKQLTokens(tokens)
	if len(tokens) == 0 {
		a.markAmbiguous("KQL source expression is empty")
		return 0
	}
	if tokens[0].text == "(" {
		close, ok := matchingKQLParen(tokens, 0)
		if !ok {
			a.markAmbiguous("KQL source expression has unmatched parentheses")
			return 0
		}
		a.parseQuery(tokens[1:close])
		return close + 1
	}
	if tokens[0].kind != kqlIdentifier {
		a.markAmbiguous("KQL source expression does not start with a named table or function")
		return 0
	}

	name := tokens[0].text
	if strings.TrimSpace(name) == "" {
		a.markAmbiguous("KQL table or function name is empty")
		return 0
	}
	if strings.Contains(name, "*") || (len(tokens) > 1 && tokens[1].text == "*") {
		a.markUnsupported("wildcard table sources are not assessed")
		return len(tokens)
	}
	if len(tokens) > 1 && tokens[1].text == "(" {
		close, ok := matchingKQLParen(tokens, 1)
		if !ok {
			a.markAmbiguous(fmt.Sprintf("KQL function %s has unmatched parentheses", name))
			return 0
		}
		consumed := consumeKQLCallChain(tokens, close+1)
		switch {
		case isKQLLiteralScopeFunction(name):
			dependency, ok := literalRemoteTableDependency(name, tokens, close)
			if ok {
				a.addDependency(dependency)
			} else {
				a.addDependency(Dependency{Name: name, Kind: KindRemote})
				a.addNote(fmt.Sprintf("remote source %s() does not use a literal scope and direct table member", name))
			}
			a.remote = true
		case isKQLUnsupportedRemoteFunction(name):
			a.addDependency(Dependency{Name: name, Kind: KindRemote})
			a.remote = true
			a.addNote(fmt.Sprintf("remote source %s() is not assessed", name))
		case strings.EqualFold(name, "_GetWatchlist"):
			alias, ok := literalWatchlistAlias(tokens[2:close])
			if !ok {
				a.markUnsupported("_GetWatchlist requires exactly one non-empty string literal alias")
			} else {
				a.addDependency(Dependency{Name: alias, Kind: KindWatchlist})
			}
		case isKQLWatchlistFunction(name):
			a.markUnsupported(fmt.Sprintf("Sentinel watchlist function %s is not assessed", name))
		case isKQLDynamicSourceFunction(name):
			a.markUnsupported(fmt.Sprintf("dynamic source function %s() is not assessed", name))
		default:
			if _, exists := a.functions[name]; exists {
				a.addDependency(Dependency{Name: name, Kind: KindFunction})
				a.expandWorkspaceFunction(name, tokens[2:close], true)
			} else if isKQLASIMParserName(name) {
				call, ok := a.canonicalASIMCall(name, tokens[2:close], true)
				a.addDependency(Dependency{Name: name, Kind: KindASIMBuiltin, Call: call})
				if ok {
					a.markDeferredUnsupported(fmt.Sprintf("built-in ASIM parser %s requires a native dependency probe", name))
				} else {
					a.markUnsupported(fmt.Sprintf("built-in ASIM parser %s has non-literal or unsupported arguments", name))
				}
			} else {
				a.addDependency(Dependency{Name: name, Kind: KindFunction})
				a.expandWorkspaceFunction(name, tokens[2:close], true)
			}
		}
		return consumed
	}
	if binding, ok := a.bindings[name]; ok {
		if a.resolving[name] {
			a.markAmbiguous(fmt.Sprintf("KQL let aliases contain a cycle at %s", name))
			return 1
		}
		a.resolving[name] = true
		a.parseQuery(binding)
		delete(a.resolving, name)
		return 1
	}
	if _, ok := a.functions[name]; ok {
		a.addDependency(Dependency{Name: name, Kind: KindFunction})
		a.expandWorkspaceFunction(name, nil, false)
		return 1
	}
	if isKQLASIMParserName(name) {
		a.addDependency(Dependency{Name: name, Kind: KindASIMBuiltin, Call: name})
		a.markDeferredUnsupported(fmt.Sprintf("built-in ASIM parser %s requires a native dependency probe", name))
		return 1
	}
	if a.scalarParameters[name] {
		a.markUnsupported(fmt.Sprintf("scalar function parameter %s cannot select a table", name))
		return 1
	}
	if !tokens[0].quoted && isKQLNonSourceKeyword(name) {
		a.markAmbiguous(fmt.Sprintf("KQL starts with operator %s instead of a source", name))
		return 0
	}
	if strings.HasPrefix(name, "$") {
		a.markAmbiguous(fmt.Sprintf("KQL source %s is contextual and cannot be resolved directly", name))
		return 0
	}
	a.addDependency(Dependency{Name: name, Kind: KindTable})
	return 1
}

func (a *kqlAnalyzer) expandWorkspaceFunction(name string, arguments []kqlToken, called bool) {
	function, ok := a.functions[name]
	if !ok {
		a.markUnsupported(fmt.Sprintf("tabular function %s() requires workspace metadata expansion", name))
		return
	}
	parameters, err := parseWorkspaceFunctionParameters(function.Parameters)
	if err != nil {
		a.markAmbiguous(fmt.Sprintf("workspace function %s() has invalid parameter metadata: %v", name, err))
		return
	}
	if !called && len(parameters) != 0 {
		a.markUnsupported(fmt.Sprintf("parameterized tabular function %s must be invoked with parentheses", name))
		return
	}
	if err := a.validateWorkspaceFunctionArguments(parameters, arguments); err != nil {
		a.markUnsupported(fmt.Sprintf("workspace function %s() arguments are not assessed: %v", name, err))
		return
	}
	if a.resolvingFunctions[name] {
		a.markAmbiguous(fmt.Sprintf("workspace functions contain a cycle at %s()", name))
		return
	}
	if a.functionDepth >= maxKQLFunctionExpansionDepth {
		a.markAmbiguous(fmt.Sprintf("workspace function expansion exceeds the depth limit at %s()", name))
		return
	}

	tokens, err := lexKQL(function.Body)
	if err != nil {
		a.markAmbiguous(fmt.Sprintf("workspace function %s() has an invalid body: %v", name, err))
		return
	}
	if len(tokens) == 0 {
		a.markAmbiguous(fmt.Sprintf("workspace function %s() has an empty body", name))
		return
	}
	if err := validateKQLParens(tokens); err != nil {
		a.markAmbiguous(fmt.Sprintf("workspace function %s() has an invalid body: %v", name, err))
		return
	}

	savedBindings := a.bindings
	savedResolving := a.resolving
	savedScalarResolving := a.scalarResolving
	savedScalarParameters := a.scalarParameters
	a.bindings = make(map[string][]kqlToken)
	a.resolving = make(map[string]bool)
	a.scalarResolving = make(map[string]bool)
	a.scalarParameters = make(map[string]bool, len(parameters))
	for _, parameter := range parameters {
		a.scalarParameters[parameter.name] = true
	}
	a.resolvingFunctions[name] = true
	a.functionDepth++
	a.parseProgram(tokens)
	a.functionDepth--
	delete(a.resolvingFunctions, name)
	a.bindings = savedBindings
	a.resolving = savedResolving
	a.scalarResolving = savedScalarResolving
	a.scalarParameters = savedScalarParameters
}

type workspaceFunctionParameter struct {
	name       string
	typeName   string
	hasDefault bool
	defaultArg []kqlToken
}

func parseWorkspaceFunctionParameters(raw []string) ([]workspaceFunctionParameter, error) {
	declaration := strings.TrimSpace(strings.Join(raw, ","))
	if declaration == "" || declaration == "()" {
		return nil, nil
	}
	tokens, err := lexKQL(declaration)
	if err != nil {
		return nil, err
	}
	if len(tokens) >= 2 && tokens[0].text == "(" {
		if close, ok := matchingKQLParen(tokens, 0); ok && close == len(tokens)-1 {
			tokens = tokens[1:close]
		}
	}
	parts := splitKQLTopLevel(tokens, ",")
	parameters := make([]workspaceFunctionParameter, 0, len(parts))
	seen := make(map[string]bool, len(parts))
	optionalSeen := false
	for _, part := range parts {
		part = trimKQLTokens(part)
		if len(part) < 3 || part[0].kind != kqlIdentifier || part[1].text != ":" {
			return nil, fmt.Errorf("expected name:type parameter declaration")
		}
		name := part[0].text
		if seen[name] {
			return nil, fmt.Errorf("duplicate parameter %s", name)
		}
		seen[name] = true
		if part[2].text == "(" {
			return nil, fmt.Errorf("tabular parameter %s is not supported", name)
		}
		if part[2].kind != kqlIdentifier || !isSupportedKQLScalarType(part[2].text) {
			return nil, fmt.Errorf("parameter %s has unsupported type %s", name, part[2].text)
		}
		parameter := workspaceFunctionParameter{name: name, typeName: strings.ToLower(part[2].text)}
		if len(part) > 3 {
			if part[3].text != "=" || len(part) == 4 {
				return nil, fmt.Errorf("parameter %s has an invalid default", name)
			}
			parameter.hasDefault = true
			parameter.defaultArg = cloneKQLTokens(part[4:])
			if _, ok := canonicalSimpleScalar(parameter.defaultArg, nil); !ok {
				return nil, fmt.Errorf("parameter %s has a non-literal default", name)
			}
			optionalSeen = true
		} else if optionalSeen {
			return nil, fmt.Errorf("required parameter %s follows a defaulted parameter", name)
		}
		parameters = append(parameters, parameter)
	}
	return parameters, nil
}

func isSupportedKQLScalarType(name string) bool {
	switch strings.ToLower(name) {
	case "bool", "boolean", "string", "long", "int", "int64", "datetime", "date", "timespan", "time", "real", "double", "decimal", "dynamic", "guid":
		return true
	default:
		return false
	}
}

func (a *kqlAnalyzer) validateWorkspaceFunctionArguments(parameters []workspaceFunctionParameter, arguments []kqlToken) error {
	if len(parameters) == 0 {
		if len(trimKQLTokens(arguments)) != 0 {
			return fmt.Errorf("function declares no parameters")
		}
		return nil
	}
	parts := splitKQLTopLevel(arguments, ",")
	if len(parts) == 1 && len(trimKQLTokens(parts[0])) == 0 {
		parts = nil
	}
	byName := make(map[string]int, len(parameters))
	for i, parameter := range parameters {
		byName[parameter.name] = i
	}
	assigned := make(map[int]bool, len(parts))
	positional := 0
	namedSeen := false
	for _, part := range parts {
		part = trimKQLTokens(part)
		if len(part) == 0 {
			return fmt.Errorf("empty argument")
		}
		index := -1
		value := part
		if len(part) >= 3 && part[0].kind == kqlIdentifier && part[1].text == "=" {
			namedSeen = true
			var exists bool
			index, exists = byName[part[0].text]
			if !exists {
				return fmt.Errorf("unknown named parameter %s", part[0].text)
			}
			value = trimKQLTokens(part[2:])
		} else {
			if namedSeen {
				return fmt.Errorf("positional argument follows a named argument")
			}
			for positional < len(parameters) && assigned[positional] {
				positional++
			}
			if positional >= len(parameters) {
				return fmt.Errorf("too many arguments")
			}
			index = positional
			positional++
		}
		if assigned[index] {
			return fmt.Errorf("parameter %s is assigned more than once", parameters[index].name)
		}
		if _, ok := canonicalSimpleScalar(value, a.scalarParameters); !ok {
			return fmt.Errorf("parameter %s is not a closed scalar literal", parameters[index].name)
		}
		assigned[index] = true
	}
	for i, parameter := range parameters {
		if !assigned[i] && !parameter.hasDefault {
			return fmt.Errorf("missing required parameter %s", parameter.name)
		}
	}
	return nil
}

func canonicalSimpleScalar(tokens []kqlToken, bound map[string]bool) (string, bool) {
	tokens = stripKQLOuterParens(trimKQLTokens(tokens))
	if len(tokens) == 0 {
		return "", false
	}
	if len(tokens) == 1 {
		switch {
		case tokens[0].kind == kqlString:
			return quoteKQLString(tokens[0].text), true
		case tokens[0].kind == kqlOther && isKQLNumber(tokens[0].text):
			return tokens[0].text, true
		case tokens[0].kind == kqlIdentifier && (kqlWord(tokens[0], "true") || kqlWord(tokens[0], "false") || kqlWord(tokens[0], "null")):
			return strings.ToLower(tokens[0].text), true
		case tokens[0].kind == kqlIdentifier && bound[tokens[0].text]:
			return tokens[0].text, true
		}
	}
	if len(tokens) == 2 && tokens[0].kind == kqlOther && isKQLNumber(tokens[0].text) && isKQLTimespanUnit(tokens[1]) {
		return tokens[0].text + strings.ToLower(tokens[1].text), true
	}
	if len(tokens) == 2 && (tokens[0].text == "+" || tokens[0].text == "-") && tokens[1].kind == kqlOther && isKQLNumber(tokens[1].text) {
		return tokens[0].text + tokens[1].text, true
	}
	if len(tokens) >= 3 && tokens[0].kind == kqlIdentifier && tokens[1].text == "(" {
		close, ok := matchingKQLParen(tokens, 1)
		if !ok || close != len(tokens)-1 {
			return "", false
		}
		name := strings.ToLower(tokens[0].text)
		inside := trimKQLTokens(tokens[2:close])
		switch name {
		case "now":
			if len(inside) != 0 {
				return "", false
			}
			return "now()", true
		case "ago":
			value, ok := canonicalSimpleScalar(inside, bound)
			if !ok || !isCanonicalTimespan(value) {
				return "", false
			}
			return "ago(" + value + ")", true
		case "datetime", "todatetime", "timespan", "totimespan", "dynamic", "todynamic", "guid", "toguid":
			value, ok := canonicalConstructorArgument(name, inside)
			if !ok {
				return "", false
			}
			return name + "(" + value + ")", true
		}
	}
	return "", false
}

func canonicalConstructorArgument(name string, tokens []kqlToken) (string, bool) {
	if len(tokens) == 0 {
		return "", false
	}
	if len(tokens) == 1 && tokens[0].kind == kqlString {
		return quoteKQLString(tokens[0].text), true
	}
	if name == "timespan" || name == "totimespan" {
		if value, ok := canonicalSimpleScalar(tokens, nil); ok && isCanonicalTimespan(value) {
			return value, true
		}
	}
	if name == "dynamic" || name == "todynamic" {
		return canonicalDynamicLiteral(tokens)
	}
	switch name {
	case "datetime", "todatetime":
		return canonicalDateTimeLiteral(tokens)
	case "guid", "toguid":
		return canonicalGUIDLiteral(tokens)
	default:
		return "", false
	}
}

func canonicalDateTimeLiteral(tokens []kqlToken) (string, bool) {
	var out strings.Builder
	for _, token := range tokens {
		for _, r := range token.text {
			if !unicode.IsDigit(r) && !strings.ContainsRune("-+.:TtZz/", r) {
				return "", false
			}
		}
		out.WriteString(token.text)
	}
	value := out.String()
	return value, value != "" && unicode.IsDigit(rune(value[0]))
}

func canonicalGUIDLiteral(tokens []kqlToken) (string, bool) {
	var out strings.Builder
	for _, token := range tokens {
		for _, r := range token.text {
			if !unicode.IsDigit(r) && (unicode.ToLower(r) < 'a' || unicode.ToLower(r) > 'f') && r != '-' {
				return "", false
			}
		}
		out.WriteString(token.text)
	}
	value := out.String()
	parts := strings.Split(value, "-")
	if len(parts) != 5 || len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 || len(parts[3]) != 4 || len(parts[4]) != 12 {
		return "", false
	}
	return value, true
}

func canonicalDynamicLiteral(tokens []kqlToken) (string, bool) {
	var out strings.Builder
	stack := make([]string, 0, 2)
	for _, token := range tokens {
		if token.quoted {
			// The lexer represents a singleton JSON string array with the same
			// token used for a bracketed identifier. Constructor context makes
			// the intended literal unambiguous.
			out.WriteString("[" + quoteKQLJSONString(token.text) + "]")
			continue
		}
		switch {
		case token.kind == kqlString:
			out.WriteString(quoteKQLJSONString(token.text))
		case token.kind == kqlOther && isKQLNumber(token.text):
			out.WriteString(token.text)
		case token.kind == kqlIdentifier && (kqlWord(token, "true") || kqlWord(token, "false") || kqlWord(token, "null")):
			out.WriteString(strings.ToLower(token.text))
		case token.text == "{" || token.text == "[":
			stack = append(stack, token.text)
			out.WriteString(token.text)
		case token.text == "}" || token.text == "]":
			if len(stack) == 0 || (token.text == "}" && stack[len(stack)-1] != "{") || (token.text == "]" && stack[len(stack)-1] != "[") {
				return "", false
			}
			stack = stack[:len(stack)-1]
			out.WriteString(token.text)
		case token.text == ":" || token.text == "," || token.text == "-":
			out.WriteString(token.text)
		default:
			// Identifiers here are row/runtime values, not closed JSON. Never
			// preserve them in an automatically executed native probe.
			return "", false
		}
	}
	return out.String(), out.Len() != 0 && len(stack) == 0
}

func isKQLNumber(value string) bool {
	if value == "" {
		return false
	}
	dot := false
	for _, r := range value {
		if r == '.' && !dot {
			dot = true
			continue
		}
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isKQLTimespanUnit(token kqlToken) bool {
	if token.kind != kqlIdentifier {
		return false
	}
	switch strings.ToLower(token.text) {
	case "d", "day", "days", "h", "hour", "hours", "m", "min", "minute", "minutes", "s", "sec", "second", "seconds", "ms", "millisecond", "milliseconds", "microsecond", "microseconds", "tick", "ticks":
		return true
	default:
		return false
	}
}

func isCanonicalTimespan(value string) bool {
	for i, r := range value {
		if unicode.IsLetter(r) {
			return i > 0
		}
	}
	return false
}

func quoteKQLString(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func quoteKQLJSONString(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}

func (a *kqlAnalyzer) canonicalASIMCall(name string, arguments []kqlToken, called bool) (string, bool) {
	if !called {
		return name, true
	}
	parts := splitKQLTopLevel(arguments, ",")
	if len(parts) == 1 && len(trimKQLTokens(parts[0])) == 0 {
		return name + "()", true
	}
	canonical := make([]string, 0, len(parts))
	namedSeen := false
	seenNames := make(map[string]bool)
	for _, part := range parts {
		part = trimKQLTokens(part)
		if len(part) == 0 {
			return "", false
		}
		prefix := ""
		value := part
		if len(part) >= 3 && part[0].kind == kqlIdentifier && part[1].text == "=" {
			namedSeen = true
			if seenNames[part[0].text] {
				return "", false
			}
			seenNames[part[0].text] = true
			prefix = part[0].text + "="
			value = part[2:]
		} else if namedSeen {
			return "", false
		}
		encoded, ok := canonicalSimpleScalar(value, a.scalarParameters)
		if !ok {
			return "", false
		}
		canonical = append(canonical, prefix+encoded)
	}
	return name + "(" + strings.Join(canonical, ",") + ")", true
}

func consumeKQLCallChain(tokens []kqlToken, pos int) int {
	for pos+1 < len(tokens) && tokens[pos].text == "." && tokens[pos+1].kind == kqlIdentifier {
		pos += 2
		if pos < len(tokens) && tokens[pos].text == "(" {
			close, ok := matchingKQLParen(tokens, pos)
			if !ok {
				return len(tokens)
			}
			pos = close + 1
		}
	}
	return pos
}

func literalWatchlistAlias(arguments []kqlToken) (string, bool) {
	arguments = trimKQLTokens(arguments)
	if len(arguments) != 1 || arguments[0].kind != kqlString {
		return "", false
	}
	alias := strings.TrimSpace(arguments[0].text)
	return alias, alias != ""
}

func literalRemoteTableDependency(name string, tokens []kqlToken, close int) (Dependency, bool) {
	arguments := trimKQLTokens(tokens[2:close])
	if len(arguments) != 1 || arguments[0].kind != kqlString || strings.TrimSpace(arguments[0].text) == "" {
		return Dependency{}, false
	}
	if close+2 >= len(tokens) || tokens[close+1].text != "." || tokens[close+2].kind != kqlIdentifier {
		return Dependency{}, false
	}
	if close+3 != len(tokens) || strings.TrimSpace(tokens[close+2].text) == "" || strings.Contains(tokens[close+2].text, "*") {
		return Dependency{}, false
	}
	target := tokens[close+2].text
	return Dependency{
		Name: target, Kind: KindRemoteTable, ScopeKind: strings.ToLower(name),
		Scope: arguments[0].text, Target: target,
	}, true
}

func (a *kqlAnalyzer) parsePipelineSegment(tokens []kqlToken) {
	if len(tokens) == 0 || tokens[0].kind != kqlIdentifier {
		return
	}
	// search/find use "in (...)" for their source list and parse it below.
	// Other operators can contain scalar membership tests whose right-hand side
	// is itself a tabular expression. Those nested sources are part of the
	// rule's input set and must not disappear from the graph.
	if !kqlWord(tokens[0], "search") && !kqlWord(tokens[0], "find") {
		a.parseMembershipSubqueries(tokens)
	}
	switch {
	case kqlWord(tokens[0], "join"):
		a.parseJoinOrLookup(tokens, "join")
	case kqlWord(tokens[0], "lookup"):
		a.parseJoinOrLookup(tokens, "lookup")
	case kqlWord(tokens[0], "union"):
		a.parseUnion(tokens)
	case kqlWord(tokens[0], "search"), kqlWord(tokens[0], "find"):
		a.parseSearch(tokens)
	case kqlWord(tokens[0], "invoke"):
		if len(tokens) > 2 && tokens[1].kind == kqlIdentifier && tokens[2].text == "(" {
			a.addDependency(Dependency{Name: tokens[1].text, Kind: KindFunction})
		}
		a.markUnsupported("invoke operators require function metadata and are not assessed")
	case kqlWord(tokens[0], "evaluate"):
		a.markUnsupported("evaluate plugins are not assessed")
	case kqlWord(tokens[0], "fork"), kqlWord(tokens[0], "partition"), kqlWord(tokens[0], "macro-expand"):
		a.markUnsupported(fmt.Sprintf("%s subqueries are not assessed", strings.ToLower(tokens[0].text)))
	}
	// Fuzzy-union operands are scanned inside parseUnion so hidden scalar
	// inputs inherit the operand's optionality. Every other pipeline segment
	// is required and can be scanned as a whole, including join predicates.
	if !kqlWord(tokens[0], "union") {
		a.parseScalarBindingReferences(tokens)
	}
}

// parseScalarBindingReferences follows only let bindings that are actually
// referenced by the main query. A used toscalar(tabular-query) contributes
// its hidden tables; unused bindings and literal scalar bindings contribute
// nothing.
func (a *kqlAnalyzer) parseScalarBindingReferences(tokens []kqlToken) {
	for _, token := range tokens {
		if token.kind != kqlIdentifier {
			continue
		}
		if _, exists := a.bindings[token.text]; exists {
			a.parseScalarBinding(token.text)
		}
	}
	a.parseToscalarSubqueries(tokens, "query expression")
}

func (a *kqlAnalyzer) parseScalarBinding(name string) {
	binding, exists := a.bindings[name]
	if !exists {
		return
	}
	if a.scalarResolving[name] {
		a.markAmbiguous(fmt.Sprintf("KQL scalar let bindings contain a cycle at %s", name))
		return
	}
	a.scalarResolving[name] = true
	defer delete(a.scalarResolving, name)

	// Follow scalar aliases first so a used binding can refer to another let
	// that owns the actual toscalar subquery.
	for _, token := range binding {
		if token.kind == kqlIdentifier && token.text != name {
			if _, nested := a.bindings[token.text]; nested {
				a.parseScalarBinding(token.text)
			}
		}
	}

	a.parseToscalarSubqueries(binding, "scalar let binding "+name)
}

func (a *kqlAnalyzer) parseToscalarSubqueries(tokens []kqlToken, location string) {
	for pos := 0; pos+1 < len(tokens); pos++ {
		if !kqlWord(tokens[pos], "toscalar") || tokens[pos+1].text != "(" {
			continue
		}
		close, ok := matchingKQLParen(tokens, pos+1)
		if !ok {
			a.markAmbiguous(fmt.Sprintf("KQL %s has an unmatched toscalar expression", location))
			return
		}
		expression := stripKQLOuterParens(trimKQLTokens(tokens[pos+2 : close]))
		if len(expression) == 1 && expression[0].kind == kqlIdentifier {
			if binding, bound := a.bindings[expression[0].text]; bound && bindingHasTabularInput(expression[0].text, a.bindings, a.functions, nil) {
				a.parseQuery(binding)
				pos = close
				continue
			}
		}
		if scalarExpressionHasTabularInput(expression, a.bindings, a.functions) {
			a.parseQuery(expression)
		}
		pos = close
	}
}

func bindingHasTabularInput(name string, bindings map[string][]kqlToken, functions map[string]WorkspaceFunction, seen map[string]bool) bool {
	if seen == nil {
		seen = make(map[string]bool)
	}
	if seen[name] {
		return false
	}
	seen[name] = true
	binding, exists := bindings[name]
	if !exists {
		return false
	}
	binding = stripKQLOuterParens(trimKQLTokens(binding))
	if len(binding) == 1 && binding[0].kind == kqlIdentifier {
		if _, nested := bindings[binding[0].text]; nested {
			return bindingHasTabularInput(binding[0].text, bindings, functions, seen)
		}
	}
	return scalarExpressionHasTabularInput(binding, bindings, functions)
}

func scalarExpressionHasTabularInput(tokens []kqlToken, bindings map[string][]kqlToken, functions map[string]WorkspaceFunction) bool {
	tokens = stripKQLOuterParens(trimKQLTokens(tokens))
	if len(tokens) == 0 || tokens[0].kind != kqlIdentifier {
		return false
	}
	if kqlWord(tokens[0], "print") || kqlWord(tokens[0], "range") || kqlWord(tokens[0], "datatable") {
		return false
	}
	if findKQLTopLevel(tokens, 0, "|") >= 0 || kqlWord(tokens[0], "union") || kqlWord(tokens[0], "search") || kqlWord(tokens[0], "find") {
		return true
	}
	if len(tokens) == 1 {
		_, bound := bindings[tokens[0].text]
		return !bound
	}
	if tokens[1].text == "(" {
		_, workspaceFunction := functions[tokens[0].text]
		return workspaceFunction || isKQLRemoteFunction(tokens[0].text) || isKQLWatchlistFunction(tokens[0].text) ||
			isKQLDynamicSourceFunction(tokens[0].text) || isKQLASIMParserName(tokens[0].text)
	}
	return false
}

// parseMembershipSubqueries finds tabular expressions nested on the right side
// of the in and in~ operators. Comma-separated and literal expressions are
// scalar membership lists. A single unbound name is ambiguous because KQL can
// resolve it as either a scalar name or a tabular expression; treating it as a
// table would manufacture evidence, while ignoring it could hide a dependency.
func (a *kqlAnalyzer) parseMembershipSubqueries(tokens []kqlToken) {
	for pos := 0; pos < len(tokens); pos++ {
		if !kqlWord(tokens[pos], "in") {
			continue
		}
		open := pos + 1
		if open < len(tokens) && tokens[open].text == "~" {
			open++
		}
		if open >= len(tokens) || tokens[open].text != "(" {
			continue
		}
		close, ok := matchingKQLParen(tokens, open)
		if !ok {
			a.markAmbiguous("KQL membership expression has unmatched parentheses")
			return
		}
		right := stripKQLOuterParens(trimKQLTokens(tokens[open+1 : close]))
		switch {
		case len(right) == 0:
			a.markAmbiguous("KQL membership expression is empty")
		case findKQLTopLevel(right, 0, "|") >= 0:
			a.parseQuery(right)
		case isSingleKQLCall(right):
			name := right[0].text
			if _, exists := a.functions[name]; exists || isKQLRemoteFunction(name) || isKQLWatchlistFunction(name) || isKQLDynamicSourceFunction(name) || isKQLASIMParserName(name) {
				a.parseSourceSegment(right)
			} else {
				a.markAmbiguous(fmt.Sprintf("KQL membership function %s() may be scalar or tabular", name))
			}
		case len(right) == 1 && right[0].kind == kqlIdentifier:
			if binding, exists := a.bindings[right[0].text]; exists {
				if a.resolving[right[0].text] {
					a.markAmbiguous(fmt.Sprintf("KQL let aliases contain a cycle at %s", right[0].text))
				} else {
					a.resolving[right[0].text] = true
					a.parseQuery(binding)
					delete(a.resolving, right[0].text)
				}
			} else {
				a.markAmbiguous(fmt.Sprintf("KQL membership expression %s may be scalar or tabular", right[0].text))
			}
		}
		pos = close
	}
}

func isSingleKQLCall(tokens []kqlToken) bool {
	if len(tokens) < 3 || tokens[0].kind != kqlIdentifier || tokens[1].text != "(" {
		return false
	}
	close, ok := matchingKQLParen(tokens, 1)
	return ok && close == len(tokens)-1
}

func (a *kqlAnalyzer) parseJoinOrLookup(tokens []kqlToken, operator string) {
	pos := skipKQLOptions(tokens, 1)
	on := findKQLTopLevelWord(tokens, pos, "on")
	if on < 0 {
		a.markAmbiguous(fmt.Sprintf("KQL %s has no on clause", operator))
		return
	}
	source := trimKQLTokens(tokens[pos:on])
	if len(source) == 0 {
		a.markAmbiguous(fmt.Sprintf("KQL %s has no right-hand source", operator))
		return
	}
	if source[0].text == "(" {
		if close, ok := matchingKQLParen(source, 0); ok && close == len(source)-1 {
			a.parseQuery(source[1:close])
			return
		}
	}
	a.parseSourceSegment(source)
}

func (a *kqlAnalyzer) parseUnion(tokens []kqlToken) {
	fuzzy, fuzzyPresent, fuzzyValid := kqlBoolOption(tokens, 1, "isfuzzy")
	if fuzzyPresent && !fuzzyValid {
		a.markAmbiguous("KQL union isfuzzy option is not a literal boolean")
	}
	pos := skipKQLOptions(tokens, 1)
	operands := splitKQLTopLevel(tokens[pos:], ",")
	if len(operands) == 0 {
		a.markAmbiguous("KQL union has no operands")
		return
	}
	for _, operand := range operands {
		operand = trimKQLTokens(operand)
		if len(operand) == 0 {
			a.markAmbiguous("KQL union contains an empty operand")
			continue
		}
		if hasKQLWildcard(operand) {
			a.markUnsupported("wildcard union sources are not assessed")
			continue
		}
		if fuzzy {
			a.optionalDepth++
		}
		if operand[0].text == "(" {
			if close, ok := matchingKQLParen(operand, 0); ok && close == len(operand)-1 {
				a.parseQuery(operand[1:close])
				if fuzzy {
					a.optionalDepth--
				}
				continue
			}
		}
		a.parseSourceSegment(operand)
		if fuzzy {
			a.optionalDepth--
		}
	}
}

func (a *kqlAnalyzer) parseSearch(tokens []kqlToken) {
	operator := strings.ToLower(tokens[0].text)
	pos := skipKQLOptions(tokens, 1)
	in := findKQLTopLevelWord(tokens, pos, "in")
	if in < 0 {
		a.markUnsupported(fmt.Sprintf("%s without an explicit table list is not assessed", operator))
		return
	}
	if in+1 >= len(tokens) || tokens[in+1].text != "(" {
		a.markAmbiguous(fmt.Sprintf("KQL %s in clause has no parenthesized table list", operator))
		return
	}
	close, ok := matchingKQLParen(tokens, in+1)
	if !ok {
		a.markAmbiguous(fmt.Sprintf("KQL %s table list has unmatched parentheses", operator))
		return
	}
	for _, source := range splitKQLTopLevel(tokens[in+2:close], ",") {
		source = trimKQLTokens(source)
		if len(source) == 0 {
			a.markAmbiguous(fmt.Sprintf("KQL %s contains an empty table source", operator))
			continue
		}
		if hasKQLWildcard(source) {
			a.markUnsupported(fmt.Sprintf("wildcard %s sources are not assessed", operator))
			continue
		}
		a.parseSourceSegment(source)
	}
}

func skipKQLOptions(tokens []kqlToken, pos int) int {
	for pos < len(tokens) {
		start := pos
		if tokens[pos].kind != kqlIdentifier {
			return pos
		}
		pos++
		for pos+1 < len(tokens) && tokens[pos].text == "." && tokens[pos+1].kind == kqlIdentifier {
			pos += 2
		}
		if pos >= len(tokens) || tokens[pos].text != "=" {
			return start
		}
		pos++
		if pos >= len(tokens) {
			return pos
		}
		if tokens[pos].text == "(" {
			if close, ok := matchingKQLParen(tokens, pos); ok {
				pos = close + 1
				continue
			}
		}
		pos++
	}
	return pos
}

func kqlBoolOption(tokens []kqlToken, pos int, want string) (value, present, valid bool) {
	for pos < len(tokens) {
		if tokens[pos].kind != kqlIdentifier {
			return false, false, false
		}
		name := tokens[pos].text
		pos++
		for pos+1 < len(tokens) && tokens[pos].text == "." && tokens[pos+1].kind == kqlIdentifier {
			name += "." + tokens[pos+1].text
			pos += 2
		}
		if pos >= len(tokens) || tokens[pos].text != "=" {
			return false, false, false
		}
		pos++
		if pos >= len(tokens) {
			if strings.EqualFold(name, want) {
				return false, true, false
			}
			return false, false, false
		}
		if strings.EqualFold(name, want) {
			if kqlWord(tokens[pos], "true") {
				return true, true, true
			}
			if kqlWord(tokens[pos], "false") {
				return false, true, true
			}
			return false, true, false
		}
		if tokens[pos].text == "(" {
			close, ok := matchingKQLParen(tokens, pos)
			if !ok {
				return false, false, false
			}
			pos = close + 1
		} else {
			pos++
		}
	}
	return false, false, false
}

func (a *kqlAnalyzer) scanUnsupportedCalls(tokens []kqlToken) {
	for i := 0; i+1 < len(tokens); i++ {
		if tokens[i].kind != kqlIdentifier || tokens[i+1].text != "(" {
			continue
		}
		name := tokens[i].text
		switch {
		case isKQLLiteralScopeFunction(name):
			close, ok := matchingKQLParen(tokens, i+1)
			if !ok {
				a.markAmbiguous(fmt.Sprintf("remote source %s has unmatched parentheses", name))
				continue
			}
			end := consumeKQLCallChain(tokens, close+1)
			segment := tokens[i:end]
			if dependency, literal := literalRemoteTableDependency(name, segment, close-i); literal {
				a.addScannedDependency(dependency)
			} else {
				a.addScannedDependency(Dependency{Name: name, Kind: KindRemote})
				a.addNote(fmt.Sprintf("remote source %s() does not use a literal scope and direct table member", name))
			}
			a.remote = true
		case isKQLUnsupportedRemoteFunction(name):
			a.addScannedDependency(Dependency{Name: name, Kind: KindRemote})
			a.remote = true
			a.addNote(fmt.Sprintf("remote source %s() is not assessed", name))
		case strings.EqualFold(name, "_GetWatchlist"):
			close, ok := matchingKQLParen(tokens, i+1)
			if !ok {
				a.markAmbiguous("_GetWatchlist has unmatched parentheses")
				continue
			}
			if alias, literal := literalWatchlistAlias(tokens[i+2 : close]); literal {
				a.addScannedDependency(Dependency{Name: alias, Kind: KindWatchlist})
			} else {
				a.markUnsupported("_GetWatchlist requires exactly one non-empty string literal alias")
			}
		case isKQLWatchlistFunction(name):
			a.markUnsupported(fmt.Sprintf("Sentinel watchlist function %s is not assessed", name))
		case isKQLDynamicSourceFunction(name) && !strings.EqualFold(name, "toscalar"):
			a.markUnsupported(fmt.Sprintf("dynamic source function %s() is not assessed", name))
		}
	}
}

func (a *kqlAnalyzer) addDependency(dependency Dependency) {
	if a.optionalDepth > 0 {
		dependency.Optional = true
	}
	key := strings.Join([]string{string(dependency.Kind), dependency.Name, dependency.ScopeKind, dependency.Scope, dependency.Target, dependency.Call}, "\x00")
	if index, exists := a.seenDeps[key]; exists {
		// Required evidence wins when the same source also appears in a fuzzy
		// union. Keep its first position while upgrading its requiredness.
		if !dependency.Optional && a.deps[index].Optional {
			a.deps[index].Optional = false
		}
		return
	}
	a.seenDeps[key] = len(a.deps)
	a.deps = append(a.deps, dependency)
}

// addScannedDependency records a dependency found by the whole-expression
// safety scan without changing optionality already established by the
// structural parser. Required duplicate sources still upgrade fuzzy evidence
// through addDependency when parseUnion encounters them explicitly.
func (a *kqlAnalyzer) addScannedDependency(dependency Dependency) {
	if a.optionalDepth > 0 {
		dependency.Optional = true
	}
	key := strings.Join([]string{string(dependency.Kind), dependency.Name, dependency.ScopeKind, dependency.Scope, dependency.Target, dependency.Call}, "\x00")
	if _, exists := a.seenDeps[key]; exists {
		return
	}
	a.seenDeps[key] = len(a.deps)
	a.deps = append(a.deps, dependency)
}

func (a *kqlAnalyzer) addNote(note string) {
	if _, exists := a.seenNotes[note]; exists {
		return
	}
	a.seenNotes[note] = struct{}{}
	a.notes = append(a.notes, note)
}

func (a *kqlAnalyzer) addBlockingNote(note string) {
	if _, exists := a.seenBlockingNotes[note]; exists {
		return
	}
	a.seenBlockingNotes[note] = struct{}{}
	a.blockingNotes = append(a.blockingNotes, note)
}

func (a *kqlAnalyzer) markUnsupported(reason string) {
	a.unsupported = true
	a.addNote(reason)
	a.addBlockingNote(reason)
}

func (a *kqlAnalyzer) markDeferredUnsupported(reason string) {
	a.deferredUnsupported = true
	a.addNote(reason)
}

func (a *kqlAnalyzer) markAmbiguous(reason string) {
	a.ambiguous = true
	a.addNote(reason)
	a.addBlockingNote(reason)
}

func (a *kqlAnalyzer) result() KQLResolution {
	result := KQLResolution{
		Dependencies:   append([]Dependency(nil), a.deps...),
		Reason:         strings.Join(a.notes, "; "),
		BlockingReason: strings.Join(a.blockingNotes, "; "),
	}
	if a.ambiguous {
		result.BlockingStatus = backend.ResolutionAmbiguous
	} else if a.unsupported {
		result.BlockingStatus = backend.ResolutionUnsupported
	}
	switch {
	case a.remote:
		result.Status = backend.ResolutionRemote
	case a.ambiguous:
		result.Status = backend.ResolutionAmbiguous
	case a.unsupported:
		result.Status = backend.ResolutionUnsupported
	case a.deferredUnsupported:
		result.Status = backend.ResolutionUnsupported
	case hasKQLDependencyKind(a.deps, KindTable), hasKQLDependencyKind(a.deps, KindWatchlist):
		result.Status = backend.ResolutionResolved
		if result.Reason == "" {
			tables := countKQLDependencyKind(a.deps, KindTable)
			watchlists := countKQLDependencyKind(a.deps, KindWatchlist)
			result.Reason = fmt.Sprintf("resolved %s and %s", counted(tables, "direct local table source", "direct local table sources"), counted(watchlists, "literal watchlist", "literal watchlists"))
		}
	default:
		result.Status = backend.ResolutionEmpty
		if result.Reason == "" {
			result.Reason = "KQL query has no table sources"
		}
	}
	return result
}

func counted(n int, singular, plural string) string {
	label := plural
	if n == 1 {
		label = singular
	}
	return fmt.Sprintf("%d %s", n, label)
}

func hasKQLDependencyKind(dependencies []Dependency, kind DependencyKind) bool {
	return countKQLDependencyKind(dependencies, kind) != 0
}

func countKQLDependencyKind(dependencies []Dependency, kind DependencyKind) int {
	count := 0
	for _, dependency := range dependencies {
		if dependency.Kind == kind {
			count++
		}
	}
	return count
}

func kqlTablePatterns(dependencies []Dependency) (required, optional []string) {
	for _, dependency := range dependencies {
		if dependency.Kind != KindTable {
			continue
		}
		if dependency.Optional {
			optional = append(optional, dependency.Name)
		} else {
			required = append(required, dependency.Name)
		}
	}
	return required, optional
}

func isKQLRemoteFunction(name string) bool {
	return isKQLLiteralScopeFunction(name) || isKQLUnsupportedRemoteFunction(name)
}

func isKQLLiteralScopeFunction(name string) bool {
	switch strings.ToLower(name) {
	case "workspace", "app", "resource":
		return true
	default:
		return false
	}
}

func isKQLUnsupportedRemoteFunction(name string) bool {
	switch strings.ToLower(name) {
	case "cluster", "adx", "arg":
		return true
	default:
		return false
	}
}

func isKQLWatchlistFunction(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "_getwatchlist")
}

func isKQLDynamicSourceFunction(name string) bool {
	switch strings.ToLower(name) {
	case "table", "externaldata", "datatable", "materialize", "toscalar":
		return true
	default:
		return false
	}
}

// isKQLASIMParserName recognizes the documented Microsoft Sentinel ASIM
// parser families that can be built in and therefore absent from the Logs
// workspace-function metadata response. It deliberately matches only known
// schema names and documented prefixes. Native ASIM ingestion tables remain
// tables, as do arbitrary identifiers that merely begin with "Im".
func isKQLASIMParserName(name string) bool {
	if strings.HasSuffix(name, "_CL") || isKQLASIMNativeTableName(name) {
		return false
	}
	switch {
	case strings.HasPrefix(name, "_Im_"):
		_, suffix, ok := splitKQLASIMSchema(strings.TrimPrefix(name, "_Im_"))
		return ok && (suffix == "" || strings.HasPrefix(suffix, "_"))
	case strings.HasPrefix(name, "_ASim_"):
		_, suffix, ok := splitKQLASIMSchema(strings.TrimPrefix(name, "_ASim_"))
		return ok && (suffix == "" || strings.HasPrefix(suffix, "_"))
	case strings.HasPrefix(name, "Im_"):
		_, suffix, ok := splitKQLASIMSchema(strings.TrimPrefix(name, "Im_"))
		return ok && (suffix == "" || suffix == "Custom")
	case strings.HasPrefix(name, "im"):
		_, suffix, ok := splitKQLASIMSchema(strings.TrimPrefix(name, "im"))
		return ok && suffix == ""
	case strings.HasPrefix(name, "vim"):
		_, _, ok := splitKQLASIMSchema(strings.TrimPrefix(name, "vim"))
		return ok
	case strings.HasPrefix(name, "ASim"):
		_, suffix, ok := splitKQLASIMSchema(strings.TrimPrefix(name, "ASim"))
		return ok && suffix != ""
	default:
		return false
	}
}

func isKQLASIMNativeTableName(name string) bool {
	switch name {
	case "ASimAuditEventLogs",
		"ASimAuthenticationEventLogs",
		"ASimDhcpEventLogs",
		"ASimDnsActivityLogs",
		"ASimFileEventLogs",
		"ASimNetworkSessionLogs",
		"ASimProcessEventLogs",
		"ASimRegistryEventLogs",
		"ASimUserManagementActivityLogs",
		"ASimWebSessionLogs":
		return true
	default:
		return false
	}
}

func splitKQLASIMSchema(name string) (schema string, suffix string, ok bool) {
	// Longer names come first so ProcessCreate is not truncated by a future
	// shorter schema alias.
	for _, candidate := range []string{
		"NetworkSession",
		"ProcessTerminate",
		"UserManagement",
		"Authentication",
		"ProcessCreate",
		"RegistryEvent",
		"AgentEvent",
		"AlertEvent",
		"AssetEntity",
		"AuditEvent",
		"ProcessEvent",
		"WebSession",
		"DhcpEvent",
		"FileEvent",
		"Dns",
	} {
		if strings.HasPrefix(name, candidate) {
			return candidate, strings.TrimPrefix(name, candidate), true
		}
	}
	return "", "", false
}

func isKQLNonSourceKeyword(name string) bool {
	switch strings.ToLower(name) {
	case "as", "consume", "count", "distinct", "evaluate", "extend", "facet", "fork",
		"getschema", "invoke", "join", "limit", "lookup", "make-series", "mv-apply",
		"mv-expand", "order", "parse", "parse-where", "partition", "project",
		"project-away", "project-keep", "project-rename", "project-reorder", "range",
		"render", "sample", "search", "serialize", "sort", "summarize", "take", "top",
		"top-nested", "union", "where":
		return true
	default:
		return false
	}
}

func kqlWord(token kqlToken, word string) bool {
	return token.kind == kqlIdentifier && !token.quoted && strings.EqualFold(token.text, word)
}

func trimKQLTokens(tokens []kqlToken) []kqlToken {
	return tokens
}

func stripKQLOuterParens(tokens []kqlToken) []kqlToken {
	for len(tokens) >= 2 && tokens[0].text == "(" {
		close, ok := matchingKQLParen(tokens, 0)
		if !ok || close != len(tokens)-1 {
			break
		}
		tokens = tokens[1:close]
	}
	return tokens
}

func matchingKQLParen(tokens []kqlToken, open int) (int, bool) {
	if open >= len(tokens) || tokens[open].text != "(" {
		return 0, false
	}
	depth := 0
	for i := open; i < len(tokens); i++ {
		switch tokens[i].text {
		case "(":
			depth++
		case ")":
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

func findKQLTopLevel(tokens []kqlToken, start int, text string) int {
	depth := 0
	for i := start; i < len(tokens); i++ {
		switch tokens[i].text {
		case "(":
			depth++
		case ")":
			depth--
		default:
			if depth == 0 && tokens[i].text == text {
				return i
			}
		}
	}
	return -1
}

func findKQLTopLevelWord(tokens []kqlToken, start int, word string) int {
	depth := 0
	for i := start; i < len(tokens); i++ {
		switch tokens[i].text {
		case "(":
			depth++
		case ")":
			depth--
		default:
			if depth == 0 && kqlWord(tokens[i], word) {
				return i
			}
		}
	}
	return -1
}

func splitKQLTopLevel(tokens []kqlToken, separator string) [][]kqlToken {
	parts := make([][]kqlToken, 0, 2)
	start := 0
	depth := 0
	for i, token := range tokens {
		switch token.text {
		case "(":
			depth++
		case ")":
			depth--
		default:
			if depth == 0 && token.text == separator {
				parts = append(parts, tokens[start:i])
				start = i + 1
			}
		}
	}
	return append(parts, tokens[start:])
}

func hasKQLWildcard(tokens []kqlToken) bool {
	for _, token := range tokens {
		if token.text == "*" || (token.kind == kqlIdentifier && strings.Contains(token.text, "*")) {
			return true
		}
	}
	return false
}
