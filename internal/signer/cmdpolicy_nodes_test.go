package signer

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// shellNodeVerdicts is the complete enumeration of the node types
// mvdan.cc/sh/v3/syntax defines (every type with a Pos method in
// syntax/nodes.go), each with the verdict the command-policy walker must give
// it. It is the reviewable form of the #820 node allowlist:
// TestShellNodeAllowlistIsExhaustive checks it against the parser's source, so
// a dependency bump that adds a node type fails here until someone decides its
// verdict (the walker's default already rejects it meanwhile).
//
// wantErr == "" means accepted; otherwise the rejection must contain it.
var shellNodeVerdicts = []struct {
	node    syntax.Node
	wantErr string
}{
	// Accepted: containers whose children are statements only.
	{&syntax.File{}, ""},
	{&syntax.Comment{}, ""},
	{&syntax.Stmt{}, ""},
	{&syntax.Subshell{}, ""},
	{&syntax.Block{}, ""},
	{&syntax.IfClause{}, ""},
	{&syntax.WhileClause{}, ""},
	{&syntax.BinaryCmd{Op: syntax.AndStmt}, ""},
	// Accepted, vetting their own words (the walker does not descend).
	{&syntax.CallExpr{}, ""},
	{&syntax.Redirect{Op: syntax.DplOut, Word: litWord("1")}, ""},

	// Rejected: every word-level node. A simple command's words are vetted by
	// literalArgs and a redirect's by vetRedirect, without descending — so a
	// word the walker REACHES is in a position nothing vetted.
	{&syntax.Word{}, "word outside a simple command"},
	{&syntax.Lit{}, "word outside a simple command"},
	{&syntax.SglQuoted{}, "word outside a simple command"},
	{&syntax.DblQuoted{}, "word outside a simple command"},
	{&syntax.ParamExp{}, "parameter expansion"},
	{&syntax.CmdSubst{}, "command substitution not allowed"},
	{&syntax.ArithmExp{}, "arithmetic expansion"},
	{&syntax.ProcSubst{}, "process substitution not allowed"},
	{&syntax.ExtGlob{}, "extended glob"},
	{&syntax.BraceExp{}, "brace expansion"},
	// Rejected: compound commands that carry words or expressions.
	{&syntax.ForClause{}, "for loop"},
	{&syntax.ForClause{Select: true}, "select loop"},
	{&syntax.WordIter{}, "for loop"},
	{&syntax.CStyleLoop{}, "for loop"},
	{&syntax.CaseClause{}, "case"},
	{&syntax.CaseItem{}, "case"},
	{&syntax.TestClause{}, "[[ ]] test"},
	{&syntax.BinaryTest{}, "[[ ]] test"},
	{&syntax.UnaryTest{}, "[[ ]] test"},
	{&syntax.ParenTest{}, "[[ ]] test"},
	{&syntax.LetClause{}, "let"},
	{&syntax.ArithmCmd{}, "arithmetic command not allowed"},
	{&syntax.BinaryArithm{}, "arithmetic expression"},
	{&syntax.UnaryArithm{}, "arithmetic expression"},
	{&syntax.ParenArithm{}, "arithmetic expression"},
	{&syntax.FlagsArithm{}, "arithmetic expression"},
	// Rejected: declarations, assignments and wrappers.
	{&syntax.DeclClause{}, "environment declaration"},
	{&syntax.Assign{}, "assignment"},
	{&syntax.ArrayExpr{}, "assignment"},
	{&syntax.ArrayElem{}, "assignment"},
	{&syntax.FuncDecl{}, "function declaration"},
	{&syntax.TimeClause{}, "time"},
	{&syntax.CoprocClause{}, "coproc"},
	{&syntax.TestDecl{}, "TestDecl"},
}

func litWord(s string) *syntax.Word {
	return &syntax.Word{Parts: []syntax.WordPart{&syntax.Lit{Value: s}}}
}

// TestShellNodeAllowlist feeds the walker one value of every node type and
// checks its verdict, independently of what the parser happens to nest where
// (a parsed `case $((1)) in …` stops at CaseClause and would never prove that
// ArithmExp on its own is rejected).
func TestShellNodeAllowlist(t *testing.T) {
	t.Parallel()
	for _, tc := range shellNodeVerdicts {
		var v commandVetter
		_, err := v.vet(tc.node)
		name := reflect.TypeOf(tc.node).Elem().Name()
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s must be accepted, got: %v", name, err)
		case tc.wantErr != "" && err == nil:
			t.Errorf("%s must be rejected (want %q), was accepted", name, tc.wantErr)
		case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
			t.Errorf("%s: error = %q, want it to contain %q", name, err, tc.wantErr)
		}
	}
}

// futureNode stands for a node type a later parser version might add.
type futureNode struct{ syntax.Lit }

// TestShellNodeAllowlistFailsClosed is the property the #820 fix rests on: a
// node type the walker has no case for is REJECTED, not skipped. It also pins
// the per-field rules of the accepted nodes.
func TestShellNodeAllowlistFailsClosed(t *testing.T) {
	t.Parallel()

	rejected := []struct {
		name    string
		node    syntax.Node
		wantErr string
	}{
		{"unknown node type", &futureNode{}, "shell construct not allowed by command policy: *signer.futureNode"},
		{"|& pipe", &syntax.BinaryCmd{Op: syntax.PipeAll}, "shell construct not allowed by command policy: |&"},
		{"unknown binary operator", &syntax.BinaryCmd{Op: syntax.BinCmdOperator(0)}, "shell construct not allowed by command policy"},
		{"coprocess statement", &syntax.Stmt{Coprocess: true}, "coprocess / disown"},
		{"disowned statement", &syntax.Stmt{Disown: true}, "coprocess / disown"},
		{"file redirect", &syntax.Redirect{Op: syntax.RdrOut, Word: litWord("/tmp/x")}, "file redirect not allowed"},
		{"fd dup to a file name", &syntax.Redirect{Op: syntax.DplOut, Word: litWord("/tmp/x")}, "file redirect not allowed"},
		{"fd dup with a here-doc body", &syntax.Redirect{Op: syntax.DplOut, Word: litWord("1"), Hdoc: litWord("x")}, "file redirect not allowed"},
		{"named source descriptor", &syntax.Redirect{Op: syntax.DplOut, N: &syntax.Lit{Value: "{PATH}"}, Word: litWord("2")}, "named file descriptor"},
		{"standalone assignment", &syntax.CallExpr{Assigns: []*syntax.Assign{{Name: &syntax.Lit{Value: "A"}}}}, "standalone environment assignment"},
	}
	for _, tc := range rejected {
		var v commandVetter
		if _, err := v.vet(tc.node); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: err = %v, want it to contain %q", tc.name, err, tc.wantErr)
		}
	}

	accepted := []struct {
		name string
		node syntax.Node
	}{
		{"negated background statement", &syntax.Stmt{Negated: true, Background: true}},
		{"&&", &syntax.BinaryCmd{Op: syntax.AndStmt}},
		{"||", &syntax.BinaryCmd{Op: syntax.OrStmt}},
		{"|", &syntax.BinaryCmd{Op: syntax.Pipe}},
		{"2>&1", &syntax.Redirect{Op: syntax.DplOut, N: &syntax.Lit{Value: "2"}, Word: litWord("1")}},
		{"<&-", &syntax.Redirect{Op: syntax.DplIn, Word: litWord("-")}},
	}
	for _, tc := range accepted {
		var v commandVetter
		if _, err := v.vet(tc.node); err != nil {
			t.Errorf("%s must be accepted, got: %v", tc.name, err)
		}
	}

	// The walker must not descend into the two word-bearing nodes it accepts:
	// that is what makes "a word the walker reaches" mean "an unvetted word".
	for _, n := range []syntax.Node{
		&syntax.CallExpr{Args: []*syntax.Word{litWord("true")}},
		&syntax.Redirect{Op: syntax.DplOut, Word: litWord("1")},
	} {
		var v commandVetter
		if descend, err := v.vet(n); err != nil || descend {
			t.Errorf("%T: descend=%v err=%v, want descend=false and no error", n, descend, err)
		}
	}
}

// TestShellNodeAllowlistIsExhaustive compares shellNodeVerdicts with the node
// types the pinned mvdan.cc/sh actually defines, read from its source in the
// module cache. It skips when the go tool or the module source is unavailable.
func TestShellNodeAllowlistIsExhaustive(t *testing.T) {
	t.Parallel()

	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "mvdan.cc/sh/v3").Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	dir := filepath.Join(strings.TrimSpace(string(out)), "syntax")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("module source unavailable: %v", err)
	}

	// A node type is any type with a `Pos() Pos` method (the syntax.Node
	// interface); they are all declared in the package's non-test files.
	defined := map[string]bool{}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", e.Name(), err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Name.Name != "Pos" || len(fn.Recv.List) != 1 {
				continue
			}
			recv := fn.Recv.List[0].Type
			if star, ok := recv.(*ast.StarExpr); ok {
				recv = star.X
			}
			if id, ok := recv.(*ast.Ident); ok {
				defined[id.Name] = true
			}
		}
	}
	if len(defined) < 40 {
		t.Fatalf("found only %d node types in %s; the scan is broken", len(defined), dir)
	}

	covered := map[string]bool{}
	for _, tc := range shellNodeVerdicts {
		covered[reflect.TypeOf(tc.node).Elem().Name()] = true
	}
	var missing, stale []string
	for name := range defined {
		if !covered[name] {
			missing = append(missing, name)
		}
	}
	for name := range covered {
		if !defined[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("node types with no verdict in shellNodeVerdicts (decide accept/reject explicitly): %v", missing)
	}
	if len(stale) > 0 {
		t.Errorf("shellNodeVerdicts names types the parser no longer defines: %v", stale)
	}
}
