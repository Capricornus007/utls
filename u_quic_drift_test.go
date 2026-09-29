package tls

// u_quic.go is a hand-maintained mirror of quic.go: same state machine, same
// signal channels, but for UQUICConn/UConn instead of QUICConn/Conn. Every
// time upstream or the Go standard library changes a channel operation in
// quic.go and the mirror is not updated, the result is a hang, not a compile
// error — that is exactly how UQUICConn.Close() deadlocked after the go1.26
// QUIC rework (quicWaitForSignal dropped its cancelc select arms and Close()
// gained `<-signalc`; the mirror had neither).
//
// This test compares the two files mechanically: for each paired exported
// method it collects every operation on the handshake signal channels
// (send / receive / close / range) and requires the multisets to match.
// Divergences that are deliberate are listed in justifiedDifferences below
// with the reason, so a NEW divergence is a red build rather than a silent
// hang.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"
)

// signalChannels are the fields whose operations must stay mirrored.
var signalChannels = map[string]bool{
	"signalc":  true,
	"blockedc": true,
	"cancelc":  true,
}

// methodKey is "RecvType.MethodName" with the leading pointer stripped.
func methodKey(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return "*" + fn.Name.Name
	}
	t := fn.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + fn.Name.Name
	}
	return "?" + fn.Name.Name
}

// channelOps collects the signal-channel operations inside one function.
func channelOps(src nodeSrc) []string {
	var ops []string
	add := func(name, kind string) {
		if signalChannels[name] {
			ops = append(ops, kind+":"+name)
		}
	}
	ast.Inspect(src.node, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		switch e := n.(type) {
		case *ast.SendStmt: // ch <- v
			if name, ok := chanFieldName(e.Chan); ok {
				add(name, "send")
			}
		case *ast.UnaryExpr: // <-ch
			if e.Op == token.ARROW {
				if name, ok := chanFieldName(e.X); ok {
					add(name, "recv")
				}
			}
		case *ast.CallExpr: // close(ch)
			if id, ok := e.Fun.(*ast.Ident); ok && id.Name == "close" && len(e.Args) == 1 {
				if name, ok := chanFieldName(e.Args[0]); ok {
					add(name, "close")
				}
			}
		case *ast.RangeStmt: // for range ch
			if name, ok := chanFieldName(e.X); ok {
				add(name, "range")
			}
		}
		return true
	})
	return ops
}

type nodeSrc struct{ node ast.Node }

// chanFieldName returns the last selector component of an expression, which is
// the channel field name regardless of how deep the receiver path is
// (q.conn.quic.signalc vs q.signalc).
func chanFieldName(expr ast.Expr) (string, bool) {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name, signalChannels[e.Name]
	case *ast.SelectorExpr:
		return e.Sel.Name, signalChannels[e.Sel.Name]
	case *ast.ParenExpr:
		return chanFieldName(e.X)
	}
	return "", false
}

func parseMethods(t *testing.T, path string) map[string][]string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	out := map[string][]string{}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		out[methodKey(fn)] = channelOps(nodeSrc{fn.Body})
	}
	return out
}

// justifiedDifferences records mirror gaps that are deliberate, so the gate
// stays enforceable instead of being switched off the first time something
// legitimately differs:
//
//	justifiedDifferences["Close"]["quic.go only: recv:signalc"] = "why"
//
// It is empty right now on purpose: quic.go and u_quic.go currently agree
// operation for operation, which is the state this test holds them in.
var justifiedDifferences = map[string]map[string]string{}

func TestQUICMirrorChannelOpsMatch(t *testing.T) {
	base := parseMethods(t, "quic.go")
	mirror := parseMethods(t, "u_quic.go")

	pairs := map[string][2]string{
		"Start":                  {"QUICConn.Start", "UQUICConn.Start"},
		"NextEvent":              {"QUICConn.NextEvent", "UQUICConn.NextEvent"},
		"Close":                  {"QUICConn.Close", "UQUICConn.Close"},
		"HandleData":             {"QUICConn.HandleData", "UQUICConn.HandleData"},
		"SendSessionTicket":      {"QUICConn.SendSessionTicket", "UQUICConn.SendSessionTicket"},
		"StoreSession":           {"QUICConn.StoreSession", "UQUICConn.StoreSession"},
		"ConnectionState":        {"QUICConn.ConnectionState", "UQUICConn.ConnectionState"},
		"SetTransportParameters": {"QUICConn.SetTransportParameters", "UQUICConn.SetTransportParameters"},
	}

	for name, pair := range pairs {
		t.Run(name, func(t *testing.T) {
			orig, hasOrig := base[pair[0]]
			mirr, hasMirr := mirror[pair[1]]
			if !hasOrig {
				t.Fatalf("%s not found in quic.go: the mirror map is stale, update this test", pair[0])
			}
			if !hasMirr {
				t.Fatalf("%s not found in u_quic.go: the mirror dropped a method", pair[1])
			}
			missing, extra := diffOps(orig, mirr)
			if len(missing) == 0 && len(extra) == 0 {
				return
			}
			for _, op := range missing {
				key := "quic.go only: " + op
				if reason, ok := justifiedDifferences[name][key]; ok {
					t.Logf("%s: %s is a justified gap (%s)", name, key, reason)
					continue
				}
				t.Errorf("%s: quic.go does %q but u_quic.go does not — mirror drift. "+
					"If this is intentional, add %q to justifiedDifferences with a reason.", name, op, key)
			}
			for _, op := range extra {
				key := "mirror only: " + op
				if reason, ok := justifiedDifferences[name][key]; ok {
					t.Logf("%s: %s is a justified gap (%s)", name, key, reason)
					continue
				}
				t.Errorf("%s: u_quic.go does %q but quic.go does not — mirror drift.", name, op)
			}
		})
	}
}

// diffOps returns (in orig but not mirror, in mirror but not orig) as multisets.
func diffOps(orig, mirr []string) (missing, extra []string) {
	count := map[string]int{}
	for _, o := range orig {
		count[o]++
	}
	for _, o := range mirr {
		count[o]--
	}
	keys := make([]string, 0, len(count))
	for k := range count {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch {
		case count[k] > 0:
			for i := 0; i < count[k]; i++ {
				missing = append(missing, k)
			}
		case count[k] < 0:
			for i := 0; i < -count[k]; i++ {
				extra = append(extra, k)
			}
		}
	}
	return missing, extra
}

// TestQUICMirrorMethodSetMatch catches the other way the mirror rots: upstream
// adds a new exported QUICConn method and u_quic.go never grows one.
func TestQUICMirrorMethodSetMatch(t *testing.T) {
	base := parseMethods(t, "quic.go")
	mirror := parseMethods(t, "u_quic.go")
	for key := range base {
		if !strings.HasPrefix(key, "QUICConn.") {
			continue
		}
		name := strings.TrimPrefix(key, "QUICConn.")
		if _, ok := mirror["UQUICConn."+name]; !ok {
			t.Errorf("quic.go has QUICConn.%s but u_quic.go has no UQUICConn.%s", name, name)
		}
	}
	for key := range mirror {
		if !strings.HasPrefix(key, "UQUICConn.") {
			continue
		}
		name := strings.TrimPrefix(key, "UQUICConn.")
		if utlsOnlyMethods[name] {
			continue
		}
		if _, ok := base["QUICConn."+name]; !ok {
			t.Errorf("u_quic.go has UQUICConn.%s but quic.go has no QUICConn.%s "+
				"(if this is uTLS-only API, add it to utlsOnlyMethods)", name, name)
		}
	}
}

// utlsOnlyMethods are UQUICConn methods with no QUICConn counterpart: they are
// this fork's own surface (a UConn can re-apply a ClientHelloSpec, a plain
// crypto/tls Conn cannot).
var utlsOnlyMethods = map[string]bool{
	"ApplyPreset": true,
}
