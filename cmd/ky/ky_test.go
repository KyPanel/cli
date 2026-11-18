package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseArgs(t *testing.T) {
	a := parseArgs([]string{"acme", "acme.com", "--package", "basic", "--wait", "--email=a@b.c", "-d", "{}", "x=1"}, "wait")
	if !reflect.DeepEqual(a.pos, []string{"acme", "acme.com", "x=1"}) {
		t.Fatalf("pos: %v", a.pos)
	}
	if a.get("package") != "basic" || !a.has("wait") || a.get("email") != "a@b.c" || a.get("d") != "{}" {
		t.Fatalf("flags: %v", a.flags)
	}
}

func TestTyped(t *testing.T) {
	if typed("12", "integer") != int64(12) || typed("true", "boolean") != true || typed("x", "string") != "x" {
		t.Fatal("scalars")
	}
	if !reflect.DeepEqual(typed("a,b", "array"), []string{"a", "b"}) || !reflect.DeepEqual(typed(`["a"]`, "array"), []any{"a"}) {
		t.Fatal("arrays")
	}
}

func TestSpecLoads(t *testing.T) {
	s, ops, err := loadSpec()
	if err != nil || len(ops) < 500 {
		t.Fatalf("spec: %v, %d ops", err, len(ops))
	}
	for _, op := range ops {
		if op.ID == "createAccount" {
			if p := s.bodyProps(op); p["username"] != "string" {
				t.Fatalf("createAccount body: %v", p)
			}
			return
		}
	}
	t.Fatal("createAccount not found")
}

// A fake server: login stores the profile, accounts resolve by username, call fills path and body.
func TestLoginAndCommands(t *testing.T) {
	var got []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer kpt_test" {
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": 401, "title": "Invalid or expired API token"})
			return
		}
		got = append(got, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/token":
			_, _ = w.Write([]byte(`{"type":"admin","admin":"root","name":"ci","server":"srv.example.com","version":"1"}`))
		case r.URL.Path == "/api/v1/accounts" && r.Method == "GET":
			_, _ = w.Write([]byte(`{"items":[{"id":"01JABCDEFGHJKMNPQRSTVWXYZ0","username":"acme","main_domain":"acme.com"}],"total":1}`))
		case strings.HasSuffix(r.URL.Path, "/suspend"):
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b["reason"] != "unpaid" {
				w.WriteHeader(400)
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	t.Setenv("KY_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	if err := run([]string{"login", "--server", srv.URL, "--token", "kpt_bad", "--insecure"}); err == nil {
		t.Fatal("bad token accepted")
	}
	if err := run([]string{"login", "--server", srv.URL, "--token", "kpt_test", "--insecure"}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(os.Getenv("KY_CONFIG")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("config file: %v %v", fi, err)
	}
	got = nil
	if err := run([]string{"accounts", "suspend", "acme", "--reason", "unpaid"}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !strings.HasPrefix(got[1], "POST /api/v1/accounts/01JABCDEFGHJKMNPQRSTVWXYZ0/suspend") {
		t.Fatalf("requests: %v", got)
	}
	got = nil
	if err := run([]string{"call", "setAccountShell", "id=acme", "shell=jailed"}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !strings.HasPrefix(got[1], "PUT /api/v1/accounts/01JABCDEFGHJKMNPQRSTVWXYZ0/shell") {
		t.Fatalf("call: %v", got)
	}
	if err := run([]string{"call", "setAccountShell", "id=01JABCDEFGHJKMNPQRSTVWXYZ0", "nope=1"}); err == nil || !strings.Contains(err.Error(), "no field") {
		t.Fatalf("unknown field: %v", err)
	}
}
