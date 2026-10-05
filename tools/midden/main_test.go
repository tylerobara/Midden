package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setup(t *testing.T) {
	t.Setenv("MIDDEN_CONFIG_DIR", t.TempDir())
	pollDelay, waitDelay = 1e6, 1e6 // 1ms
}

func TestStoreRoundTrip(t *testing.T) {
	setup(t)
	s := loadStore()
	s.Current = "https://m1"
	s.Accounts["https://m1"] = account{URL: "https://m1", Token: "mk_a", User: "ty"}
	if err := saveStore(s); err != nil {
		t.Fatal(err)
	}
	got := loadStore()
	if got.Current != "https://m1" || got.Accounts["https://m1"].Token != "mk_a" {
		t.Fatalf("store lost data: %+v", got)
	}
	b, _ := os.ReadFile(filepath.Join(storeDir(), "credentials.json"))
	if info, _ := os.Stat(filepath.Join(storeDir(), "credentials.json")); info.Mode().Perm() != 0o600 {
		t.Errorf("credentials file mode %v, want 600", info.Mode().Perm())
	}
	_ = b
}

func TestPickCase(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/cases" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("authorization") != "Bearer mk_k" {
			t.Error("missing bearer")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"cases": []caseInfo{
			{ID: "case_a", Number: "C1", Name: "first"},
			{ID: "case_b", Number: "C2", Name: "second", ArchivedAt: strptr("yes")},
		}})
	}))
	defer srv.Close()
	c := client{base: srv.URL, token: "mk_k"}
	var out bytes.Buffer
	id, err := pickCase(c, strings.NewReader("9\n2\n"), &out)
	if err != nil || id != "case_b" {
		t.Fatalf("got %q %v", id, err)
	}
	o := out.String()
	if !strings.Contains(o, "> 2) C2 — second [archived]") || !strings.Contains(o, "not a case number") {
		t.Errorf("bad output:\n%s", o)
	}
}

func TestUploadAndWait(t *testing.T) {
	var gotFields map[string]string
	var gotBearer string
	polls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBearer = r.Header.Get("authorization")
		if r.Method == "POST" {
			_ = r.ParseMultipartForm(1 << 20)
			gotFields = map[string]string{"name": r.FormValue("name"), "phase": r.FormValue("phase")}
			file, _, _ := r.FormFile("file")
			b, _ := io.ReadAll(file)
			if !strings.Contains(string(b), "nmaprun") {
				t.Error("file body missing")
			}
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"scan":{"id":"s1"}}`))
			return
		}
		polls++
		status := "ready"
		if polls == 1 {
			status = "parsing"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"scans": []map[string]any{{"id": "s1", "status": status}}})
	}))
	defer srv.Close()
	dir := t.TempDir()
	file := filepath.Join(dir, "scan.xml")
	_ = os.WriteFile(file, []byte("<nmaprun/>"), 0o600)

	var out bytes.Buffer
	cf := &config{url: srv.URL, token: "mk_k", caseID: "case_a", name: "edge", phase: "discovery", wait: true}
	if code := doUpload(cf, file, false, nil, &out); code != 0 {
		t.Fatalf("exit %d out=%s", code, out.String())
	}
	if gotBearer != "Bearer mk_k" || gotFields["name"] != "edge" || gotFields["phase"] != "discovery" {
		t.Fatalf("bad upload: bearer=%q fields=%v", gotBearer, gotFields)
	}
	if !strings.Contains(out.String(), "(ready)") || !strings.Contains(out.String(), "#/c/case_a/scans") {
		t.Errorf("bad summary: %s", out.String())
	}
}

func TestUploadTransportAndParseFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			http.Error(w, `{"error":"boom"}`, 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"scans": []map[string]any{{"id": "s1", "status": "failed", "error": "bad xml"}}})
	}))
	defer srv.Close()
	file := filepath.Join(t.TempDir(), "s.xml")
	_ = os.WriteFile(file, []byte("<x/>"), 0o600)
	var out bytes.Buffer
	base := config{url: srv.URL, token: "mk_k", caseID: "c1", name: "n"}
	if code := doUpload(&base, file, false, nil, &out); code != 3 {
		t.Fatalf("transport failure exit %d, want 3 (%s)", code, out.String())
	}
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			_, _ = w.Write([]byte(`{"scan":{"id":"s1"}}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"scans": []map[string]any{{"id": "s1", "status": "failed", "error": "bad xml"}}})
	}))
	defer okSrv.Close()
	cf := &config{url: okSrv.URL, token: "mk_k", caseID: "c1", name: "n", wait: true}
	out.Reset()
	if code := doUpload(cf, file, false, nil, &out); code != 4 {
		t.Fatalf("parse failure exit %d, want 4 (%s)", code, out.String())
	}
}

func TestLoginFlow(t *testing.T) {
	setup(t)
	opened := ""
	openBrowser = func(u string) error { opened = u; return nil }
	authed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/auth/cli/challenge":
			_, _ = w.Write([]byte(`{"challenge":"0123456789abcdef0123456789abcdef","expiresIn":120}`))
		case strings.HasPrefix(r.URL.Path, "/api/auth/cli/challenge/"):
			if authed {
				_, _ = w.Write([]byte(`{"status":"ready","token":"mk_new","tokenId":"tok1","username":"ty"}`))
			} else {
				authed = true // simulate the browser approving
				_, _ = w.Write([]byte(`{"status":"pending"}`))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	a, err := loginFlow(srv.URL, 5e9)
	if err != nil {
		t.Fatal(err)
	}
	if a.Token != "mk_new" || a.User != "ty" {
		t.Fatalf("bad account %+v", a)
	}
	if !strings.Contains(opened, "/#/cli?challenge=0123456789abcdef0123456789abcdef") {
		t.Errorf("browser opened %q", opened)
	}
}

func TestNmapPassthroughAndUploadFlags(t *testing.T) {
	setup(t)
	fake := filepath.Join(t.TempDir(), "nmap")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MIDDEN_NMAP", fake) // LookPath just needs it to exist + be executable
	var captured []string
	var uploadHit bool
	var upName, upPhase string
	runNmap = func(args []string) (int, error) { captured = args; return 0, nil }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uploadHit = true
		_ = r.ParseMultipartForm(1 << 20)
		upName, upPhase = r.FormValue("name"), r.FormValue("phase")
		_, _ = w.Write([]byte(`{"scan":{"id":"s1"}}`))
	}))
	defer srv.Close()
	var out bytes.Buffer

	// passthrough: -U not consumed, no upload
	code := cmdNmap([]string{"-sT", "-T4", "10.0.0.1"}, nil, &out)
	if code != 0 || len(captured) != 3 || uploadHit {
		t.Fatalf("passthrough wrong: code=%d args=%v upload=%v", code, captured, uploadHit)
	}

	// upload: -U stripped, upload flags consumed, -oX appended, cached login used
	t.Setenv("MIDDEN_CASE_ID", "case_a")
	load := loadStore()
	load.Current = srv.URL
	load.Accounts[srv.URL] = account{URL: srv.URL, Token: "mk_k"}
	_ = saveStore(load)
	code = cmdNmap([]string{"-sT", "-U", "--name", "edge sweep", "--phase", "service", "10.0.0.1"}, nil, &out)
	if code != 0 || !uploadHit {
		t.Fatalf("upload exit %d out=%s", code, out.String())
	}
	if captured[0] != "-sT" || captured[1] != "10.0.0.1" || captured[2] != "-oX" || len(captured) != 4 {
		t.Fatalf("nmap args wrong: %v", captured)
	}
	if upName != "edge sweep" || upPhase != "service" {
		t.Fatalf("upload fields wrong: name=%q phase=%q", upName, upPhase)
	}
	if !strings.Contains(out.String(), "scan s1 uploaded") {
		t.Errorf("missing summary: %s", out.String())
	}
}

func TestRunDispatchAndVersion(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"version"}, nil, &out); code != 0 || out.String() != version+"\n" {
		t.Fatalf("version: %d %q", code, out.String())
	}
	out.Reset()
	if code := run(nil, nil, &out); code != 0 || !strings.Contains(out.String(), "nmap wrapper") {
		t.Fatalf("usage: %d", code)
	}
}

func TestLogoutRevokes(t *testing.T) {
	setup(t)
	var revoked string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		revoked = r.Method + " " + r.URL.Path
	}))
	defer srv.Close()
	s := loadStore()
	s.Current = srv.URL
	s.Accounts[srv.URL] = account{URL: srv.URL, Token: "mk_k", TokenID: "tok9"}
	_ = saveStore(s)
	var out bytes.Buffer
	if code := cmdLogout(nil, &out); code != 0 {
		t.Fatal(code)
	}
	if revoked != "DELETE /api/auth/tokens/tok9" {
		t.Errorf("server not revoked: %q", revoked)
	}
	if len(loadStore().Accounts) != 0 {
		t.Error("local creds not cleared")
	}
}

func strptr(s string) *string { return &s }
