// midden is a compiled nmap wrapper that uploads scans to a Midden case.
//
//	midden <nmap args...>            plain nmap passthrough
//	midden -U <nmap args...>         scan, then upload the XML to a case
//	midden upload scan.xml ...       upload an existing -oX/-oN file
//	midden login [--url URL]         browser sign-in, caches an API key
//	midden whoami | logout | version
//
// Credentials live in $XDG_CONFIG_HOME/midden/credentials.json (falling back
// to ~/.config). Login opens the web app, where the signed-in browser hands
// this CLI a fresh API key via the /api/auth/cli handshake.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// version is stamped by build.sh via -ldflags.
var version = "dev"

const phases = "discovery|service|other"

type account struct {
	URL     string    `json:"url"`
	Token   string    `json:"token"`
	TokenID string    `json:"token_id"`
	User    string    `json:"user"`
	SavedAt time.Time `json:"saved_at"`
}

type store struct {
	Current  string             `json:"current"`
	Accounts map[string]account `json:"accounts"` // keyed by base URL
}

// injectable for tests
var (
	httpClient  = &http.Client{Timeout: 60 * time.Second}
	pollDelay   = 500 * time.Millisecond
	waitDelay   = time.Second
	openBrowser = func(rawurl string) error {
		var cmd []string
		switch runtime.GOOS {
		case "darwin":
			cmd = []string{"open", rawurl}
		case "windows":
			cmd = []string{"rundll32", "url.dll,FileProtocolHandler", rawurl}
		default:
			cmd = []string{"xdg-open", rawurl}
		}
		return exec.Command(cmd[0], cmd[1:]...).Start()
	}
	runNmap = func(args []string) (int, error) {
		bin := os.Getenv("MIDDEN_NMAP")
		if bin == "" {
			bin = "nmap"
		}
		cmd := exec.Command(bin, args...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		err := cmd.Run()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), nil
		}
		return 0, err
	}
)

// ---------------------------------------------------------------- credentials

func storeDir() string {
	if d := os.Getenv("MIDDEN_CONFIG_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "midden")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "midden")
}

func loadStore() store {
	s := store{Accounts: map[string]account{}}
	if b, err := os.ReadFile(filepath.Join(storeDir(), "credentials.json")); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	if s.Accounts == nil {
		s.Accounts = map[string]account{}
	}
	return s
}

func saveStore(s store) error {
	dir := storeDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(filepath.Join(dir, "credentials.json"), b, 0o600)
}

// ---------------------------------------------------------------------- client

type client struct {
	base, token string
}

func (c client) do(method, path string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("authorization", "Bearer "+c.token)
	}
	if contentType != "" {
		req.Header.Set("content-type", contentType)
	}
	return httpClient.Do(req)
}

func (c client) getJSON(path string, out any) error {
	res, err := c.do("GET", path, nil, "")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return httpError(res)
	}
	return json.NewDecoder(res.Body).Decode(out)
}

func httpError(res *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(res.Body, 200))
	return fmt.Errorf("HTTP %d %s", res.StatusCode, strings.TrimSpace(string(b)))
}

type caseInfo struct {
	ID         string  `json:"id"`
	Number     string  `json:"number"`
	Name       string  `json:"name"`
	ArchivedAt *string `json:"archivedAt"`
}

func (c client) listCases() ([]caseInfo, error) {
	var out struct {
		Cases []caseInfo `json:"cases"`
	}
	if err := c.getJSON("/api/cases", &out); err != nil {
		return nil, err
	}
	return out.Cases, nil
}

type scanResult struct {
	Status string
	Error  string
}

func (c client) uploadScan(caseID, file, name, phase string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var body strings.Builder
	w := multipart.NewWriter(&body)
	fw, err := w.CreateFormFile("file", filepath.Base(file))
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(fw, f); err != nil {
		return "", err
	}
	_ = w.WriteField("name", name)
	if phase != "" {
		_ = w.WriteField("phase", phase)
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	res, err := c.do("POST", "/api/cases/"+url.PathEscape(caseID)+"/scans", strings.NewReader(body.String()), w.FormDataContentType())
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != 201 && res.StatusCode != 200 {
		return "", httpError(res)
	}
	var out struct {
		Scan struct {
			ID string `json:"id"`
		} `json:"scan"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Scan.ID, nil
}

func (c client) waitScan(caseID, scanID string, timeout time.Duration) (scanResult, error) {
	deadline := time.Now().Add(timeout)
	for {
		var out struct {
			Scans []struct {
				ID     string  `json:"id"`
				Status string  `json:"status"`
				Error  *string `json:"error"`
			} `json:"scans"`
		}
		if err := c.getJSON("/api/cases/"+url.PathEscape(caseID)+"/scans", &out); err != nil {
			return scanResult{}, err
		}
		for _, s := range out.Scans {
			if s.ID == scanID && s.Status != "parsing" {
				r := scanResult{Status: s.Status}
				if s.Error != nil {
					r.Error = *s.Error
				}
				return r, nil
			}
		}
		if time.Now().After(deadline) {
			return scanResult{}, fmt.Errorf("scan %s still parsing after %s", scanID, timeout)
		}
		time.Sleep(waitDelay)
	}
}

// ------------------------------------------------------------------ login flow

func loginFlow(base string, timeout time.Duration) (*account, error) {
	c := client{base: base}
	var ch struct {
		Challenge string `json:"challenge"`
	}
	if err := c.getJSON("/api/auth/cli/challenge", &ch); err != nil {
		return nil, fmt.Errorf("server unreachable at %s: %w", base, err)
	}
	if len(ch.Challenge) != 32 {
		return nil, fmt.Errorf("unexpected challenge response from %s", base)
	}
	page := base + "/#/cli?challenge=" + ch.Challenge
	fmt.Fprintln(os.Stderr, "Complete the sign-in in your browser:")
	fmt.Fprintln(os.Stderr, "  "+page)
	if err := openBrowser(page); err != nil {
		fmt.Fprintln(os.Stderr, "  (could not open the browser automatically)")
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var poll struct {
			Status   string  `json:"status"`
			Token    string  `json:"token"`
			TokenID  string  `json:"tokenId"`
			Username *string `json:"username"`
		}
		if err := c.getJSON("/api/auth/cli/challenge/"+ch.Challenge, &poll); err != nil {
			return nil, err
		}
		switch poll.Status {
		case "ready":
			a := &account{URL: base, Token: poll.Token, TokenID: poll.TokenID, SavedAt: time.Now().UTC()}
			if poll.Username != nil {
				a.User = *poll.Username
			}
			return a, nil
		case "expired":
			return nil, errors.New("sign-in request expired; run: midden login")
		}
		time.Sleep(pollDelay)
	}
	return nil, errors.New("timed out waiting for browser sign-in")
}

// --------------------------------------------------------------- shared config

type config struct {
	url, token, caseID, name, phase string
	wait                            bool
}

// resolve fills url/token from flags, env, then the credential store, logging
// in through the browser when nothing is cached for that server.
func (cf *config) resolve(autoLogin bool, out io.Writer) (client, error) {
	if cf.url == "" {
		cf.url = os.Getenv("MIDDEN_URL")
	}
	s := loadStore()
	if cf.url == "" {
		cf.url = s.Current
	}
	cf.url = strings.TrimRight(cf.url, "/")
	if cf.url == "" {
		return client{}, errors.New("no Midden server: pass --url, set MIDDEN_URL, or run: midden login")
	}
	if cf.token == "" {
		cf.token = os.Getenv("MIDDEN_API_KEY")
	}
	if cf.token == "" {
		if a, ok := s.Accounts[cf.url]; ok {
			cf.token = a.Token
		}
	}
	if cf.token == "" {
		if !autoLogin {
			return client{}, fmt.Errorf("not signed in to %s — run: midden login", cf.url)
		}
		fmt.Fprintf(out, "First run: signing in to %s\n", cf.url)
		a, err := loginFlow(cf.url, 2*time.Minute)
		if err != nil {
			return client{}, err
		}
		s.Accounts[a.URL] = *a
		s.Current = a.URL
		if err := saveStore(s); err != nil {
			return client{}, err
		}
		cf.token = a.Token
	}
	return client{base: cf.url, token: cf.token}, nil
}

func pickCase(c client, in io.Reader, out io.Writer) (string, error) {
	cases, err := c.listCases()
	if err != nil {
		return "", fmt.Errorf("case list failed: %w", err)
	}
	if len(cases) == 0 {
		return "", errors.New("no cases to upload to — create one in the web UI first")
	}
	fmt.Fprintln(out, "cases:")
	for i, cs := range cases {
		mark := ""
		if cs.ArchivedAt != nil {
			mark = " [archived]"
		}
		fmt.Fprintf(out, "> %d) %s — %s%s\n", i+1, cs.Number, cs.Name, mark)
	}
	r := bufio.NewReader(in)
	for {
		fmt.Fprint(out, "type the case number you want to upload results to: ")
		line, err := r.ReadString('\n')
		if strings.TrimSpace(line) == "" && err != nil {
			return "", errors.New("no selection made")
		}
		if n, cerr := strconv.Atoi(strings.TrimSpace(line)); cerr == nil && n >= 1 && n <= len(cases) {
			return cases[n-1].ID, nil
		}
		fmt.Fprintf(out, "not a case number (1-%d)\n", len(cases))
	}
}

// ------------------------------------------------------------------- commands

func cmdLogin(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	base := fs.String("url", "", "Midden base URL")
	_ = fs.Parse(args)
	baseURL := strings.TrimRight(*base, "/")
	if baseURL == "" {
		baseURL = strings.TrimRight(os.Getenv("MIDDEN_URL"), "/")
	}
	if baseURL == "" {
		fmt.Fprintln(out, "usage: midden login --url https://midden.example")
		return 1
	}
	a, err := loginFlow(baseURL, 2*time.Minute)
	if err != nil {
		fmt.Fprintln(out, "login failed:", err)
		return 1
	}
	s := loadStore()
	s.Accounts[a.URL] = *a
	s.Current = a.URL
	if err := saveStore(s); err != nil {
		fmt.Fprintln(out, "could not save credentials:", err)
		return 1
	}
	fmt.Fprintf(out, "signed in to %s as %s\n", a.URL, a.User)
	return 0
}

func cmdLogout(args []string, out io.Writer) int {
	s := loadStore()
	target := s.Current
	if len(args) > 0 && args[0] != "" {
		target = strings.TrimRight(args[0], "/")
	}
	if a, ok := s.Accounts[target]; ok {
		if a.TokenID != "" {
			c := client{base: a.URL, token: a.Token}
			if res, err := c.do("DELETE", "/api/auth/tokens/"+url.PathEscape(a.TokenID), nil, ""); err == nil {
				res.Body.Close()
			}
		}
		delete(s.Accounts, target)
	}
	s.Current = ""
	if err := saveStore(s); err != nil {
		fmt.Fprintln(out, "could not update credentials:", err)
		return 1
	}
	fmt.Fprintln(out, "signed out")
	return 0
}

func cmdWhoami(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("whoami", flag.ExitOnError)
	urlFlag := fs.String("url", "", "Midden base URL")
	_ = fs.Parse(args)
	cf := &config{url: *urlFlag}
	c, err := cf.resolve(false, out)
	if err != nil {
		fmt.Fprintln(out, err)
		return 1
	}
	var me struct {
		User struct {
			Username    string `json:"username"`
			DisplayName string `json:"displayName"`
			Role        string `json:"role"`
		} `json:"user"`
	}
	if err := c.getJSON("/api/auth/me", &me); err != nil {
		fmt.Fprintln(out, "token rejected:", err)
		return 1
	}
	fmt.Fprintf(out, "%s (%s) — %s [%s]\n", me.User.DisplayName, me.User.Username, c.base, me.User.Role)
	return 0
}

func cmdUpload(args []string, in io.Reader, out io.Writer) int {
	var cf config
	var file string
	fs := flag.NewFlagSet("upload", flag.ExitOnError)
	fs.StringVar(&file, "f", "", "scan file (-oX or -oN)")
	fs.StringVar(&file, "file", "", "scan file")
	fs.StringVar(&cf.name, "name", "", "scan display name")
	fs.StringVar(&cf.phase, "phase", "", "scan phase: "+phases)
	fs.StringVar(&cf.caseID, "case", "", "case id")
	fs.StringVar(&cf.url, "url", "", "Midden base URL")
	fs.StringVar(&cf.token, "token", "", "API key")
	fs.BoolVar(&cf.wait, "wait", false, "wait for the server to finish parsing")
	_ = fs.Parse(args)
	if file == "" && fs.NArg() > 0 {
		file = fs.Arg(0)
	}
	if file == "" {
		fmt.Fprintln(out, "usage: midden upload <scan-file> [--name n] [--phase "+phases+"] [--case id] [--wait]")
		return 1
	}
	if _, err := os.Stat(file); err != nil {
		fmt.Fprintln(out, "no such file:", file)
		return 1
	}
	if cf.name == "" {
		cf.name = filepath.Base(file)
	}
	return doUpload(&cf, file, true, in, out)
}

// doUpload uploads file to a case, asking for a login and/or case pick as needed.
func doUpload(cf *config, file string, autoLogin bool, in io.Reader, out io.Writer) int {
	c, err := cf.resolve(autoLogin, out)
	if err != nil {
		fmt.Fprintln(out, err)
		return 1
	}
	caseID := cf.caseID
	if caseID == "" {
		caseID = os.Getenv("MIDDEN_CASE_ID")
	}
	if caseID == "" {
		tty, terr := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if terr != nil {
			fmt.Fprintln(out, "no case selected and no terminal available: pass --case or set MIDDEN_CASE_ID")
			return 1
		}
		defer tty.Close()
		in = tty
		caseID, err = pickCase(c, tty, out)
		if err != nil {
			fmt.Fprintln(out, err)
			return 1
		}
	}
	scanID, err := c.uploadScan(caseID, file, cf.name, cf.phase)
	if err != nil {
		fmt.Fprintln(out, "upload failed:", err)
		return 3
	}
	link := fmt.Sprintf("%s/#/c/%s/scans", c.base, caseID)
	if !cf.wait {
		fmt.Fprintf(out, "scan %s uploaded (parsing) → %s\n", scanID, link)
		return 0
	}
	r, err := c.waitScan(caseID, scanID, 5*time.Minute)
	if err != nil {
		fmt.Fprintln(out, err)
		return 3
	}
	if r.Status == "failed" {
		fmt.Fprintf(out, "scan %s failed to parse: %s\n%s\n", scanID, r.Error, link)
		return 4
	}
	fmt.Fprintf(out, "scan %s uploaded (%s) → %s\n", scanID, r.Status, link)
	return 0
}

func cmdNmap(args []string, in io.Reader, out io.Writer) int {
	nmapArgs := []string{}
	upload := false
	for _, a := range args {
		if a == "-U" || a == "--upload" {
			upload = true
			continue
		}
		nmapArgs = append(nmapArgs, a)
	}
	bin := os.Getenv("MIDDEN_NMAP")
	if bin == "" {
		bin = "nmap"
	}
	if _, err := exec.LookPath(bin); err != nil {
		fmt.Fprintln(out, "midden: nmap not found in PATH.")
		if runtime.GOOS == "darwin" {
			fmt.Fprintln(out, "  install with: brew install nmap")
		} else {
			fmt.Fprintln(out, "  install with your package manager (apt install nmap / dnf install nmap)")
		}
		fmt.Fprintln(out, "  (uploads of existing files work without nmap: midden upload scan.xml)")
		return 127
	}
	if !upload {
		code, err := runNmap(nmapArgs)
		if err != nil {
			fmt.Fprintln(out, "midden: could not run nmap:", err)
			return 127
		}
		return code
	}
	tmp, err := os.CreateTemp("", "midden-scan-*.xml")
	if err != nil {
		fmt.Fprintln(out, err)
		return 1
	}
	xmlPath := tmp.Name()
	tmp.Close()
	defer os.Remove(xmlPath)
	code, err := runNmap(append(append([]string{}, nmapArgs...), "-oX", xmlPath))
	if err != nil {
		fmt.Fprintln(out, "midden: could not run nmap:", err)
		return 127
	}
	if code != 0 && code != 1 { // nmap: 0 = ok, 1 = some hosts down
		fmt.Fprintf(out, "nmap exited %d; upload skipped\n", code)
		return code
	}
	cf := &config{name: "nmap " + time.Now().Format("2006-01-02 15:04")}
	return doUpload(cf, xmlPath, true, in, out)
}

// ------------------------------------------------------------------- plumbing

func usage(out io.Writer) {
	fmt.Fprint(out, `midden — nmap wrapper with one-command uploads to Midden

usage:
  midden <nmap args...>            plain nmap passthrough
  midden -U <nmap args...>         scan, then upload the result
  midden upload <file> [flags]     upload an existing -oX/-oN scan file
  midden login --url <url>         sign in through the browser
  midden whoami | logout [url] | version

env: MIDDEN_URL, MIDDEN_API_KEY, MIDDEN_CASE_ID, MIDDEN_NMAP (nmap path)
upload flags: --name n  --phase `+phases+`  --case id  --url u  --token t  --wait
exit codes: 1 config/pick, 3 transport, 4 uploaded but parse failed;
otherwise nmap's own exit code is passed through
`)
}

func run(args []string, in io.Reader, out io.Writer) int {
	if len(args) == 0 {
		usage(out)
		return 0
	}
	switch args[0] {
	case "login":
		return cmdLogin(args[1:], out)
	case "logout":
		return cmdLogout(args[1:], out)
	case "whoami":
		return cmdWhoami(args[1:], out)
	case "upload":
		return cmdUpload(args[1:], in, out)
	case "version", "--version", "-v":
		fmt.Fprintln(out, version)
		return 0
	case "help", "--help", "-h":
		usage(out)
		return 0
	default:
		return cmdNmap(args, in, out)
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout))
}
