// ky is the KyPanel command line: it manages a server through the API with an API token, from any machine.
//
//	ky login --server https://server.example.com:7711 --token kpt_…
//	ky accounts list
//	ky call listAccounts q=acme
//
// Run "ky help" for every command.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var version = "dev"

const help = `ky — KyPanel command line

Sign in (the token comes from Ky Admin › Security Center › API Tokens, or the customer panel's API Tokens):
  ky login --server https://HOST:7711 --token kpt_… [--profile NAME] [--insecure]
  ky logout [--profile NAME]          ky profiles          ky whoami

Accounts (admin tokens; ACCOUNT = username, main domain or id):
  ky accounts list [--search TEXT] [--status active|suspended] [--package NAME]
  ky accounts show ACCOUNT
  ky accounts create USERNAME DOMAIN --package NAME [--email ADDRESS] [--password PASS] [--wait]
  ky accounts suspend ACCOUNT [--reason TEXT]       ky accounts unsuspend ACCOUNT
  ky accounts terminate ACCOUNT --yes [--keep-home]
  ky accounts package ACCOUNT PACKAGE                ky accounts password ACCOUNT [--password PASS]
  ky accounts sso ACCOUNT [--admin] [--goto /user/email]
  ky packages list

Inside an account (with an account token, leave ACCOUNT out):
  ky domains list ACCOUNT
  ky domains add ACCOUNT DOMAIN [--alias] [--docroot DIR] [--wait]
  ky domains add ACCOUNT --sub LABEL --parent DOMAIN [--docroot DIR] [--wait]
  ky domains remove ACCOUNT DOMAIN --yes [--remove-files]
  ky email list ACCOUNT
  ky email create ACCOUNT ADDRESS [--password PASS] [--quota MB]
  ky email password ACCOUNT ADDRESS [--password PASS]
  ky email delete ACCOUNT ADDRESS --yes
  ky dns records ACCOUNT ZONE
  ky dns add ACCOUNT ZONE NAME TYPE CONTENT [--ttl SECONDS] [--priority N]
  ky dns delete ACCOUNT ZONE RECORD-ID
  ky databases list ACCOUNT
  ky databases create ACCOUNT NAME [--user NAME --password PASS]

Background jobs, webhooks and events:
  ky jobs show ID                    ky jobs wait ID
  ky webhooks list                   ky webhooks add URL [--events a.b,c.*] [--description TEXT]
  ky webhooks test ID                ky webhooks delete ID
  ky events [--after SEQ] [--type a,b] [--follow]

Server (admin tokens):
  ky server status                   ky server update [--check]

Any API operation (see "ky ops"):
  ky ops [FILTER]                    list operations: id, method, path, summary
  ky call OPERATION [name=value…] [-d JSON]
        path parameters, query parameters and body fields by name; -d sends a JSON body as is
  ky api METHOD PATH [-d JSON]       raw request

On the server itself, as root: ky admin reset-root and the other kyd commands work as before.

Options: --json (raw JSON output), --profile NAME, --insecure (self-signed certificate).
Environment: KY_SERVER, KY_TOKEN, KY_PROFILE, KY_INSECURE=1, KY_CONFIG (config file).
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		var ae *apiError
		if errors.As(err, &ae) {
			fmt.Fprintln(os.Stderr, "ky:", ae.Error())
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "ky:", err)
		os.Exit(1)
	}
}

// args holds positionals and --flags, in any order. Flags in bools take no value.
type args struct {
	pos   []string
	flags map[string]string
}

func parseArgs(in []string, bools ...string) args {
	a := args{flags: map[string]string{}}
	isBool := map[string]bool{"json": true, "insecure": true}
	for _, b := range bools {
		isBool[b] = true
	}
	for i := 0; i < len(in); i++ {
		s := in[i]
		if s == "--" {
			a.pos = append(a.pos, in[i+1:]...)
			break
		}
		if s == "-d" && i+1 < len(in) {
			a.flags["d"] = in[i+1]
			i++
			continue
		}
		if !strings.HasPrefix(s, "--") || len(s) == 2 {
			a.pos = append(a.pos, s)
			continue
		}
		k, v, has := strings.Cut(s[2:], "=")
		if !has && !isBool[k] && i+1 < len(in) {
			v = in[i+1]
			i++
		} else if !has {
			v = "true"
		}
		a.flags[k] = v
	}
	return a
}

func (a args) has(k string) bool   { return a.flags[k] != "" && a.flags[k] != "false" }
func (a args) get(k string) string { return a.flags[k] }
func (a args) arg(i int) string {
	if i < len(a.pos) {
		return a.pos[i]
	}
	return ""
}

type profile struct {
	Server   string `json:"server"`
	Token    string `json:"token"`
	Insecure bool   `json:"insecure,omitempty"`
	// account tokens: the account they belong to
	AccountID   string `json:"account_id,omitempty"`
	AccountUser string `json:"account_username,omitempty"`
}

type config struct {
	Current  string              `json:"current"`
	Profiles map[string]*profile `json:"profiles"`
}

func configPath() string {
	if p := os.Getenv("KY_CONFIG"); p != "" {
		return p
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = filepath.Join(os.Getenv("HOME"), ".config")
	}
	return filepath.Join(dir, "ky", "config.json")
}

func loadConfig() *config {
	c := &config{Profiles: map[string]*profile{}}
	if b, err := os.ReadFile(configPath()); err == nil {
		_ = json.Unmarshal(b, c)
	}
	if c.Profiles == nil {
		c.Profiles = map[string]*profile{}
	}
	return c
}

func (c *config) save() error {
	p := configPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

type client struct {
	prof *profile
	http *http.Client
	json bool
}

type apiError struct {
	Status int               `json:"status"`
	Title  string            `json:"title"`
	Detail string            `json:"detail"`
	Fields map[string]string `json:"fields"`
}

func (e *apiError) Error() string {
	msg := e.Title
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	if e.Detail != "" {
		msg += " (" + e.Detail + ")"
	}
	keys := make([]string, 0, len(e.Fields))
	for k := range e.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		msg += fmt.Sprintf("\n  %s: %s", k, e.Fields[k])
	}
	return fmt.Sprintf("%d: %s", e.Status, msg)
}

func newClient(a args) (*client, error) {
	cfg := loadConfig()
	name := a.get("profile")
	if name == "" {
		name = os.Getenv("KY_PROFILE")
	}
	if name == "" {
		name = cfg.Current
	}
	p := &profile{}
	if q, ok := cfg.Profiles[name]; ok {
		cp := *q
		p = &cp
	} else if a.get("profile") != "" {
		return nil, fmt.Errorf("no profile %q (ky profiles)", name)
	}
	if v := os.Getenv("KY_SERVER"); v != "" {
		p.Server = v
	}
	if v := os.Getenv("KY_TOKEN"); v != "" {
		p.Token, p.AccountID, p.AccountUser = v, "", ""
	}
	if os.Getenv("KY_INSECURE") == "1" || a.has("insecure") {
		p.Insecure = true
	}
	if p.Server == "" || p.Token == "" {
		return nil, errors.New("not signed in: ky login --server https://HOST:7711 --token kpt_…")
	}
	return &client{prof: p, http: httpClient(p.Insecure), json: a.has("json")}, nil
}

func httpClient(insecure bool) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // the user asked for it (--insecure)
	}
	return &http.Client{Timeout: 5 * time.Minute, Transport: tr}
}

// do sends a request; body is JSON-encoded unless it's already []byte. out may be nil.
func (c *client) do(method, path string, query url.Values, body any, out any) error {
	u := strings.TrimRight(c.prof.Server, "/") + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rdr io.Reader
	if body != nil {
		b, ok := body.([]byte)
		if !ok {
			b, _ = json.Marshal(body)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, u, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.prof.Token)
	req.Header.Set("User-Agent", "ky/"+version)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "certificate") {
			return fmt.Errorf("%w\n(the server's certificate isn't trusted; use its hostname, or --insecure)", err)
		}
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		e := &apiError{Status: resp.StatusCode}
		_ = json.Unmarshal(b, e)
		return e
	}
	if out == nil || len(b) == 0 {
		return nil
	}
	if raw, ok := out.(*json.RawMessage); ok {
		*raw = b
		return nil
	}
	return json.Unmarshal(b, out)
}

func (c *client) get(path string, q url.Values, out any) error { return c.do("GET", path, q, nil, out) }

func printJSON(b []byte) {
	var buf bytes.Buffer
	if json.Indent(&buf, b, "", "  ") != nil {
		os.Stdout.Write(b)
		return
	}
	buf.WriteByte('\n')
	os.Stdout.Write(buf.Bytes())
}

func run(argv []string) error {
	if len(argv) == 0 || argv[0] == "help" || argv[0] == "--help" || argv[0] == "-h" {
		fmt.Print(help)
		return nil
	}
	cmd, rest := argv[0], argv[1:]
	if localCommands[cmd] {
		return runLocal(argv)
	}
	switch cmd {
	case "version", "--version":
		fmt.Println("ky", version)
		return nil
	case "login":
		return cmdLogin(rest)
	case "logout":
		return cmdLogout(rest)
	case "profiles":
		return cmdProfiles()
	case "ops":
		return cmdOps(rest)
	}
	sub := ""
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		sub, rest = rest[0], rest[1:]
	}
	handlers := map[string]map[string]func(*client, args) error{
		"accounts":  {"list": accountsList, "show": accountsShow, "create": accountsCreate, "suspend": accountsSuspend, "unsuspend": accountsUnsuspend, "terminate": accountsTerminate, "package": accountsPackage, "password": accountsPassword, "sso": accountsSSO},
		"packages":  {"list": packagesList},
		"domains":   {"list": domainsList, "add": domainsAdd, "remove": domainsRemove},
		"email":     {"list": emailList, "create": emailCreate, "password": emailPassword, "delete": emailDelete},
		"dns":       {"records": dnsRecords, "add": dnsAdd, "delete": dnsDelete},
		"databases": {"list": databasesList, "create": databasesCreate},
		"jobs":      {"show": jobsShow, "wait": jobsWait},
		"webhooks":  {"list": webhooksList, "add": webhooksAdd, "test": webhooksTest, "delete": webhooksDelete},
		"server":    {"status": serverStatus, "update": serverUpdate},
	}
	single := map[string]func(*client, args) error{"whoami": cmdWhoami, "call": cmdCall, "api": cmdAPI, "events": cmdEvents}
	bools := []string{"wait", "yes", "keep-home", "admin", "alias", "remove-files", "follow", "check"}
	if h, ok := single[cmd]; ok {
		if sub != "" {
			rest = append([]string{sub}, rest...)
		}
		a := parseArgs(rest, bools...)
		c, err := newClient(a)
		if err != nil {
			return err
		}
		return h(c, a)
	}
	group, ok := handlers[cmd]
	if !ok {
		return fmt.Errorf("unknown command %q (ky help)", cmd)
	}
	h, ok := group[sub]
	if !ok {
		subs := make([]string, 0, len(group))
		for k := range group {
			subs = append(subs, k)
		}
		sort.Strings(subs)
		return fmt.Errorf("ky %s: choose one of %s", cmd, strings.Join(subs, ", "))
	}
	a := parseArgs(rest, bools...)
	c, err := newClient(a)
	if err != nil {
		return err
	}
	return h(c, a)
}

// localCommands belong to kyd on the server itself (no API, no token): ky admin reset-root, ky config…
var localCommands = map[string]bool{"admin": true, "config": true, "agent": true, "serve": true, "node-updater": true}

const kydPath = "/usr/local/kypanel/bin/kyd"

func runLocal(argv []string) error {
	if _, err := os.Stat(kydPath); err != nil {
		return fmt.Errorf("%q runs on a KyPanel server (as root); here, use the API commands (ky help)", argv[0])
	}
	cmd := exec.Command(kydPath, argv...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		return err
	}
	return nil
}

func cmdLogin(argv []string) error {
	a := parseArgs(argv)
	server, token := a.get("server"), a.get("token")
	if token == "" {
		token = os.Getenv("KY_TOKEN")
	}
	if server == "" || token == "" {
		return errors.New("usage: ky login --server https://HOST:7711 --token kpt_… [--profile NAME] [--insecure]")
	}
	if !strings.Contains(server, "://") {
		server = "https://" + server
	}
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid server %q", server)
	}
	if u.Port() == "" {
		u.Host += ":7711"
	}
	p := &profile{Server: u.Scheme + "://" + u.Host, Token: token, Insecure: a.has("insecure")}
	c := &client{prof: p, http: httpClient(p.Insecure)}
	var me struct {
		Type    string            `json:"type"`
		Name    string            `json:"name"`
		Admin   string            `json:"admin"`
		Account map[string]string `json:"account"`
		Server  string            `json:"server"`
		Version string            `json:"version"`
	}
	if err := c.get("/api/v1/token", nil, &me); err != nil {
		return err
	}
	if me.Type == "account" {
		p.AccountID, p.AccountUser = me.Account["id"], me.Account["username"]
	}
	name := a.get("profile")
	if name == "" {
		name = "default"
	}
	cfg := loadConfig()
	cfg.Profiles[name] = p
	cfg.Current = name
	if err := cfg.save(); err != nil {
		return err
	}
	who := "admin " + me.Admin
	if me.Type == "account" {
		who = "account " + p.AccountUser
	}
	fmt.Printf("Signed in to %s (KyPanel %s) as %s with token %q. Profile %q saved in %s.\n", me.Server, me.Version, who, me.Name, name, configPath())
	return nil
}

func cmdLogout(argv []string) error {
	a := parseArgs(argv)
	cfg := loadConfig()
	name := a.get("profile")
	if name == "" {
		name = cfg.Current
	}
	if _, ok := cfg.Profiles[name]; !ok {
		return fmt.Errorf("no profile %q", name)
	}
	delete(cfg.Profiles, name)
	if cfg.Current == name {
		cfg.Current = ""
		for k := range cfg.Profiles {
			cfg.Current = k
			break
		}
	}
	if err := cfg.save(); err != nil {
		return err
	}
	fmt.Printf("Profile %q removed (the token itself stays valid until you revoke it in the panel).\n", name)
	return nil
}

func cmdProfiles() error {
	cfg := loadConfig()
	names := make([]string, 0, len(cfg.Profiles))
	for k := range cfg.Profiles {
		names = append(names, k)
	}
	sort.Strings(names)
	t := newTable("", "PROFILE", "SERVER", "TOKEN", "ACCOUNT")
	for _, n := range names {
		p := cfg.Profiles[n]
		mark := ""
		if n == cfg.Current {
			mark = "*"
		}
		tok := p.Token
		if len(tok) > 12 {
			tok = tok[:12] + "…"
		}
		t.row(mark, n, p.Server, tok, p.AccountUser)
	}
	t.print()
	return nil
}

func cmdWhoami(c *client, a args) error {
	var raw json.RawMessage
	if err := c.get("/api/v1/token", nil, &raw); err != nil {
		return err
	}
	printJSON(raw)
	return nil
}
