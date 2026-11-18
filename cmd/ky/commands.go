package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

const V = "/api/v1"

var esc = url.PathEscape

type table struct {
	w *tabwriter.Writer
}

func newTable(cols ...string) *table {
	t := &table{w: tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)}
	if cols[0] == "" { // first column is a marker without a header
		cols = cols[1:]
		fmt.Fprintln(t.w, "\t"+strings.Join(cols, "\t"))
		return t
	}
	fmt.Fprintln(t.w, strings.Join(cols, "\t"))
	return t
}

func (t *table) row(v ...any) {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = fmt.Sprint(x)
	}
	fmt.Fprintln(t.w, strings.Join(s, "\t"))
}

func (t *table) print() { _ = t.w.Flush() }

func (c *client) show(raw json.RawMessage, v any, printer func()) error {
	if c.json {
		printJSON(raw)
		return nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return err
	}
	printer()
	return nil
}

func mb(v int64) string {
	switch {
	case v <= 0:
		return "unlimited"
	case v >= 1024 && v%1024 == 0:
		return fmt.Sprintf("%d GB", v/1024)
	}
	return fmt.Sprintf("%d MB", v)
}

func when(ms int64) string {
	if ms == 0 {
		return "-"
	}
	return time.UnixMilli(ms).Local().Format("2006-01-02 15:04")
}

type account struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	MainDomain  string `json:"main_domain"`
	Status      string `json:"status"`
	PackageName string `json:"package_name"`
	OwnerName   string `json:"owner_name"`
	IPAddress   string `json:"ip_address"`
	DiskUsedMB  int64  `json:"disk_used_mb"`
	DiskQuotaMB int64  `json:"disk_quota_mb"`
	CreatedAt   int64  `json:"created_at"`
}

func isID(s string) bool {
	if len(s) != 26 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}

// account takes the ACCOUNT argument (username, main domain or id) off the positionals. With an account token
// there is none: the token's own account is used.
func (c *client) account(a args) (string, []string, error) {
	if c.prof.AccountID != "" {
		return c.prof.AccountID, a.pos, nil
	}
	if len(a.pos) == 0 {
		return "", nil, errors.New("name the account (username, main domain or id)")
	}
	ref, rest := a.pos[0], a.pos[1:]
	if isID(ref) {
		return ref, rest, nil
	}
	var page struct {
		Items []account `json:"items"`
	}
	if err := c.get(V+"/accounts", url.Values{"q": {ref}, "per_page": {"100"}}, &page); err != nil {
		return "", nil, err
	}
	for _, x := range page.Items {
		if strings.EqualFold(x.Username, ref) || strings.EqualFold(x.MainDomain, ref) {
			return x.ID, rest, nil
		}
	}
	return "", nil, fmt.Errorf("no account %q", ref)
}

func (c *client) packageID(name string) (string, error) {
	var out struct {
		Items []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := c.get(V+"/packages", nil, &out); err != nil {
		return "", err
	}
	for _, p := range out.Items {
		if p.ID == name || strings.EqualFold(p.Name, name) {
			return p.ID, nil
		}
	}
	return "", fmt.Errorf("no package %q (ky packages list)", name)
}

type domain struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Docroot    string `json:"docroot"`
	PHPVersion string `json:"php_version"`
	Status     string `json:"status"`
	ForceHTTPS bool   `json:"force_https"`
	SSL        *struct {
		HasCert  bool   `json:"has_cert"`
		NotAfter int64  `json:"not_after"`
		Problem  string `json:"problem"`
	} `json:"ssl"`
}

func (c *client) domains(acct string) ([]domain, error) {
	var out struct {
		Items []domain `json:"items"`
	}
	err := c.get(V+"/accounts/"+esc(acct)+"/domains", nil, &out)
	return out.Items, err
}

func (c *client) domainID(acct, name string) (string, error) {
	list, err := c.domains(acct)
	if err != nil {
		return "", err
	}
	for _, d := range list {
		if strings.EqualFold(d.Name, name) || d.ID == name {
			return d.ID, nil
		}
	}
	return "", fmt.Errorf("no domain %q in this account", name)
}

func (c *client) zoneID(acct, name string) (string, error) {
	var out struct {
		Items []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := c.get(V+"/accounts/"+esc(acct)+"/dns/zones", nil, &out); err != nil {
		return "", err
	}
	for _, z := range out.Items {
		if strings.EqualFold(z.Name, strings.TrimSuffix(name, ".")) || z.ID == name {
			return z.ID, nil
		}
	}
	return "", fmt.Errorf("no DNS zone %q in this account", name)
}

type mailbox struct {
	ID        string `json:"id"`
	Address   string `json:"address"`
	QuotaMB   *int64 `json:"quota_mb"`
	UsedBytes int64  `json:"used_bytes"`
	Login     string `json:"login_state"`
	Receive   string `json:"receive_state"`
	Send      string `json:"send_state"`
	System    bool   `json:"is_system"`
}

func (c *client) mailboxes(acct string) ([]mailbox, error) {
	var out struct {
		Items []mailbox `json:"items"`
	}
	err := c.get(V+"/accounts/"+esc(acct)+"/email/accounts", nil, &out)
	return out.Items, err
}

func (c *client) mailboxID(acct, addr string) (string, error) {
	list, err := c.mailboxes(acct)
	if err != nil {
		return "", err
	}
	for _, m := range list {
		if strings.EqualFold(m.Address, addr) || m.ID == addr {
			return m.ID, nil
		}
	}
	return "", fmt.Errorf("no mailbox %q in this account", addr)
}

// --password, or a random one (printed so the user can keep it)
func password(a args) (string, bool) {
	if p := a.get("password"); p != "" {
		return p, false
	}
	const set = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_.!@#%"
	b := make([]byte, 20)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		b[i] = set[n.Int64()]
	}
	return string(b), true
}

func need(a args, n int, usage string) error {
	if len(a.pos) < n {
		return errors.New("usage: " + usage)
	}
	return nil
}

func confirm(a args, what string) error {
	if !a.has("yes") {
		return fmt.Errorf("%s can't be undone: add --yes to go ahead", what)
	}
	return nil
}

func (c *client) waitJob(id string) error {
	cursor := int64(0)
	for {
		var out struct {
			Job struct {
				Status   string `json:"status"`
				Error    string `json:"error"`
				Progress int    `json:"progress_pct"`
			} `json:"job"`
			Log []struct {
				Level   string `json:"level"`
				Message string `json:"message"`
			} `json:"log"`
			Cursor int64 `json:"log_cursor"`
		}
		if err := c.get(V+"/jobs/"+esc(id), url.Values{"log_after": {strconv.FormatInt(cursor, 10)}}, &out); err != nil {
			return err
		}
		for _, l := range out.Log {
			fmt.Fprintf(os.Stderr, "  %s\n", l.Message)
		}
		if out.Cursor > cursor {
			cursor = out.Cursor
		}
		switch out.Job.Status {
		case "succeeded":
			return nil
		case "failed", "dead", "cancelled":
			if out.Job.Error != "" {
				return fmt.Errorf("job %s %s: %s", id, out.Job.Status, out.Job.Error)
			}
			return fmt.Errorf("job %s %s", id, out.Job.Status)
		}
		time.Sleep(time.Second)
	}
}

func (c *client) afterJob(a args, raw json.RawMessage, done string) error {
	var r struct {
		JobID string `json:"job_id"`
	}
	_ = json.Unmarshal(raw, &r)
	if c.json {
		printJSON(raw)
	}
	if r.JobID == "" {
		if !c.json {
			fmt.Println(done)
		}
		return nil
	}
	if !a.has("wait") {
		if !c.json {
			fmt.Printf("%s (job %s; ky jobs wait %s)\n", done, r.JobID, r.JobID)
		}
		return nil
	}
	if err := c.waitJob(r.JobID); err != nil {
		return err
	}
	if !c.json {
		fmt.Println(done)
	}
	return nil
}

func jobsShow(c *client, a args) error {
	if err := need(a, 1, "ky jobs show ID"); err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.get(V+"/jobs/"+esc(a.arg(0)), nil, &raw); err != nil {
		return err
	}
	printJSON(raw)
	return nil
}

func jobsWait(c *client, a args) error {
	if err := need(a, 1, "ky jobs wait ID"); err != nil {
		return err
	}
	if err := c.waitJob(a.arg(0)); err != nil {
		return err
	}
	fmt.Println("Job finished.")
	return nil
}

func accountsList(c *client, a args) error {
	q := url.Values{"per_page": {"500"}}
	for k, f := range map[string]string{"search": "q", "status": "status", "package": "package", "owner": "owner"} {
		if v := a.get(k); v != "" {
			q.Set(f, v)
		}
	}
	var raw json.RawMessage
	if err := c.get(V+"/accounts", q, &raw); err != nil {
		return err
	}
	var page struct {
		Items []account `json:"items"`
		Total int       `json:"total"`
	}
	return c.show(raw, &page, func() {
		t := newTable("USERNAME", "DOMAIN", "PACKAGE", "OWNER", "STATUS", "DISK", "IP")
		for _, x := range page.Items {
			t.row(x.Username, x.MainDomain, x.PackageName, x.OwnerName, x.Status, fmt.Sprintf("%d/%s", x.DiskUsedMB, mb(x.DiskQuotaMB)), x.IPAddress)
		}
		t.print()
		if page.Total > len(page.Items) {
			fmt.Printf("(%d of %d; narrow it with --search)\n", len(page.Items), page.Total)
		}
	})
}

func accountsShow(c *client, a args) error {
	id, _, err := c.account(a)
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.get(V+"/accounts/"+esc(id), nil, &raw); err != nil {
		return err
	}
	printJSON(raw)
	return nil
}

func accountsCreate(c *client, a args) error {
	if err := need(a, 2, "ky accounts create USERNAME DOMAIN --package NAME [--email ADDRESS] [--password PASS] [--wait]"); err != nil {
		return err
	}
	if a.get("package") == "" {
		return errors.New("choose the package: --package NAME (ky packages list)")
	}
	pkg, err := c.packageID(a.get("package"))
	if err != nil {
		return err
	}
	pass, generated := password(a)
	body := map[string]any{"username": a.arg(0), "domain": a.arg(1), "package_id": pkg, "password": pass, "contact_email": a.get("email")}
	var raw json.RawMessage
	if err := c.do("POST", V+"/accounts", nil, body, &raw); err != nil {
		return err
	}
	if generated && !c.json {
		fmt.Printf("Password: %s\n", pass)
	}
	return c.afterJob(a, raw, "Account "+a.arg(0)+" created.")
}

func accountsSuspend(c *client, a args) error {
	id, _, err := c.account(a)
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.do("POST", V+"/accounts/"+esc(id)+"/suspend", nil, map[string]any{"reason": a.get("reason")}, &raw); err != nil {
		return err
	}
	return c.afterJob(a, raw, "Suspended.")
}

func accountsUnsuspend(c *client, a args) error {
	id, _, err := c.account(a)
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.do("POST", V+"/accounts/"+esc(id)+"/unsuspend", nil, map[string]any{}, &raw); err != nil {
		return err
	}
	return c.afterJob(a, raw, "Unsuspended.")
}

func accountsTerminate(c *client, a args) error {
	ref := a.arg(0)
	id, _, err := c.account(a)
	if err != nil {
		return err
	}
	if err := confirm(a, "Terminating "+ref); err != nil {
		return err
	}
	var acct account
	if err := c.get(V+"/accounts/"+esc(id), nil, &acct); err != nil {
		return err
	}
	q := url.Values{"confirm": {acct.Username}}
	if a.has("keep-home") {
		q.Set("keep_home", "1")
	}
	var raw json.RawMessage
	if err := c.do("DELETE", V+"/accounts/"+esc(id), q, nil, &raw); err != nil {
		return err
	}
	return c.afterJob(a, raw, "Account "+acct.Username+" terminated.")
}

func accountsPackage(c *client, a args) error {
	id, rest, err := c.account(a)
	if err != nil {
		return err
	}
	if len(rest) < 1 {
		return errors.New("usage: ky accounts package ACCOUNT PACKAGE")
	}
	pkg, err := c.packageID(rest[0])
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.do("PUT", V+"/accounts/"+esc(id)+"/package", nil, map[string]any{"package_id": pkg}, &raw); err != nil {
		return err
	}
	return c.afterJob(a, raw, "Package changed to "+rest[0]+".")
}

func accountsPassword(c *client, a args) error {
	id, _, err := c.account(a)
	if err != nil {
		return err
	}
	pass, generated := password(a)
	if err := c.do("POST", V+"/accounts/"+esc(id)+"/password", nil, map[string]any{"new_password": pass}, nil); err != nil {
		return err
	}
	if generated {
		fmt.Printf("Password: %s\n", pass)
	} else {
		fmt.Println("Password changed.")
	}
	return nil
}

func accountsSSO(c *client, a args) error {
	id, _, err := c.account(a)
	if err != nil {
		return err
	}
	body := map[string]any{"goto": a.get("goto")}
	if a.has("admin") {
		body["panel"] = "admin"
	}
	var out struct {
		URL string `json:"url"`
	}
	if err := c.do("POST", V+"/accounts/"+esc(id)+"/sso", nil, body, &out); err != nil {
		return err
	}
	fmt.Println(out.URL)
	return nil
}

func packagesList(c *client, a args) error {
	var raw json.RawMessage
	if err := c.get(V+"/packages", nil, &raw); err != nil {
		return err
	}
	var out struct {
		Items []struct {
			Name     string `json:"name"`
			Disk     int64  `json:"disk_quota_mb"`
			BW       int64  `json:"bw_limit_mb"`
			Addon    *int64 `json:"max_addon"`
			Email    *int64 `json:"max_email"`
			SQL      *int64 `json:"max_sql"`
			Accounts int    `json:"account_count"`
			Owner    string `json:"owner"`
		} `json:"items"`
	}
	lim := func(p *int64) string {
		if p == nil {
			return "unlimited"
		}
		return strconv.FormatInt(*p, 10)
	}
	return c.show(raw, &out, func() {
		t := newTable("NAME", "DISK", "BANDWIDTH", "ADDON DOMAINS", "MAILBOXES", "DATABASES", "ACCOUNTS")
		for _, p := range out.Items {
			t.row(p.Name, mb(p.Disk), mb(p.BW), lim(p.Addon), lim(p.Email), lim(p.SQL), p.Accounts)
		}
		t.print()
	})
}

func domainsList(c *client, a args) error {
	id, _, err := c.account(a)
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.get(V+"/accounts/"+esc(id)+"/domains", nil, &raw); err != nil {
		return err
	}
	var out struct {
		Items []domain `json:"items"`
	}
	return c.show(raw, &out, func() {
		t := newTable("DOMAIN", "TYPE", "DOCUMENT ROOT", "PHP", "SSL", "STATUS")
		for _, d := range out.Items {
			ssl := "none"
			if d.SSL != nil && d.SSL.HasCert {
				ssl = "until " + time.UnixMilli(d.SSL.NotAfter).Format("2006-01-02")
				if d.SSL.Problem != "" {
					ssl = d.SSL.Problem
				}
			}
			php := d.PHPVersion
			if php == "" {
				php = "default"
			}
			t.row(d.Name, d.Type, d.Docroot, php, ssl, d.Status)
		}
		t.print()
	})
}

func domainsAdd(c *client, a args) error {
	id, rest, err := c.account(a)
	if err != nil {
		return err
	}
	body := map[string]any{}
	switch {
	case a.get("sub") != "":
		if a.get("parent") == "" {
			return errors.New("a subdomain needs --parent DOMAIN")
		}
		pid, err := c.domainID(id, a.get("parent"))
		if err != nil {
			return err
		}
		body = map[string]any{"type": "sub", "label": a.get("sub"), "parent_id": pid}
	case len(rest) == 0:
		return errors.New("usage: ky domains add ACCOUNT DOMAIN [--alias] | --sub LABEL --parent DOMAIN")
	case a.has("alias"):
		body = map[string]any{"type": "alias", "name": rest[0]}
	default:
		body = map[string]any{"type": "addon", "name": rest[0]}
	}
	if d := a.get("docroot"); d != "" {
		body["docroot"] = d
	}
	var raw json.RawMessage
	if err := c.do("POST", V+"/accounts/"+esc(id)+"/domains", nil, body, &raw); err != nil {
		return err
	}
	return c.afterJob(a, raw, "Domain added.")
}

func domainsRemove(c *client, a args) error {
	id, rest, err := c.account(a)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return errors.New("usage: ky domains remove ACCOUNT DOMAIN --yes [--remove-files]")
	}
	did, err := c.domainID(id, rest[0])
	if err != nil {
		return err
	}
	if err := confirm(a, "Removing "+rest[0]); err != nil {
		return err
	}
	q := url.Values{"confirm": {strings.ToLower(rest[0])}}
	if a.has("remove-files") {
		q.Set("remove_files", "1")
	}
	var raw json.RawMessage
	if err := c.do("DELETE", V+"/accounts/"+esc(id)+"/domains/"+esc(did), q, nil, &raw); err != nil {
		return err
	}
	return c.afterJob(a, raw, "Domain removed.")
}

func emailList(c *client, a args) error {
	id, _, err := c.account(a)
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.get(V+"/accounts/"+esc(id)+"/email/accounts", nil, &raw); err != nil {
		return err
	}
	var out struct {
		Items []mailbox `json:"items"`
	}
	return c.show(raw, &out, func() {
		t := newTable("ADDRESS", "USED", "QUOTA", "LOGIN", "RECEIVE", "SEND")
		for _, m := range out.Items {
			q := "unlimited"
			if m.QuotaMB != nil {
				q = mb(*m.QuotaMB)
			}
			t.row(m.Address, fmt.Sprintf("%.1f MB", float64(m.UsedBytes)/1048576), q, m.Login, m.Receive, m.Send)
		}
		t.print()
	})
}

func emailCreate(c *client, a args) error {
	id, rest, err := c.account(a)
	if err != nil {
		return err
	}
	if len(rest) == 0 || !strings.Contains(rest[0], "@") {
		return errors.New("usage: ky email create ACCOUNT ADDRESS [--password PASS] [--quota MB]")
	}
	local, dom, _ := strings.Cut(rest[0], "@")
	did, err := c.domainID(id, dom)
	if err != nil {
		return err
	}
	pass, generated := password(a)
	body := map[string]any{"local_part": local, "domain_id": did, "password": pass}
	if q := a.get("quota"); q != "" {
		n, err := strconv.ParseInt(q, 10, 64)
		if err != nil {
			return fmt.Errorf("--quota: %v", err)
		}
		body["quota_mb"] = n
	}
	var raw json.RawMessage
	if err := c.do("POST", V+"/accounts/"+esc(id)+"/email/accounts", nil, body, &raw); err != nil {
		return err
	}
	if c.json {
		printJSON(raw)
		return nil
	}
	fmt.Printf("Mailbox %s created.\n", rest[0])
	if generated {
		fmt.Printf("Password: %s\n", pass)
	}
	return nil
}

func emailPassword(c *client, a args) error {
	id, rest, err := c.account(a)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return errors.New("usage: ky email password ACCOUNT ADDRESS [--password PASS]")
	}
	mid, err := c.mailboxID(id, rest[0])
	if err != nil {
		return err
	}
	pass, generated := password(a)
	if err := c.do("PUT", V+"/accounts/"+esc(id)+"/email/accounts/"+esc(mid)+"/password", nil, map[string]any{"password": pass}, nil); err != nil {
		return err
	}
	if generated {
		fmt.Printf("Password: %s\n", pass)
	} else {
		fmt.Println("Password changed.")
	}
	return nil
}

func emailDelete(c *client, a args) error {
	id, rest, err := c.account(a)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return errors.New("usage: ky email delete ACCOUNT ADDRESS --yes")
	}
	mid, err := c.mailboxID(id, rest[0])
	if err != nil {
		return err
	}
	if err := confirm(a, "Deleting "+rest[0]+" and its mail"); err != nil {
		return err
	}
	if err := c.do("DELETE", V+"/accounts/"+esc(id)+"/email/accounts/"+esc(mid), nil, nil, nil); err != nil {
		return err
	}
	fmt.Println("Mailbox deleted.")
	return nil
}

func dnsRecords(c *client, a args) error {
	id, rest, err := c.account(a)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return errors.New("usage: ky dns records ACCOUNT ZONE")
	}
	zid, err := c.zoneID(id, rest[0])
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.get(V+"/accounts/"+esc(id)+"/dns/zones/"+esc(zid)+"/records", nil, &raw); err != nil {
		return err
	}
	var out struct {
		Items []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Type     string `json:"type"`
			TTL      int    `json:"ttl"`
			Content  string `json:"content"`
			Priority *int   `json:"priority"`
			Disabled bool   `json:"disabled"`
		} `json:"items"`
	}
	return c.show(raw, &out, func() {
		t := newTable("ID", "NAME", "TTL", "TYPE", "CONTENT")
		for _, r := range out.Items {
			content := r.Content
			if r.Priority != nil {
				content = strconv.Itoa(*r.Priority) + " " + content
			}
			if r.Disabled {
				content += "  (disabled)"
			}
			t.row(r.ID, r.Name, r.TTL, r.Type, content)
		}
		t.print()
	})
}

func dnsAdd(c *client, a args) error {
	id, rest, err := c.account(a)
	if err != nil {
		return err
	}
	if len(rest) < 4 {
		return errors.New("usage: ky dns add ACCOUNT ZONE NAME TYPE CONTENT [--ttl SECONDS] [--priority N]")
	}
	zid, err := c.zoneID(id, rest[0])
	if err != nil {
		return err
	}
	body := map[string]any{"name": rest[1], "type": strings.ToUpper(rest[2]), "content": strings.Join(rest[3:], " ")}
	for _, k := range []string{"ttl", "priority"} {
		if v := a.get(k); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("--%s: %v", k, err)
			}
			body[k] = n
		}
	}
	var raw json.RawMessage
	if err := c.do("POST", V+"/accounts/"+esc(id)+"/dns/zones/"+esc(zid)+"/records", nil, body, &raw); err != nil {
		return err
	}
	if c.json {
		printJSON(raw)
		return nil
	}
	fmt.Println("Record added.")
	return nil
}

func dnsDelete(c *client, a args) error {
	id, rest, err := c.account(a)
	if err != nil {
		return err
	}
	if len(rest) < 2 {
		return errors.New("usage: ky dns delete ACCOUNT ZONE RECORD-ID")
	}
	zid, err := c.zoneID(id, rest[0])
	if err != nil {
		return err
	}
	if err := c.do("DELETE", V+"/accounts/"+esc(id)+"/dns/zones/"+esc(zid)+"/records/"+esc(rest[1]), nil, nil, nil); err != nil {
		return err
	}
	fmt.Println("Record deleted.")
	return nil
}

func databasesList(c *client, a args) error {
	id, _, err := c.account(a)
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.get(V+"/accounts/"+esc(id)+"/mysql", nil, &raw); err != nil {
		return err
	}
	var out struct {
		Databases []struct {
			Name      string `json:"name"`
			SizeBytes int64  `json:"size_bytes"`
		} `json:"databases"`
		Users []struct {
			Name string `json:"name"`
		} `json:"users"`
	}
	return c.show(raw, &out, func() {
		t := newTable("DATABASE", "SIZE")
		for _, d := range out.Databases {
			t.row(d.Name, fmt.Sprintf("%.1f MB", float64(d.SizeBytes)/1048576))
		}
		t.print()
		if len(out.Users) > 0 {
			names := make([]string, len(out.Users))
			for i, u := range out.Users {
				names[i] = u.Name
			}
			fmt.Println("\nUsers:", strings.Join(names, ", "))
		}
	})
}

func databasesCreate(c *client, a args) error {
	id, rest, err := c.account(a)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return errors.New("usage: ky databases create ACCOUNT NAME [--user NAME --password PASS]")
	}
	var raw json.RawMessage
	if u := a.get("user"); u != "" {
		pass, generated := password(a)
		if err := c.do("POST", V+"/accounts/"+esc(id)+"/mysql/wizard", nil, map[string]any{"database": rest[0], "user": u, "password": pass, "privileges": []string{"ALL"}}, &raw); err != nil {
			return err
		}
		if c.json {
			printJSON(raw)
			return nil
		}
		fmt.Println("Database and user created, with all privileges.")
		if generated {
			fmt.Printf("Password: %s\n", pass)
		}
		return nil
	}
	if err := c.do("POST", V+"/accounts/"+esc(id)+"/mysql/databases", nil, map[string]any{"name": rest[0]}, &raw); err != nil {
		return err
	}
	if c.json {
		printJSON(raw)
		return nil
	}
	fmt.Println("Database created.")
	return nil
}

// webhooksBase: server webhooks with an admin token, the account's with an account token.
func (c *client) webhooksBase() string {
	if c.prof.AccountID != "" {
		return V + "/accounts/" + esc(c.prof.AccountID)
	}
	return V
}

func webhooksList(c *client, a args) error {
	var raw json.RawMessage
	if err := c.get(c.webhooksBase()+"/webhooks", nil, &raw); err != nil {
		return err
	}
	var out struct {
		Items []struct {
			ID       string   `json:"id"`
			URL      string   `json:"url"`
			Events   []string `json:"events"`
			Enabled  bool     `json:"enabled"`
			Failures int      `json:"consecutive_failures"`
		} `json:"items"`
	}
	return c.show(raw, &out, func() {
		t := newTable("ID", "URL", "EVENTS", "ACTIVE", "FAILURES")
		for _, w := range out.Items {
			t.row(w.ID, w.URL, strings.Join(w.Events, ","), w.Enabled, w.Failures)
		}
		t.print()
	})
}

func webhooksAdd(c *client, a args) error {
	if err := need(a, 1, "ky webhooks add URL [--events a.b,c.*] [--description TEXT]"); err != nil {
		return err
	}
	body := map[string]any{"url": a.arg(0), "description": a.get("description")}
	if e := a.get("events"); e != "" {
		body["events"] = strings.Split(e, ",")
	}
	var out struct {
		Webhook struct {
			ID string `json:"id"`
		} `json:"webhook"`
		Secret string `json:"secret"`
	}
	if err := c.do("POST", c.webhooksBase()+"/webhooks", nil, body, &out); err != nil {
		return err
	}
	fmt.Printf("Webhook %s added.\nSigning secret (shown once): %s\n", out.Webhook.ID, out.Secret)
	return nil
}

func webhooksTest(c *client, a args) error {
	if err := need(a, 1, "ky webhooks test ID"); err != nil {
		return err
	}
	if err := c.do("POST", c.webhooksBase()+"/webhooks/"+esc(a.arg(0))+"/test", nil, map[string]any{}, nil); err != nil {
		return err
	}
	fmt.Println("Test event queued.")
	return nil
}

func webhooksDelete(c *client, a args) error {
	if err := need(a, 1, "ky webhooks delete ID"); err != nil {
		return err
	}
	if err := c.do("DELETE", c.webhooksBase()+"/webhooks/"+esc(a.arg(0)), nil, nil, nil); err != nil {
		return err
	}
	fmt.Println("Webhook deleted.")
	return nil
}

func cmdEvents(c *client, a args) error {
	after := a.get("after")
	if after == "" {
		after = "0"
	}
	path := c.webhooksBase() + "/events"
	for {
		q := url.Values{"after": {after}, "limit": {"500"}}
		if t := a.get("type"); t != "" {
			q.Set("type", t)
		}
		var out struct {
			Items []struct {
				Seq       int64           `json:"seq"`
				Type      string          `json:"type"`
				AccountID string          `json:"account_id"`
				Data      json.RawMessage `json:"data"`
				At        int64           `json:"created_at"`
			} `json:"items"`
			Next int64 `json:"next"`
		}
		if err := c.get(path, q, &out); err != nil {
			return err
		}
		for _, e := range out.Items {
			if c.json {
				b, _ := json.Marshal(e)
				fmt.Println(string(b))
				continue
			}
			var d struct {
				Account struct {
					Username string `json:"username"`
				} `json:"account"`
				ObjectID string `json:"object_id"`
			}
			_ = json.Unmarshal(e.Data, &d)
			fmt.Printf("%d  %s  %-26s %s\n", e.Seq, when(e.At), e.Type, d.Account.Username)
		}
		after = strconv.FormatInt(out.Next, 10)
		if !a.has("follow") {
			return nil
		}
		if len(out.Items) < 500 {
			time.Sleep(3 * time.Second)
		}
	}
}

func serverStatus(c *client, a args) error {
	var raw json.RawMessage
	if err := c.get(V+"/server/status", nil, &raw); err != nil {
		return err
	}
	var s struct {
		Hostname string  `json:"hostname"`
		OS       string  `json:"os_pretty_name"`
		Kernel   string  `json:"kernel"`
		CPUs     int     `json:"cpus"`
		Load1    float64 `json:"load1"`
		Load5    float64 `json:"load5"`
		Load15   float64 `json:"load15"`
		MemTotal int64   `json:"mem_total_bytes"`
		MemAvail int64   `json:"mem_available_bytes"`
		Uptime   int64   `json:"uptime_seconds"`
		SELinux  string  `json:"selinux"`
		Disks    []struct {
			Mount string `json:"mount"`
			Free  int64  `json:"free_bytes"`
			Total int64  `json:"total_bytes"`
		} `json:"disks"`
	}
	return c.show(raw, &s, func() {
		gb := func(b int64) string { return fmt.Sprintf("%.1f GB", float64(b)/(1<<30)) }
		fmt.Printf("%s — %s, kernel %s\n", s.Hostname, s.OS, s.Kernel)
		fmt.Printf("Load %.2f %.2f %.2f on %d CPUs · memory %s free of %s · up %s", s.Load1, s.Load5, s.Load15, s.CPUs, gb(s.MemAvail), gb(s.MemTotal), (time.Duration(s.Uptime) * time.Second).Round(time.Minute))
		if s.SELinux != "" {
			fmt.Printf(" · SELinux %s", s.SELinux)
		}
		fmt.Println()
		for _, d := range s.Disks {
			fmt.Printf("  %-12s %s used of %s\n", d.Mount, gb(d.Total-d.Free), gb(d.Total))
		}
	})
}

func serverUpdate(c *client, a args) error {
	type status struct {
		Available bool   `json:"available"`
		Current   string `json:"current_version"`
		Latest    *struct {
			Version string `json:"version"`
		} `json:"latest"`
		Applying string `json:"applying"`
	}
	var s status
	method, path := "GET", V+"/server/updates"
	if a.has("check") {
		method, path = "POST", V+"/server/updates/check"
	}
	var raw json.RawMessage
	if err := c.do(method, path, nil, nil, &raw); err != nil {
		return err
	}
	_ = json.Unmarshal(raw, &s)
	if a.has("check") || !s.Available {
		if c.json {
			printJSON(raw)
			return nil
		}
		if !s.Available {
			fmt.Printf("KyPanel %s is up to date.\n", s.Current)
			return nil
		}
		latest := ""
		if s.Latest != nil {
			latest = s.Latest.Version
		}
		fmt.Printf("KyPanel %s is available (installed: %s). Install it with: ky server update\n", latest, s.Current)
		return nil
	}
	var out struct {
		Message string `json:"message"`
		Version string `json:"version"`
	}
	if err := c.do("POST", V+"/server/updates/apply", nil, nil, &out); err != nil {
		return err
	}
	fmt.Printf("Installing KyPanel %s: %s\n", out.Version, out.Message)
	return nil
}
