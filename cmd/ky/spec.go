package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/KyPanel/cli/openapi"
)

// The generic commands read the OpenAPI description built into ky (the same one the server serves at
// /api/v1/openapi.json), so every API operation is reachable by its operationId.

type specParam struct {
	Name string `json:"name"`
	In   string `json:"in"`
}

type specOp struct {
	ID         string      `json:"operationId"`
	Summary    string      `json:"summary"`
	Parameters []specParam `json:"parameters"`
	Body       *struct {
		Content map[string]struct {
			Schema map[string]any `json:"schema"`
		} `json:"content"`
	} `json:"requestBody"`
	Access string `json:"x-kypanel-access"`
	Token  string `json:"x-kypanel-token"`

	method, path string
}

type spec struct {
	Paths      map[string]map[string]*specOp `json:"paths"`
	Components struct {
		Schemas map[string]map[string]any `json:"schemas"`
	} `json:"components"`
}

func loadSpec() (*spec, []*specOp, error) {
	var s spec
	if err := json.Unmarshal(openapi.JSON, &s); err != nil {
		return nil, nil, err
	}
	var ops []*specOp
	for p, ms := range s.Paths {
		for m, op := range ms {
			op.method, op.path = strings.ToUpper(m), p
			ops = append(ops, op)
		}
	}
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].path != ops[j].path {
			return ops[i].path < ops[j].path
		}
		return ops[i].method < ops[j].method
	})
	return &s, ops, nil
}

// bodyProps returns the request body's fields and their JSON types.
func (s *spec) bodyProps(op *specOp) map[string]string {
	if op.Body == nil {
		return nil
	}
	sc := op.Body.Content["application/json"].Schema
	if ref, ok := sc["$ref"].(string); ok {
		sc = s.Components.Schemas[strings.TrimPrefix(ref, "#/components/schemas/")]
	}
	out := map[string]string{}
	props, _ := sc["properties"].(map[string]any)
	for k, v := range props {
		t, _ := v.(map[string]any)["type"].(string)
		if t == "" {
			t = "object"
		}
		out[k] = t
	}
	return out
}

func cmdOps(argv []string) error {
	a := parseArgs(argv)
	_, ops, err := loadSpec()
	if err != nil {
		return err
	}
	filter := strings.ToLower(strings.Join(a.pos, " "))
	t := newTable("OPERATION", "METHOD", "PATH", "SUMMARY")
	n := 0
	for _, op := range ops {
		line := strings.ToLower(op.ID + " " + op.path + " " + op.Summary)
		if filter != "" && !strings.Contains(line, filter) {
			continue
		}
		t.row(op.ID, op.method, op.path, op.Summary)
		n++
	}
	t.print()
	if n == 0 {
		return fmt.Errorf("no operation matches %q", filter)
	}
	return nil
}

// cmdCall: ky call OPERATION [name=value…] [-d JSON]. Path parameters fill the URL, query parameters the query
// string, anything else a body field (typed by the schema: numbers, booleans, JSON arrays and objects).
// With an account token, {id} defaults to the token's account.
func cmdCall(c *client, a args) error {
	if len(a.pos) == 0 {
		return errors.New("usage: ky call OPERATION [name=value…] [-d JSON] (ky ops lists them)")
	}
	s, ops, err := loadSpec()
	if err != nil {
		return err
	}
	var op *specOp
	for _, o := range ops {
		if strings.EqualFold(o.ID, a.pos[0]) {
			op = o
			break
		}
	}
	if op == nil {
		return fmt.Errorf("no operation %q (ky ops %s)", a.pos[0], a.pos[0])
	}
	kinds := map[string]string{}
	for _, p := range op.Parameters {
		kinds[p.Name] = p.In
	}
	props := s.bodyProps(op)
	path := op.path
	query := url.Values{}
	body := map[string]any{}
	for _, kv := range a.pos[1:] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return fmt.Errorf("%q: arguments are name=value", kv)
		}
		switch kinds[k] {
		case "path":
			if k == "id" && strings.Contains(op.path, "/accounts/{id}") && !isID(v) && c.prof.AccountID == "" {
				id, _, err := c.account(args{pos: []string{v}})
				if err != nil {
					return err
				}
				v = id
			}
			path = strings.ReplaceAll(path, "{"+k+"}", url.PathEscape(v))
		case "query":
			query.Add(k, v)
		default:
			if props != nil {
				if _, known := props[k]; !known && a.get("d") == "" {
					names := make([]string, 0, len(props))
					for n := range props {
						names = append(names, n)
					}
					sort.Strings(names)
					return fmt.Errorf("%s has no field %q; fields: %s", op.ID, k, strings.Join(names, ", "))
				}
			}
			body[k] = typed(v, props[k])
		}
	}
	if c.prof.AccountID != "" {
		path = strings.ReplaceAll(path, "{id}", url.PathEscape(c.prof.AccountID))
	}
	if m := pathParamRE.FindStringSubmatch(path); m != nil {
		return fmt.Errorf("missing %s=… (path parameter)", m[1])
	}
	var payload any
	switch {
	case a.get("d") != "":
		if !json.Valid([]byte(a.get("d"))) {
			return errors.New("-d: not valid JSON")
		}
		payload = []byte(a.get("d"))
	case len(body) > 0 || (op.Body != nil):
		payload = body
	}
	var raw json.RawMessage
	if err := c.do(op.method, path, query, payload, &raw); err != nil {
		return err
	}
	if len(raw) > 0 {
		printJSON(raw)
	}
	return nil
}

var pathParamRE = regexp.MustCompile(`\{([a-z_]+)\.*\}`)

func typed(v, t string) any {
	switch t {
	case "integer":
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	case "number":
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	case "boolean":
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	case "array", "object":
		var x any
		if json.Unmarshal([]byte(v), &x) == nil {
			return x
		}
		if t == "array" {
			return strings.Split(v, ",")
		}
	}
	return v
}

// cmdAPI: ky api METHOD PATH [-d JSON]
func cmdAPI(c *client, a args) error {
	if len(a.pos) < 2 {
		return errors.New("usage: ky api METHOD PATH [-d JSON]")
	}
	method := strings.ToUpper(a.pos[0])
	u, err := url.Parse(a.pos[1])
	if err != nil {
		return err
	}
	path := u.Path
	if !strings.HasPrefix(path, "/api/") {
		path = V + "/" + strings.TrimPrefix(path, "/")
	}
	var payload any
	if d := a.get("d"); d != "" {
		if !json.Valid([]byte(d)) {
			return errors.New("-d: not valid JSON")
		}
		payload = []byte(d)
	} else if method != "GET" && method != "DELETE" && method != "HEAD" {
		payload = map[string]any{}
	}
	var raw json.RawMessage
	if err := c.do(method, path, u.Query(), payload, &raw); err != nil {
		return err
	}
	if len(raw) > 0 {
		printJSON(raw)
	}
	return nil
}
