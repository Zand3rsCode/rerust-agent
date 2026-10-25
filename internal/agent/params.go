package agent

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// maxJSON is the largest JSON body read (a file write can carry up to 8 MB as base64).
const maxJSON = 16 << 20

// input is a request's fields: the JSON body over the query string (the panel sends JSON bodies and query params,
// like Laravel's $request->input()).
type input map[string]any

func readInput(r *http.Request) (input, error) {
	in := input{}
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			in[k] = v[0]
		}
	}
	if r.Body == nil || r.ContentLength == 0 || !strings.Contains(r.Header.Get("Content-Type"), "json") {
		return in, nil
	}
	var raw any
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxJSON))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return in, fmt.Errorf("the request body is not valid JSON")
	}
	body, ok := raw.(map[string]any)
	if !ok {
		if list, isList := raw.([]any); isList && len(list) == 0 {
			return in, nil // PHP sends an empty field list as []
		}
		return in, fmt.Errorf("the request body must be a JSON object")
	}
	for k, v := range body {
		in[k] = v
	}
	return in, nil
}

func (in input) has(key string) bool { _, ok := in[key]; return ok }

// str is a string field ("" when missing or null; numbers as text).
func (in input) str(key string) string {
	switch v := in[key].(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case bool:
		if v {
			return "1"
		}
		return "0"
	}
	return ""
}

// isString tells a real string (or null) apart from arrays/objects.
func (in input) isString(key string) bool {
	switch in[key].(type) {
	case string, nil, json.Number:
		return true
	}
	return false
}

// boolean accepts what Laravel's "boolean" rule accepts: true/false, 1/0, "1"/"0", "true"/"false".
func (in input) boolean(key string) (bool, bool) {
	switch v := in[key].(type) {
	case bool:
		return v, true
	case json.Number:
		switch v.String() {
		case "1":
			return true, true
		case "0":
			return false, true
		}
	case string:
		switch strings.ToLower(v) {
		case "1", "true", "on", "yes":
			return true, true
		case "0", "false", "off", "no", "":
			return false, true
		}
	}
	return false, false
}

func (in input) truthy(key string) bool { b, _ := in.boolean(key); return b }

// integer is an integer field.
func (in input) integer(key string) (int64, bool) {
	switch v := in[key].(type) {
	case json.Number:
		n, err := v.Int64()
		return n, err == nil
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		return n, err == nil
	}
	return 0, false
}

// strings is a list of strings (nil when missing or not a list of strings).
func (in input) strings(key string) ([]string, bool) {
	list, ok := in[key].([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// ints is a list of integers.
func (in input) ints(key string) ([]int64, bool) {
	list, ok := in[key].([]any)
	if !ok {
		return nil, false
	}
	out := make([]int64, 0, len(list))
	for _, item := range list {
		var n int64
		var err error
		switch v := item.(type) {
		case json.Number:
			n, err = v.Int64()
		case string:
			n, err = strconv.ParseInt(v, 10, 64)
		default:
			return nil, false
		}
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// object is a nested object field.
func (in input) object(key string) input {
	if m, ok := in[key].(map[string]any); ok {
		return input(m)
	}
	return input{}
}

// parse reads the input or answers 400.
func parse(w http.ResponseWriter, r *http.Request) (input, bool) {
	in, err := readInput(r)
	if err != nil {
		fail(w, 400, "bad_request", err.Error())
		return nil, false
	}
	return in, true
}
