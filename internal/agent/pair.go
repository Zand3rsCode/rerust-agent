package agent

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/Zand3rsCode/rerust-agent/internal/auth"
)

// pair completes a pairing started on this machine with `rerust-agent pair`: the panel sends the code's secret and
// the new machine key. The only call without a key: a small, typed body (no query string), and a wrong secret counts
// as a wrong key.
func (a *Agent) pair(w http.ResponseWriter, r *http.Request) {
	if !a.Auth.Pending() {
		fail(w, 409, "not_pairing", "This machine is not waiting for a pairing - make a new code on it: sudo -u rerust-agent /opt/rerust-agent/rerust-agent pair")
		return
	}
	var body struct {
		Secret string `json:"secret"`
		Key    string `json:"key"`
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4097))
	if err != nil || len(raw) > 4096 || json.Unmarshal(raw, &body) != nil {
		a.failed(clientIP(r))
		fail(w, 400, "bad_request", "Send {secret, key} as JSON.")
		return
	}
	err = a.Auth.Pair(body.Secret, body.Key)
	if errors.Is(err, auth.ErrPairing) {
		a.failed(clientIP(r))
		fail(w, 401, "bad_pairing", upperFirst(err.Error())+".")
		return
	}
	if err != nil {
		invalid(w, upperFirst(err.Error())+".")
		return
	}
	writeJSON(w, 200, map[string]any{"paired": true, "version": a.Version, "protocol": Protocol})
}
