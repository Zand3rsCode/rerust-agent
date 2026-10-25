package agent

import (
	"errors"
	"net/http"

	"github.com/Zand3rsCode/rerust-agent/internal/auth"
)

// pair completes a pairing started with `rerust-agent pair` on this machine: the panel sends the code's secret and
// the new machine key. The only call without a key; a wrong secret counts as a wrong key.
func (a *Agent) pair(w http.ResponseWriter, r *http.Request) {
	in, ok := parse(w, r)
	if !ok {
		return
	}
	if !a.Auth.Pending() {
		a.failed(clientIP(r))
		fail(w, 409, "not_pairing", "This machine is not waiting for a pairing - make a new code on it: sudo rerust-agent pair")
		return
	}
	err := a.Auth.Pair(in.str("secret"), in.str("key"))
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
