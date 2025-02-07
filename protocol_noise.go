package headscale

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
)

// // NoiseRegistrationHandler handles the actual registration process of a machine.
func (t *ts2021App) NoiseRegistrationHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	log.Trace().
		Caller().
		Msgf("Noise registration handler for client %s", req.RemoteAddr)
	if req.Method != http.MethodPost {
		http.Error(writer, "Wrong method", http.StatusMethodNotAllowed)

		return
	}
	body, _ := io.ReadAll(req.Body)
	registerRequest := tailcfg.RegisterRequest{}
	if err := json.Unmarshal(body, &registerRequest); err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot parse RegisterRequest")
		machineRegistrations.WithLabelValues("unknown", "web", "error", "unknown").Inc()
		http.Error(writer, "Internal error", http.StatusInternalServerError)

		return
	}

	t.headscale.handleRegisterCommon(writer, req, registerRequest, t.conn.Peer(), true)
}
