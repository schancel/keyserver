package keytp

import (
	"io/ioutil"
	"net/http"

	"github.com/cashweb/keyserver/pkg/models"
	"github.com/go-chi/chi"
	"github.com/golang/protobuf/proto"
	"github.com/rs/zerolog/hlog"
)

func (h HTTPKeyServer) setKey(w http.ResponseWriter,
	r *http.Request) {
	log := hlog.FromRequest(r)

	defer r.Body.Close()
	keyID := chi.URLParam(r, "keyID")
	if keyID == "" {
		log.Error().Msg("missing key id")
		http.Error(w, "missing keyID", http.StatusBadRequest)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Error().Msg("error reading the key metadata")
		http.Error(w, "internal server error",
			http.StatusInternalServerError)
		return
	}

	var keyMessage models.AddressMetadata
	err = proto.Unmarshal(body, &keyMessage)
	if err != nil {
		log.Error().Msgf("unable to unmarshal request to PROTO: %s", err)
		http.Error(w, "malformed request",
			http.StatusBadRequest)
		return
	}

	err = h.db.Set(keyID, &keyMessage)
	if err != nil {
		log.Error().Msgf("unable to set key in database: %s", err)
		http.Error(w, "internal server error",
			http.StatusInternalServerError)
		return
	}
}

func (h HTTPKeyServer) getKey(w http.ResponseWriter,
	r *http.Request) {
	log := hlog.FromRequest(r)

	defer r.Body.Close()
	keyID := chi.URLParam(r, "keyID")
	if keyID == "" {
		log.Error().Msg("missing key id")
		http.Error(w, "missing keyID", http.StatusBadRequest)
		return
	}

	model, err := h.db.Get(keyID)
	if err != nil {
		log.Error().Msgf("unable to find key: %s", err)
		http.Error(w, "key not found",
			http.StatusNotFound)
		return
	}

	resp, err := proto.Marshal(model)
	if err != nil {
		log.Error().Msgf("unable to marshal request to PROTO: %s", err)
		http.Error(w, "internal server error",
			http.StatusInternalServerError)
		return
	}

	w.Write(resp)
}
