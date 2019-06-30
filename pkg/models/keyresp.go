package models

// KeyMessage is the basic unit of the keytp server.  It is used in both PUT and GET requests for various keyids
type KeyMessage struct {
	// Serialized version of the XPubKey.  The *hash* of this XPub should correspond to the `key` in the kv store
	XPubKey []byte `json:xpub`

	// Signature is the signature of the metadata by XPubKey
	Signature []byte `json:sig`

	// Metadata is the value set by the user for the particular key
	Metadata []byte `json:sig`
}
