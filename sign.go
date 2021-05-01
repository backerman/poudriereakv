package poudriereakv

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
)

// Result represents the result of an Azure Key Vault signing operation.
type Result struct {
	KeyID     string // The versioned URI of the key used for this operation.
	Signature []byte // The PKCS#1 signature of the provided digest.
}

// Sign signs the provided digest using this key.
func (k *KeyVaultKey) Sign(ctx context.Context, digest []byte) (Result, error) {
	res := Result{}
	// Base64-encode digest.
	b64Builder := strings.Builder{}
	b64Encoder := base64.NewEncoder(base64.RawURLEncoding, &b64Builder)
	_, err := b64Encoder.Write(digest)
	if err != nil {
		return res, err
	}
	b64Encoder.Close()
	b64Digest := b64Builder.String()

	parameters := keyvault.KeySignParameters{
		Algorithm: keyvault.RS256,
		Value:     &b64Digest,
	}
	kvResult, err := k.client.Sign(ctx, k.baseURI, k.name, k.version, parameters)
	if err != nil {
		return res, err
	}
	res.KeyID = *kvResult.Kid

	// Base64-decode signature.
	b64SigReader := strings.NewReader(*kvResult.Result)
	sigBuffer := bytes.Buffer{}
	b64Decoder := base64.NewDecoder(base64.RawURLEncoding, b64SigReader)
	_, err = sigBuffer.ReadFrom(b64Decoder)
	if err != nil {
		return res, err
	}
	res.Signature = sigBuffer.Bytes()
	return res, nil
}
