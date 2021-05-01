package poudriereakv

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
)

type Result struct {
	KeyID     string
	Signature []byte
}

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
