package poudriereakv

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// Result represents the result of an Azure Key Vault signing operation.
type Result struct {
	KeyID     string // The versioned URI of the key used for this operation.
	Signature []byte // The PKCS#1 signature of the provided digest.
}

// Sign signs the provided digest using this key.
func (k *KeyVaultKey) Sign(ctx context.Context, digest []byte) (Result, error) {
	res := Result{}
	parameters := azkeys.SignParameters{
		Algorithm: to.Ptr(azkeys.SignatureAlgorithmRS256),
		// Value:     []byte(b64Digest),
		Value: digest,
	}
	kvResult, err := k.client.Sign(ctx, k.name, k.version, parameters, nil)
	if err != nil {
		return res, err
	}
	res.KeyID = string(*kvResult.KID)
	res.Signature = kvResult.Result
	return res, nil
}
