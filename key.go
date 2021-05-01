package poudriereakv

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/auth"
	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"gopkg.in/square/go-jose.v2"
)

type KeyVaultKey struct {
	client  keyvault.BaseClient
	baseURI string
	name    string
	version string
	PEMKey  []byte
}

func getClient() (keyvault.BaseClient, error) {
	keyClient := keyvault.New()
	a, err := auth.NewAuthorizerFromEnvironment()
	if err != nil {
		return keyClient, err
	}
	keyClient.Authorizer = a
	return keyClient, nil
}

const (
	unversionedKVURISegmentCount = 3
	versionedKVURISegmentCount   = 4
	maxKeyVaultURIVersionLength  = 32
)

func GetKey(uri string) (*KeyVaultKey, error) {
	key := &KeyVaultKey{}
	var err error

	// Validate URI.
	parsedURI, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	if parsedURI.Scheme != "https" {
		return nil, errors.New("key URI has non-https scheme")
	}
	splitPath := strings.Split(parsedURI.Path, "/")
	// First will always be nil, so a valid URI has either three or four
	// components.
	// Example valid URIs:
	//    https://vaultname.vault.azure.net/keys/keyName
	//    https://vaultname.vault.azure.net/keys/keyName/1371ade5d34f4d77bc193267adface2f
	pathLength := len(splitPath)
	if pathLength != unversionedKVURISegmentCount &&
		pathLength != versionedKVURISegmentCount {
		return nil, errors.New("key URI has wrong number of segments")
	}
	if splitPath[1] != "keys" {
		return nil, errors.New("key URI must be for keys")
	}
	if pathLength == versionedKVURISegmentCount {
		// A version identifier is present.
		key.version = splitPath[3]
		if len(key.version) != maxKeyVaultURIVersionLength {
			return nil, errors.New("a Key Vault object version must be exactly 32 characters long")
		}
	}

	key.client, err = getClient()
	if err != nil {
		return nil, err
	}

	// Get the actual key.
	ctx := context.Background()
	key.name = splitPath[2]
	parsedURI.Path = "/" // nope!
	key.baseURI = parsedURI.String()
	bundle, err := key.client.GetKey(ctx, key.baseURI, key.name, "")
	if err != nil {
		return nil, err
	}
	jsonStr, err := json.Marshal(bundle.Key)
	if err != nil {
		return nil, err
	}
	var joseKey jose.JSONWebKey
	err = json.Unmarshal(jsonStr, &joseKey)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := joseKey.Key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not of type *rsa.PublicKey")
	}

	pemBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(rsaKey),
	}
	key.PEMKey = pem.EncodeToMemory(pemBlock)

	return key, nil
}
