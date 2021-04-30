package poudriereAKV

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
	client keyvault.BaseClient
	PEMKey []byte
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

func GetKey(uri string) (*KeyVaultKey, error) {
	key := &KeyVaultKey{}
	var err error

	// Validate URI.
	parsedUri, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	if parsedUri.Scheme != "https" {
		return nil, errors.New("Key URI has non-https scheme")
	}
	splitPath := strings.Split(parsedUri.Path, "/")
	// First will always be nil, so a valid URI has either three or four
	// components.
	// Example valid URIs:
	//    https://vaultname.vault.azure.net/keys/keyName
	//    https://vaultname.vault.azure.net/keys/keyName/1371ade5d34f4d77bc193267adface2f
	pathLength := len(splitPath)
	if pathLength < 3 || pathLength > 4 {
		return nil, errors.New("Key URI has wrong number of segments")
	}
	if splitPath[1] != "keys" {
		return nil, errors.New("Key URI must be for keys")
	}
	if pathLength == 4 && len(splitPath[3]) != 32 {
		return nil, errors.New("A Key Vault object version must be exactly 32 characters long.")
	}

	key.client, err = getClient()
	if err != nil {
		return nil, err
	}

	// Get the actual key.
	ctx := context.Background()
	keyName := splitPath[2]
	parsedUri.Path = "/" // nope!
	bundle, err := key.client.GetKey(ctx, parsedUri.String(), keyName, "")
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
		return nil, errors.New("Key is not of type *rsa.PublicKey!")
	}

	pemBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(rsaKey),
	}

	key.PEMKey = pem.EncodeToMemory(pemBlock)

	return key, nil
}
