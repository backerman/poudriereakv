package poudriereakv_test

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/backerman/poudriereakv"
	. "github.com/smartystreets/goconvey/convey"
)

func TestSignature(t *testing.T) {
	Convey("Given a SHA-256 digest and a key", t, func() {
		keyURI := os.Getenv("TEST_KEY")
		key, err := poudriereakv.GetKey(keyURI)
		So(err, ShouldBeNil)
		Convey("A digest should be signable", func() {
			message := []byte("The magic words are squeamish ossifrage.")
			digest := sha256.Sum256(message)
			ctx := context.Background()
			result, err := key.Sign(ctx, digest[:])
			So(err, ShouldBeNil)
			So(result.KeyID, ShouldStartWith, keyURI)
			// A PKCS#1 signature is always exactly the length of
			// the modulus, which here is 2048 bits.
			So(result.Signature, ShouldHaveLength, 256)
			Convey("The signature should be verifiable", func() {
				block, rest := pem.Decode(key.PEMKey)
				So(rest, ShouldBeEmpty)
				So(block.Type, ShouldEqual, "RSA PUBLIC KEY")
				pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
				So(err, ShouldBeNil)
				err = rsa.VerifyPKCS1v15(
					pubKey, crypto.SHA256, digest[:], result.Signature)
				So(err, ShouldBeNil)
			})
		})
	})
}
