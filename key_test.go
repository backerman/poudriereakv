package poudriereakv_test

import (
	"os"
	"testing"

	"github.com/backerman/poudriereakv"
	. "github.com/smartystreets/goconvey/convey"
)

func TestKeyCreation(t *testing.T) {
	Convey("Given an Azure Key Vault URI", t, func() {
		Convey("If it's valid", func() {
			uri := os.Getenv("TEST_KEY")
			Convey("The client is created", func() {
				key, err := poudriereakv.GetKey(uri)
				So(err, ShouldBeNil)
				pemKey := key.PEMKey
				Convey("The key has a reasonable extent", func() {
					So(len(pemKey), ShouldBeGreaterThan, 40)
				})
				Convey("The key looks like SubjectPublicKeyInfo", func() {
					pemString := string(pemKey)
					So(pemString, ShouldStartWith, "-----BEGIN PUBLIC KEY-----")
				})
			})
		})
		failingTests := []struct {
			description string
			uri         string
		}{
			{"If it's for something other than a key",
				"https://vaultName.vault.azure.net/secrets/keyName"},
			{"If it's for an invalid object version",
				"https://vaultName.vault.azure.net/keys/keyName/12345678901234567890"},
			{"If it's not for a valid vault object",
				"https://vaultName.vault.azure.net/"},
			{"If it's not for the correct URI scheme",
				"http://vaultName.vault.azure.net/keys/keyName"},
		}
		for _, test := range failingTests {
			Convey(test.description, func() {
				uri := test.uri
				Convey("The client is not created", func() {
					_, err := poudriereakv.GetKey(uri)
					So(err, ShouldNotBeNil)
				})
			})
		}
	})
}
