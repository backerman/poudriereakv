package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/backerman/poudriereakv"
)

const (
	numArguments       = 1
	wrongArgumentCount = 65 // arbitrary nonzero error code
	badArgument        = 66
)

func main() {
	if len(os.Args) != numArguments+1 {
		printHelp(os.Stderr)
		os.Exit(wrongArgumentCount)
	}
	keyURI := os.Args[1]
	digestHex, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Reading digest failed: %v", err)
		os.Exit(badArgument)
	}
	digest, err := hex.DecodeString(strings.TrimSpace(string(digestHex)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Invalid digest: %v", err)
		os.Exit(badArgument)
	}
	key, err := poudriereakv.GetKey(keyURI)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Unable to retrieve the signing key: %v", err)
		os.Exit(badArgument)
	}
	result, err := key.Sign(context.Background(), digest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Unable to sign digest: %v", err)
		os.Exit(badArgument)
	}
	fmt.Println("SIGNATURE")
	_, err = os.Stdout.Write(result.Signature)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Unexpected error: %v", err)
		os.Exit(badArgument)
	}
	fmt.Println()
	fmt.Println("CERT")
	fmt.Print(string(key.PEMKey))
	os.Exit(0)
}

func printHelp(w io.Writer) {
	fmt.Fprintf(w, "Usage: %s keyuri\n\n", os.Args[0])
	fmt.Fprintln(w, "    keyuri   The URI (versioned or unversioned) of the AKV key to use.")
	fmt.Fprintln(w, "\nExample invocation:")
	fmt.Fprintf(w, "    %s https://foo.vault.azure.net/keys/bar\n\n", os.Args[0])
	fmt.Fprintln(w, "The SHA256 digest to be signed should be passed on stdin in hex form.")
}
