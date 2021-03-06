package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/backerman/poudriereakv"
)

const (
	numArguments       = 1
	wrongArgumentCount = 65 // arbitrary nonzero error code
	badArgument        = 66

	digestLength    = 32               // size of the digest to sign (raw)
	digestHexLength = digestLength * 2 // size as hex encoded

	readTimeout = 2 * time.Second // maximum wait time
)

var debug bool

func main() {
	debugFlag := flag.Bool("debug", false, "Turn on debug messages")
	flag.Parse()
	debug = *debugFlag
	positionalArgs := flag.Args()
	if len(positionalArgs) != numArguments {
		printHelp(os.Stderr)
		os.Exit(wrongArgumentCount)
	}
	keyURI := positionalArgs[0]
	digestHex, err := readWithTimeout(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Reading digest failed: %v", err)
		os.Exit(badArgument)
	}
	trimmedDigest := strings.TrimSpace(string(digestHex))
	// Also trim nulls, which can show up if timeout occurs and digest has been
	// fully read into the buffer.
	trimmedDigest = strings.Trim(trimmedDigest, "\x00")
	if debug {
		fmt.Fprintf(os.Stderr, "Got digest '%v'\n", trimmedDigest)
	}
	if len(trimmedDigest) != digestHexLength {
		fmt.Fprintf(os.Stderr, "[ERROR] Digest has invalid length %v (should be %v): %q",
			len(trimmedDigest), digestHexLength, trimmedDigest)
		os.Exit(badArgument)
	}
	// Oh, you thought it signs the digest of the meta file? Nope!
	// It signs the digest of the digest.
	digestOfDigest := sha256.Sum256([]byte(trimmedDigest))
	key, err := poudriereakv.GetKey(keyURI)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Unable to retrieve the signing key: %v", err)
		os.Exit(badArgument)
	}
	result, err := key.Sign(context.Background(), digestOfDigest[:])
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

func readWithTimeout(r io.Reader) ([]byte, error) {
	success := make(chan bool, 1)
	buf := make([]byte, digestHexLength+1)
	var n int
	var err error
	go func() {
		// Read from the input.
		n, err = r.Read(buf)
		success <- true
	}()
	// Wait until timeout or enough characters read.
	select {
	case <-success:
	case <-time.After(readTimeout):
	}
	if n < digestHexLength ||
		(err != nil && err != io.EOF) {
		return buf, errors.New("Unable to read digest")
	}
	return buf, nil
}
