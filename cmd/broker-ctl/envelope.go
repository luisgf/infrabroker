package main

// envelope.go implements `broker-ctl envelope pubkey`, the offline half of a
// sealed-exec envelope-key rotation.
//
// The signer logs the public key of the seed it is CURRENTLY using, which is
// enough to pin a host initially but not enough to rotate: a no-downtime
// rotation has to pin the INCOMING key on every host BEFORE the signer switches
// to it (docs/OPERATIONS.md § 2.2), and until that switch nothing has ever
// printed it. This derives it straight from the seed file, so the runbook's
// step 2 is executable.

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"

	"github.com/luisgf/infrabroker/internal/sealed"
)

func cmdEnvelope(args []string) {
	if len(args) == 0 {
		usageEnvelope()
		os.Exit(2)
	}
	switch args[0] {
	case "pubkey":
		cmdEnvelopePubkey(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown envelope subcommand: %q\n", args[0])
		usageEnvelope()
		os.Exit(1)
	}
}

func usageEnvelope() {
	fmt.Fprintln(os.Stderr, `Usage: broker-ctl envelope pubkey --seed <file>

Print the sealed-exec envelope PUBLIC key for a seed file, in the one-line
base64 form pinned at /etc/infrabroker/envelope.pub on a sealed host.

Offline: reads only the seed file, contacts nothing. Use it to learn the
INCOMING key during a rotation, before the signer is switched to it:

    umask 077 && head -c 32 /dev/urandom > envelope-new.seed
    broker-ctl envelope pubkey --seed envelope-new.seed
    # pin that value on every sealed host with:
    #   install-shim.sh --accounts <acct> --add-pubkey -`)
}

func cmdEnvelopePubkey(args []string) {
	fs := flag.NewFlagSet("envelope pubkey", flag.ExitOnError)
	seed := fs.String("seed", "", "path to the 32-byte Ed25519 envelope seed (signer.json envelope_key)")
	fs.Usage = usageEnvelope
	must(fs.Parse(args))
	if *seed == "" {
		usageEnvelope()
		os.Exit(2)
	}
	raw, err := os.ReadFile(*seed)
	if err != nil {
		fatalf("reading seed: %v", err)
	}
	key, err := sealed.KeyFromSeed(raw)
	if err != nil {
		fatalf("%v", err)
	}
	fmt.Println(sealed.PublicKeyString(key.Public().(ed25519.PublicKey)))
}
