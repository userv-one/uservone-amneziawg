package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/userv-one/uservone-amneziawg/v3/buildinfo"
	"github.com/userv-one/uservone-amneziawg/v3/profile"
)

func usage(writer io.Writer) {
	fmt.Fprintln(writer, "Usage: uservone-awg profile [--client] [--header-protection] balanced|low-bandwidth")
	fmt.Fprintln(writer, "       uservone-awg version")
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "%s %s\nupstream amneziawg-go %s\n", buildinfo.Product, buildinfo.Version, buildinfo.UpstreamCommit)
		return 0
	case "profile":
		flags := flag.NewFlagSet("profile", flag.ContinueOnError)
		flags.SetOutput(stderr)
		client := flags.Bool("client", false, "include client-side junk packets")
		headerProtection := flags.Bool("header-protection", false, "generate a fresh header protection key")
		flags.Usage = func() { usage(stderr) }
		if err := flags.Parse(args[1:]); err != nil {
			return 2
		}
		if flags.NArg() != 1 {
			usage(stderr)
			return 2
		}
		var config profile.Profile
		switch flags.Arg(0) {
		case "balanced":
			config = profile.Balanced()
		case "low-bandwidth":
			config = profile.LowBandwidth()
		default:
			fmt.Fprintf(stderr, "unknown profile %q\n", flags.Arg(0))
			return 2
		}
		if *headerProtection {
			key, err := profile.GenerateHeaderProtectionKey()
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			config.HeaderProtectionKey = key
		}
		output, err := config.UAPI(*client)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprint(stdout, output)
		return 0
	default:
		usage(stderr)
		return 2
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
