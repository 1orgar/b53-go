// Command b53 provides a CLI for reversible 53-bit cryptographic packing of
// boolean arrays (1..50) into IEEE 754 float64 values in [0.0, 1.0).
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/1orgar/b53-go"
)

type boolFlagger interface {
	IsBoolFlag() bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}

func run(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) == 0 {
		printTopHelp(stderr)
		return 2
	}

	switch args[0] {
	case "-h", "--help", "help":
		printTopHelp(stdout)
		return 0
	case "-v", "--version", "version":
		fmt.Fprintf(stdout, "b53 %s\n", b53.Version)
		return 0
	case "generate-salt", "keygen":
		return runGenerateSalt(args[1:], stdout, stderr)
	case "derive-salt":
		return runDeriveSalt(args[1:], stdout, stderr)
	case "encrypt":
		return runEncrypt(args[1:], stdout, stderr, getenv)
	case "decrypt":
		return runDecrypt(args[1:], stdout, stderr, getenv)
	case "serialize":
		return runSerialize(args[1:], stdout, stderr, getenv)
	case "deserialize":
		return runDeserialize(args[1:], stdout, stderr, getenv)
	default:
		fmt.Fprintf(stderr, "Error: unknown command %q\n\n", args[0])
		printTopHelp(stderr)
		return 2
	}
}

func printTopHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: b53 <command> [options]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Reversible 53-bit cryptographic packing of bool arrays (1..50) into IEEE 754 double values in [0.0, 1.0).")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  generate-salt, keygen   Generate a cryptographically secure hex-encoded salt")
	fmt.Fprintln(w, "  derive-salt             Stretch a password into a hex salt using scrypt (RFC 7914)")
	fmt.Fprintln(w, "  encrypt                 Encrypt a boolean array into a double in [0.0, 1.0)")
	fmt.Fprintln(w, "  decrypt                 Decrypt a double back into the original boolean array")
	fmt.Fprintln(w, "  serialize               Serialize an arbitrary-length boolean array into chained doubles")
	fmt.Fprintln(w, "  deserialize             Deserialize chained doubles back into the full boolean array")
	fmt.Fprintln(w, "  version                 Print version information")
	fmt.Fprintln(w, "  help                    Show this help message")
}

func runGenerateSalt(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("generate-salt", flag.ContinueOnError)
	fs.SetOutput(stderr)

	numBytes := fs.Int("bytes", b53.DefaultSaltBytes, "Key length in bytes (default: 32 bytes = 256 bits)")
	outPath := fs.String("out", "", "Optional output file path to save the generated salt")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: b53 generate-salt [--bytes N] [--out PATH]")
		fs.PrintDefaults()
	}

	pos, err := parseInterleaved(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if len(pos) > 0 {
		fmt.Fprintf(stderr, "Error: unexpected positional arguments: %v\n", pos)
		return 2
	}

	salt, err := b53.GenerateSalt(*numBytes)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	if *outPath != "" {
		if err := os.WriteFile(*outPath, []byte(salt+"\n"), 0o600); err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Salt saved to %s: %s\n", *outPath, salt)
	} else {
		fmt.Fprintln(stdout, salt)
	}
	return 0
}

func runDeriveSalt(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("derive-salt", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		context  string
		numBytes int
		n        int
		r        int
		p        int
		maxMem   int
		outPath  string
	)
	fs.StringVar(&context, "context", "", "Optional domain-separation context")
	fs.IntVar(&numBytes, "bytes", b53.DefaultSaltBytes, "Derived key length in bytes (default: 32)")
	fs.IntVar(&n, "n", b53.DefaultScryptN, "scrypt cost factor N (power of 2 >= 2)")
	fs.IntVar(&r, "r", b53.DefaultScryptR, "scrypt block size r")
	fs.IntVar(&p, "p", b53.DefaultScryptP, "scrypt parallelization p")
	fs.IntVar(&maxMem, "maxmem", b53.DefaultScryptMaxMem, "scrypt memory cap in bytes")
	fs.StringVar(&outPath, "out", "", "Optional output file path to save the derived salt")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: b53 derive-salt <password> [--context CTX] [--bytes N] [--n N] [--r R] [--p P] [--maxmem BYTES] [--out PATH]")
		fs.PrintDefaults()
	}

	pos, err := parseInterleaved(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, "Error: derive-salt requires exactly one positional <password> argument")
		fs.Usage()
		return 2
	}

	var contextSet bool
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "context" {
			contextSet = true
		}
	})

	opts := []b53.DeriveOption{
		b53.WithNumBytes(numBytes),
		b53.WithScryptParams(n, r, p),
		b53.WithScryptMaxMem(maxMem),
	}
	if contextSet {
		opts = append(opts, b53.WithContext(context))
	}

	salt, err := b53.DeriveSalt(pos[0], opts...)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	if outPath != "" {
		if err := os.WriteFile(outPath, []byte(salt+"\n"), 0o600); err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Salt saved to %s: %s\n", outPath, salt)
	} else {
		fmt.Fprintln(stdout, salt)
	}
	return 0
}

type commonFlags struct {
	saltVal  string
	saltFile string
	quiet    bool
}

func registerCommonFlags(fs *flag.FlagSet, quietUsage string) *commonFlags {
	cf := &commonFlags{}
	fs.StringVar(&cf.saltVal, "salt", "", "Secret salt (hex or UTF-8 string)")
	fs.StringVar(&cf.saltFile, "salt-file", "", "Read salt from file")
	fs.BoolVar(&cf.quiet, "q", false, quietUsage)
	fs.BoolVar(&cf.quiet, "quiet", false, quietUsage)
	return cf
}

func printDecodedBits(stdout io.Writer, restored []bool, quiet bool) {
	bitString := b53.FormatBits(restored)
	if quiet {
		fmt.Fprintln(stdout, bitString)
		return
	}
	fmt.Fprintf(stdout, "Restored length: %d\n", len(restored))
	fmt.Fprintf(stdout, "Bit string:      %s\n", bitString)
	fmt.Fprintf(stdout, "Go slice:        %#v\n", restored)
}

func runEncrypt(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cf := registerCommonFlags(fs, "Print only the resulting double value(s)")
	var count int
	fs.IntVar(&count, "count", 1, "Number of independent random encryptions to generate")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: b53 encrypt <bits> [--salt SALT | --salt-file PATH] [--count N] [-q|--quiet]")
		fs.PrintDefaults()
	}

	pos, err := parseInterleaved(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, "Error: encrypt requires exactly one positional <bits> argument")
		fs.Usage()
		return 2
	}
	if count < 1 {
		fmt.Fprintln(stderr, "Error: --count must be at least 1")
		return 1
	}

	salt, err := resolveSalt(fs, cf.saltVal, cf.saltFile, getenv)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	bits, err := b53.ParseBits(pos[0])
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	cipher, err := b53.NewCipher(salt)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	if !cf.quiet {
		nonces, err := b53.NonceCount(len(bits))
		if err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Length: %d | Available random nonces: %d\n", len(bits), nonces)
	}

	for idx := 1; idx <= count; idx++ {
		encoded, err := cipher.Encrypt(bits)
		if err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
		formatted := strconv.FormatFloat(encoded, 'g', -1, 64)
		if count > 1 && !cf.quiet {
			fmt.Fprintf(stdout, "[%d] %s\n", idx, formatted)
		} else {
			fmt.Fprintln(stdout, formatted)
		}
	}
	return 0
}

func runDecrypt(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cf := registerCommonFlags(fs, "Print only the restored bit string")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: b53 decrypt <value> [--salt SALT | --salt-file PATH] [-q|--quiet]")
		fs.PrintDefaults()
	}

	pos, err := parseInterleaved(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, "Error: decrypt requires exactly one positional <value> argument")
		fs.Usage()
		return 2
	}

	salt, err := resolveSalt(fs, cf.saltVal, cf.saltFile, getenv)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	doubleVal, err := strconv.ParseFloat(strings.TrimSpace(pos[0]), 64)
	if err != nil {
		fmt.Fprintf(stderr, "Error: invalid float64 value %q: %v\n", pos[0], err)
		return 1
	}

	restored, err := b53.Decrypt(doubleVal, salt)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	printDecodedBits(stdout, restored, cf.quiet)
	return 0
}

func runSerialize(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet("serialize", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cf := registerCommonFlags(fs, "Print only the resulting double value(s)")
	var minSize int
	fs.IntVar(&minSize, "min-size", b53.DefaultChunkMin, "Chunk split threshold (2..50, default 10)")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: b53 serialize <bits> [--salt SALT | --salt-file PATH] [--min-size N] [-q|--quiet]")
		fs.PrintDefaults()
	}

	pos, err := parseInterleaved(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, "Error: serialize requires exactly one positional <bits> argument")
		fs.Usage()
		return 2
	}

	salt, err := resolveSalt(fs, cf.saltVal, cf.saltFile, getenv)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	var bits []bool
	if pos[0] != "" {
		bits, err = b53.ParseBits(pos[0])
		if err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
	}

	doubles, err := b53.Serialize(bits, salt, b53.WithMinSize(minSize))
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	if !cf.quiet {
		fmt.Fprintf(stdout, "Length: %d | Chunks: %d | min-size: %d\n", len(bits), len(doubles), minSize)
	}
	for idx, encoded := range doubles {
		formatted := strconv.FormatFloat(encoded, 'g', -1, 64)
		if !cf.quiet {
			fmt.Fprintf(stdout, "[%d] %s\n", idx+1, formatted)
		} else {
			fmt.Fprintln(stdout, formatted)
		}
	}
	return 0
}

func runDeserialize(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet("deserialize", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cf := registerCommonFlags(fs, "Print only the restored bit string")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: b53 deserialize <values...> [--salt SALT | --salt-file PATH] [-q|--quiet]")
		fs.PrintDefaults()
	}

	pos, err := parseInterleaved(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if len(pos) == 0 {
		fmt.Fprintln(stderr, "Error: deserialize requires at least one <value> argument")
		fs.Usage()
		return 2
	}

	salt, err := resolveSalt(fs, cf.saltVal, cf.saltFile, getenv)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	var doubles []float64
	if !(len(pos) == 1 && strings.TrimSpace(pos[0]) == "") {
		for _, arg := range pos {
			for _, part := range strings.Split(arg, ",") {
				tok := strings.TrimSpace(part)
				if tok == "" {
					fmt.Fprintf(stderr, "Error: empty float64 token in %q\n", arg)
					return 1
				}
				v, err := strconv.ParseFloat(tok, 64)
				if err != nil {
					fmt.Fprintf(stderr, "Error: invalid float64 value %q: %v\n", tok, err)
					return 1
				}
				doubles = append(doubles, v)
			}
		}
	}

	restored, err := b53.Deserialize(doubles, salt)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	printDecodedBits(stdout, restored, cf.quiet)
	return 0
}

func resolveSalt(fs *flag.FlagSet, saltVal, saltFile string, getenv func(string) string) (string, error) {
	var saltSet, saltFileSet bool
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "salt":
			saltSet = true
		case "salt-file":
			saltFileSet = true
		}
	})

	if saltSet && saltFileSet {
		return "", errors.New("specify either --salt or --salt-file, not both")
	}
	if saltSet {
		return saltVal, nil
	}
	if saltFileSet {
		data, err := os.ReadFile(saltFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}
	if envSalt := getenv("B53_SALT"); envSalt != "" {
		return envSalt, nil
	}
	return "", errors.New("a secret salt is required (--salt, --salt-file, or B53_SALT)")
}

// parseInterleaved allows flags to appear before or after positional arguments,
// matching standard CLI conventions while respecting "--" as end-of-flags.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	rest := args
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		remaining := fs.Args()
		if len(remaining) == 0 {
			break
		}
		consumed := len(rest) - len(remaining)
		if stoppedAtTerminator(fs, rest[:consumed]) {
			positionals = append(positionals, remaining...)
			break
		}
		positionals = append(positionals, remaining[0])
		rest = remaining[1:]
	}
	return positionals, nil
}

func stoppedAtTerminator(fs *flag.FlagSet, consumed []string) bool {
	for i := 0; i < len(consumed); i++ {
		arg := consumed[i]
		if arg == "--" {
			return true
		}
		if len(arg) < 2 || arg[0] != '-' {
			continue
		}
		name := strings.TrimPrefix(arg, "--")
		if name == arg {
			name = strings.TrimPrefix(arg, "-")
		}
		if strings.Contains(name, "=") {
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			continue
		}
		if bf, ok := f.Value.(boolFlagger); ok && bf.IsBoolFlag() {
			continue
		}
		i++ // Skip flag's value argument so a literal "--" value is not mistaken for terminator.
	}
	return false
}
