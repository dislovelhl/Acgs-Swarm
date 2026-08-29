package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/acgs/apcc-go-verifier/internal/apcc"
	"github.com/acgs/apcc-go-verifier/internal/cj1"
)

const protocolVersion = "APCC-1.0-draft"

type output struct {
	CertificateDigest string `json:"certificate_digest"`
	Code              string `json:"code"`
	Mode              string `json:"mode"`
	OK                bool   `json:"ok"`
	ProtocolVersion   string `json:"protocol_version"`
}

type predecessorFlags []string

func (values *predecessorFlags) String() string { return strings.Join(*values, ",") }
func (values *predecessorFlags) Set(value string) error {
	*values = append(*values, value)
	return nil
}

type fileResolver map[string][]byte

func (resolver fileResolver) ResolvePredecessor(digest string) ([]byte, bool, error) {
	value, ok := resolver[digest]
	return value, ok, nil
}

type predecessorSource struct {
	digest string
	path   string
}

func readFileAtMost(path string, maximum int) ([]byte, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = file.Close() }()
	reader := io.Reader(file)
	if uint64(maximum) < ^uint64(0)>>1 {
		reader = io.LimitReader(file, int64(maximum)+1)
	}
	value, err := io.ReadAll(reader)
	if err != nil {
		return nil, false, err
	}
	if len(value) > maximum {
		return nil, true, nil
	}
	return value, false, nil
}

func Main(arguments []string, stdout, _ io.Writer) int {
	if len(arguments) == 0 {
		return emit(stdout, "", "", false, "CLI_ERROR", 2)
	}
	mode := arguments[0]
	if mode != "historical" && mode != "causal" && mode != "current" {
		return emit(stdout, mode, "", false, "CLI_ERROR", 2)
	}
	flags := flag.NewFlagSet(mode, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	certificatePath := flags.String("certificate", "", "canonical APCC detached certificate envelope")
	trustPath := flags.String("trust", "", "canonical scoped trust manifest")
	statusPath := flags.String("authority-status", "", "canonical nonce-bound AuthorityStatus")
	requestNonce := flags.String("request-nonce", "", "22-character request nonce")
	nowMS := flags.String("now-ms", "", "current Unix milliseconds as a decimal string")
	highestSequence := flags.String("highest-trust-log-sequence", "", "consumer high-water sequence")
	highestHead := flags.String("highest-trust-log-head", "", "consumer high-water head")
	maximumStaleness := flags.String("maximum-staleness-ms", "", "mandatory consumer staleness bound")
	maxDepth := flags.Int("max-depth", 64, "maximum predecessor-edge depth")
	maxCertificates := flags.Int("max-certificates", 4096, "maximum distinct certificates including root")
	maxTotalBytes := flags.Int("max-total-bytes", 64*1024*1024, "maximum aggregate exact envelope bytes")
	var predecessorArguments predecessorFlags
	flags.Var(&predecessorArguments, "predecessor", "digest=path predecessor envelope (repeatable)")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *certificatePath == "" || *trustPath == "" {
		return emit(stdout, mode, "", false, "CLI_ERROR", 2)
	}
	allowed := map[string]bool{"certificate": true, "trust": true}
	if mode == "causal" {
		allowed["predecessor"] = true
		allowed["max-depth"] = true
		allowed["max-certificates"] = true
		allowed["max-total-bytes"] = true
	} else if mode == "current" {
		allowed["authority-status"] = true
		allowed["request-nonce"] = true
		allowed["now-ms"] = true
		allowed["highest-trust-log-sequence"] = true
		allowed["highest-trust-log-head"] = true
		allowed["maximum-staleness-ms"] = true
	}
	invalidModeFlag := false
	flags.Visit(func(item *flag.Flag) {
		if !allowed[item.Name] {
			invalidModeFlag = true
		}
	})
	if invalidModeFlag {
		return emit(stdout, mode, "", false, "CLI_ERROR", 2)
	}
	if mode == "current" && (*requestNonce == "" || *nowMS == "" || *highestSequence == "" || *highestHead == "" || *maximumStaleness == "") {
		return emit(stdout, mode, "", false, "CLI_ERROR", 2)
	}
	predecessorSources := make([]predecessorSource, 0, len(predecessorArguments))
	seenPredecessors := map[string]struct{}{}
	for _, argument := range predecessorArguments {
		digest, path, found := strings.Cut(argument, "=")
		if !found || digest == "" || path == "" {
			return emit(stdout, mode, "", false, "CLI_ERROR", 2)
		}
		if _, duplicate := seenPredecessors[digest]; duplicate {
			return emit(stdout, mode, "", false, "CLI_ERROR", 2)
		}
		seenPredecessors[digest] = struct{}{}
		predecessorSources = append(predecessorSources, predecessorSource{digest: digest, path: path})
	}
	certificate, tooLarge, err := readFileAtMost(*certificatePath, cj1.MaxEnvelopeBytes)
	if err != nil {
		return emit(stdout, mode, "", false, "CLI_ERROR", 2)
	}
	if tooLarge {
		return emit(stdout, mode, "", false, "SIZE_LIMIT_EXCEEDED", 1)
	}
	trustBytes, tooLarge, err := readFileAtMost(*trustPath, cj1.MaxPayloadBytes)
	if err != nil {
		return emit(stdout, mode, "", false, "CLI_ERROR", 2)
	}
	if tooLarge {
		return emit(stdout, mode, "", false, "SIZE_LIMIT_EXCEEDED", 1)
	}
	resolver := fileResolver{}
	if mode == "causal" {
		if *maxCertificates < 1 || *maxTotalBytes < 1 || len(predecessorSources) >= *maxCertificates || len(certificate) > *maxTotalBytes {
			return emit(stdout, mode, "", false, "SIZE_LIMIT_EXCEEDED", 1)
		}
		remaining := *maxTotalBytes - len(certificate)
		for _, source := range predecessorSources {
			value, tooLarge, readErr := readFileAtMost(source.path, remaining)
			if readErr != nil {
				return emit(stdout, mode, "", false, "CLI_ERROR", 2)
			}
			if tooLarge {
				return emit(stdout, mode, "", false, "SIZE_LIMIT_EXCEEDED", 1)
			}
			resolver[source.digest] = value
			remaining -= len(value)
		}
	}
	var status []byte
	if *statusPath != "" {
		status, tooLarge, err = readFileAtMost(*statusPath, cj1.MaxPayloadBytes)
		if err != nil {
			return emit(stdout, mode, "", false, "CLI_ERROR", 2)
		}
		if tooLarge {
			return emit(stdout, mode, "", false, "SIZE_LIMIT_EXCEEDED", 1)
		}
	}
	trust, code := apcc.ParseTrust(trustBytes)
	if code != "" {
		return emit(stdout, mode, "", false, code, 1)
	}
	var result apcc.Result
	if mode == "historical" {
		result = apcc.VerifyHistorical(certificate, trust)
	} else if mode == "causal" {
		result = apcc.VerifyCausalClosure(certificate, trust, resolver, apcc.CausalClosureLimits{MaxDepth: *maxDepth, MaxCertificates: *maxCertificates, MaxTotalBytes: *maxTotalBytes})
	} else {
		result = apcc.VerifyCurrent(certificate, trust, apcc.CurrentInputs{AuthorityStatus: status, RequestNonce: *requestNonce, NowMS: *nowMS, HighestTrustLogSequence: *highestSequence, HighestTrustLogHead: *highestHead, MaximumStalenessMS: *maximumStaleness})
	}
	if result.OK {
		return emit(stdout, mode, result.CertificateDigest, true, "OK", 0)
	}
	return emit(stdout, mode, "", false, result.Code, 1)
}

func emit(writer io.Writer, mode, certificateDigest string, ok bool, code string, exit int) int {
	encoded, err := json.Marshal(output{CertificateDigest: certificateDigest, Code: code, Mode: mode, OK: ok, ProtocolVersion: protocolVersion})
	if err != nil {
		_, _ = fmt.Fprintln(writer, `{"certificate_digest":"","code":"CLI_ERROR","mode":"","ok":false,"protocol_version":"APCC-1.0-draft"}`)
		return 2
	}
	if _, err := fmt.Fprintln(writer, string(encoded)); err != nil {
		return 2
	}
	return exit
}
