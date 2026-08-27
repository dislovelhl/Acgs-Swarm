package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/acgs/apcc-go-verifier/internal/apcc"
)

const protocolVersion = "APCC-1.0-draft"

type output struct {
	CertificateDigest string `json:"certificate_digest"`
	Code              string `json:"code"`
	Mode              string `json:"mode"`
	OK                bool   `json:"ok"`
	ProtocolVersion   string `json:"protocol_version"`
}

func Main(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		return emit(stdout, "", "", false, "CLI_ERROR", 2)
	}
	mode := arguments[0]
	if mode != "historical" && mode != "current" {
		return emit(stdout, mode, "", false, "CLI_ERROR", 2)
	}
	flags := flag.NewFlagSet(mode, flag.ContinueOnError)
	flags.SetOutput(stderr)
	certificatePath := flags.String("certificate", "", "canonical APCC detached certificate envelope")
	trustPath := flags.String("trust", "", "canonical scoped trust manifest")
	statusPath := flags.String("authority-status", "", "canonical nonce-bound AuthorityStatus")
	requestNonce := flags.String("request-nonce", "", "22-character request nonce")
	nowMS := flags.String("now-ms", "", "current Unix milliseconds as a decimal string")
	highestSequence := flags.String("highest-trust-log-sequence", "", "consumer high-water sequence")
	highestHead := flags.String("highest-trust-log-head", "", "consumer high-water head")
	maximumStaleness := flags.String("maximum-staleness-ms", "", "mandatory consumer staleness bound")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *certificatePath == "" || *trustPath == "" {
		return emit(stdout, mode, "", false, "CLI_ERROR", 2)
	}
	certificate, err := os.ReadFile(*certificatePath)
	if err != nil {
		return emit(stdout, mode, "", false, "CLI_ERROR", 2)
	}
	trustBytes, err := os.ReadFile(*trustPath)
	if err != nil {
		return emit(stdout, mode, "", false, "CLI_ERROR", 2)
	}
	trust, code := apcc.ParseTrust(trustBytes)
	if code != "" {
		return emit(stdout, mode, "", false, code, 1)
	}
	var result apcc.Result
	if mode == "historical" {
		result = apcc.VerifyHistorical(certificate, trust)
	} else {
		if *requestNonce == "" || *nowMS == "" || *highestSequence == "" || *highestHead == "" || *maximumStaleness == "" {
			return emit(stdout, mode, "", false, "CLI_ERROR", 2)
		}
		var status []byte
		if *statusPath != "" {
			var readErr error
			status, readErr = os.ReadFile(*statusPath)
			if readErr != nil {
				return emit(stdout, mode, "", false, "CLI_ERROR", 2)
			}
		}
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
		fmt.Fprintln(writer, `{"certificate_digest":"","code":"CLI_ERROR","mode":"","ok":false,"protocol_version":"APCC-1.0-draft"}`)
		return 2
	}
	fmt.Fprintln(writer, string(encoded))
	return exit
}
