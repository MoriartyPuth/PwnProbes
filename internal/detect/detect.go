package detect

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/MoriartyPuth/PwnProbes/internal/inspect"
	"github.com/MoriartyPuth/PwnProbes/internal/runner"
)

type Finding struct {
	Kind     string `json:"kind"`
	Status   string `json:"status"`
	Evidence string `json:"evidence"`
}
type Attempt struct {
	Name   string        `json:"name"`
	Input  string        `json:"input"`
	Result runner.Result `json:"result"`
}
type Report struct {
	Binary      inspect.Report `json:"binary"`
	Findings    []Finding      `json:"findings"`
	Attempts    []Attempt      `json:"attempts"`
	Limitations []string       `json:"limitations"`
}

// Probe confirms only input-dependent %p expansion. Crashes are observations,
// never proof of a buffer overflow or instruction-pointer control.
func Probe(ctx context.Context, path string, timeout time.Duration) (Report, error) {
	binary, err := inspect.Analyze(path)
	if err != nil {
		return Report{}, err
	}
	report := Report{Binary: binary, Findings: []Finding{}, Attempts: []Attempt{}, Limitations: []string{"single stdin interaction ending in EOF; menu-driven protocols are not supported", "no exploit execution or shell-success claims", "absence of a finding does not establish that the binary is safe"}}
	if !binary.ExecutionSupported {
		return report, fmt.Errorf("unsupported executable: %s %s", binary.Architecture, binary.Type)
	}
	if binary.Type == "ET_DYN" && binary.Protections["pie"].Status == "unknown" {
		return report, fmt.Errorf("ET_DYN file is not established to be an executable")
	}
	token := make([]byte, 8)
	if _, err = rand.Read(token); err != nil {
		return report, err
	}
	marker := "PP" + hex.EncodeToString(token)
	inputs := []struct{ name, input string }{
		{"baseline", marker + "BEGINplainEND" + marker + "\n"},
		{"format_pointer", marker + "BEGIN%p|%pEND" + marker + "\n"},
		{"long_input", strings.Repeat("A", 1024) + "\n"},
	}
	for _, probe := range inputs {
		if err = ctx.Err(); err != nil {
			return report, err
		}
		result, runErr := runner.Run(ctx, runner.Request{Program: path, Input: []byte(probe.input), Timeout: timeout})
		if runErr != nil {
			return report, runErr
		}
		report.Attempts = append(report.Attempts, Attempt{probe.name, probe.input, result})
		if result.Outcome == "crashed" {
			report.Findings = append(report.Findings, Finding{"crash", "observed", fmt.Sprintf("%s terminated with %s; cause and control are unconfirmed", probe.name, result.Signal)})
		}
	}
	baseline, formatted := report.Attempts[0].Result, report.Attempts[1].Result
	pattern := regexp.MustCompile(regexp.QuoteMeta(marker) + `BEGIN((?:0x[0-9a-fA-F]+|\(nil\))\|(?:0x[0-9a-fA-F]+|\(nil\)))END` + regexp.QuoteMeta(marker))
	if baseline.Outcome == "exited" && baseline.ExitCode == 0 && formatted.Outcome == "exited" && formatted.ExitCode == 0 && !baseline.OutputTruncated && !formatted.OutputTruncated && strings.Contains(baseline.Stdout, marker+"BEGINplainEND"+marker) && pattern.MatchString(formatted.Stdout) {
		report.Findings = append(report.Findings, Finding{"format_string", "confirmed_behavior", "unique input markers enclose two expanded %p fields; matching literal baseline was observed"})
	}
	return report, nil
}
