package benchmark

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/MoriartyPuth/PwnProbes/internal/detect"
	"github.com/MoriartyPuth/PwnProbes/internal/runner"
)

type Case struct {
	Name             string            `json:"name"`
	Source           string            `json:"source"`
	Flags            []string          `json:"flags"`
	Protections      map[string]string `json:"protections"`
	FormatString     bool              `json:"format_string"`
	Crash            bool              `json:"crash"`
	Timeout          bool              `json:"timeout"`
	OriginalBaseline bool              `json:"original_baseline"`
}
type OriginalResult struct {
	SourceSHA256    string `json:"source_sha256,omitempty"`
	FormatString    bool   `json:"format_string"`
	MatchesExpected bool   `json:"matches_expected"`
	Outcome         string `json:"outcome"`
	DurationMS      int64  `json:"duration_ms"`
	Error           string `json:"error,omitempty"`
}
type Result struct {
	Name      string          `json:"name"`
	Passed    bool            `json:"passed"`
	Errors    []string        `json:"errors"`
	Detection *detect.Report  `json:"detection,omitempty"`
	Original  *OriginalResult `json:"original,omitempty"`
}
type Report struct {
	Cases          []Result `json:"cases"`
	Passed         int      `json:"passed"`
	Total          int      `json:"total"`
	OriginalSource string   `json:"original_source,omitempty"`
	Limitations    []string `json:"limitations"`
}

func Run(ctx context.Context, manifest, original, baselineScript string) (Report, error) {
	report := Report{Cases: []Result{}, OriginalSource: original, Limitations: []string{"small controlled fixture suite; not an exploitation-success benchmark", "original comparison covers format-string detection only", "fixtures are known to the implementation; a held-out evaluation suite is still needed"}}
	manifest, err := filepath.Abs(manifest)
	if err != nil {
		return report, err
	}
	data, err := os.ReadFile(manifest)
	if err != nil {
		return report, err
	}
	var cases []Case
	if err = json.Unmarshal(data, &cases); err != nil {
		return report, err
	}
	if len(cases) == 0 || len(cases) > 100 {
		return report, fmt.Errorf("manifest must contain 1 to 100 cases")
	}
	dir, err := os.MkdirTemp("", "pwnprobe-bench-")
	if err != nil {
		return report, err
	}
	defer os.RemoveAll(dir)
	if original != "" {
		original, err = filepath.Abs(original)
		if err != nil {
			return report, err
		}
		baselineScript, err = filepath.Abs(baselineScript)
		if err != nil {
			return report, err
		}
	}
	for i, c := range cases {
		if err = ctx.Err(); err != nil {
			return report, err
		}
		result := Result{Name: c.Name, Errors: []string{}}
		target := filepath.Join(dir, fmt.Sprintf("fixture-%d", i))
		source := filepath.Join(filepath.Dir(manifest), c.Source)
		args := append([]string{"-O0", "-o", target, source}, c.Flags...)
		build, buildErr := runner.Run(ctx, runner.Request{Program: "gcc", Args: args, Timeout: 30 * time.Second})
		if buildErr != nil || build.Outcome != "exited" || build.ExitCode != 0 {
			result.Errors = append(result.Errors, fmt.Sprintf("build failed: %v %s %s", buildErr, build.Outcome, build.Stderr))
			report.Cases = append(report.Cases, result)
			continue
		}
		probed, probeErr := detect.Probe(ctx, target, 300*time.Millisecond)
		if probeErr != nil {
			result.Errors = append(result.Errors, probeErr.Error())
		} else {
			result.Detection = &probed
			format, crash, timedOut := false, false, false
			for _, finding := range probed.Findings {
				if finding.Kind == "format_string" {
					format = true
				}
				if finding.Kind == "crash" {
					crash = true
				}
			}
			for _, attempt := range probed.Attempts {
				if attempt.Result.Outcome == "timeout" {
					timedOut = true
				}
			}
			if format != c.FormatString {
				result.Errors = append(result.Errors, fmt.Sprintf("format_string: got %v, want %v", format, c.FormatString))
			}
			if crash != c.Crash {
				result.Errors = append(result.Errors, fmt.Sprintf("crash: got %v, want %v", crash, c.Crash))
			}
			if timedOut != c.Timeout {
				result.Errors = append(result.Errors, fmt.Sprintf("timeout: got %v, want %v", timedOut, c.Timeout))
			}
			for key, want := range c.Protections {
				if got := probed.Binary.Protections[key].Status; got != want {
					result.Errors = append(result.Errors, fmt.Sprintf("%s: got %s, want %s", key, got, want))
				}
			}
		}
		if original != "" && c.OriginalBaseline {
			old, oldErr := runner.Run(ctx, runner.Request{Program: "python3", Args: []string{baselineScript, original, target}, Timeout: 15 * time.Second})
			baseline := OriginalResult{Outcome: old.Outcome, DurationMS: old.DurationMS}
			if oldErr != nil || old.Outcome != "exited" || old.ExitCode != 0 {
				baseline.Error = fmt.Sprintf("baseline failed: %v %s", oldErr, old.Stderr)
			} else {
				var value struct {
					FormatString bool   `json:"format_string"`
					SourceSHA256 string `json:"source_sha256"`
				}
				if decodeErr := json.Unmarshal([]byte(old.Stdout), &value); decodeErr != nil {
					baseline.Error = decodeErr.Error()
				} else {
					baseline.FormatString = value.FormatString
					baseline.SourceSHA256 = value.SourceSHA256
					baseline.MatchesExpected = value.FormatString == c.FormatString
				}
			}
			result.Original = &baseline
			if baseline.Error != "" {
				result.Errors = append(result.Errors, baseline.Error)
			}
		}
		result.Passed = len(result.Errors) == 0
		if result.Passed {
			report.Passed++
		}
		report.Cases = append(report.Cases, result)
	}
	report.Total = len(cases)
	return report, nil
}
