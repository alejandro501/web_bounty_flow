package app

import (
	"net/url"
	"strings"
)

func mutateURLQuery(rawURL, key, value string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	q := parsed.Query()
	q.Set(key, value)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func paramFuzzReasons(base, mutated paramFuzzObservation) []string {
	var reasons []string
	if base.StatusCode != mutated.StatusCode {
		baseClass := statusCodeClass(base.StatusCode)
		mutatedClass := statusCodeClass(mutated.StatusCode)
		if baseClass != mutatedClass || base.StatusCode >= 500 || mutated.StatusCode >= 500 {
			reasons = append(reasons, "status_code_changed")
		}
	}
	lenDiff := mutated.Length - base.Length
	if lenDiff < 0 {
		lenDiff = -lenDiff
	}
	lenThreshold := 80
	if dynamic := int(float64(base.Length) * 0.35); dynamic > lenThreshold {
		lenThreshold = dynamic
	}
	if lenDiff > lenThreshold {
		reasons = append(reasons, "response_length_changed")
	}
	if base.Location != mutated.Location {
		if redirectTargetMeaningfullyChanged(base.Location, mutated.Location) {
			reasons = append(reasons, "redirect_target_changed")
		}
	}
	if mutated.DurationMS > (base.DurationMS*3 + 1500) {
		reasons = append(reasons, "timing_spike")
	}
	for _, kw := range paramFuzzSignalKeywords {
		if strings.Contains(mutated.Snippet, kw) && !strings.Contains(base.Snippet, kw) {
			reasons = append(reasons, "new_signal_keyword:"+kw)
		}
	}
	return unique(reasons)
}

func injectionReasons(base, mutated paramFuzzObservation, familyKeywords []string) []string {
	reasons := paramFuzzReasons(base, mutated)
	if base.StatusCode < 500 && mutated.StatusCode >= 500 {
		reasons = append(reasons, "server_error_on_payload")
	}
	for _, kw := range familyKeywords {
		kw = strings.ToLower(strings.TrimSpace(kw))
		if kw == "" {
			continue
		}
		if strings.Contains(mutated.Snippet, kw) && !strings.Contains(base.Snippet, kw) {
			reasons = append(reasons, "family_keyword:"+kw)
		}
	}
	reasons = unique(reasons)
	if len(reasons) == 0 {
		return nil
	}
	strong := hasReasonPrefix(reasons, "family_keyword:") ||
		hasReasonPrefix(reasons, "new_signal_keyword:") ||
		containsAny(reasons, "server_error_on_payload")
	if strong {
		return reasons
	}
	lenDiff := mutated.Length - base.Length
	if lenDiff < 0 {
		lenDiff = -lenDiff
	}
	if mutated.StatusCode >= 500 || lenDiff > 600 {
		return reasons
	}
	return nil
}

func hasReasonPrefix(reasons []string, prefix string) bool {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	if prefix == "" {
		return false
	}
	for _, reason := range reasons {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(reason)), prefix) {
			return true
		}
	}
	return false
}

func statusCodeClass(code int) int {
	if code >= 100 && code <= 599 {
		return code / 100
	}
	return 0
}

func redirectTargetMeaningfullyChanged(baseLoc, mutatedLoc string) bool {
	baseTrimmed := strings.TrimSpace(baseLoc)
	mutatedTrimmed := strings.TrimSpace(mutatedLoc)
	if baseTrimmed == mutatedTrimmed {
		return false
	}
	if baseTrimmed == "" || mutatedTrimmed == "" {
		return true
	}
	baseCore := normalizedRedirectCore(baseTrimmed)
	mutatedCore := normalizedRedirectCore(mutatedTrimmed)
	if baseCore == "" || mutatedCore == "" {
		return !strings.EqualFold(baseTrimmed, mutatedTrimmed)
	}
	return baseCore != mutatedCore
}

func normalizedRedirectCore(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	path := strings.TrimSpace(parsed.EscapedPath())
	if path == "" {
		path = "/"
	}
	return scheme + "|" + host + "|" + path
}
