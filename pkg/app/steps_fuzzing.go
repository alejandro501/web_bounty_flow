package app

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func (a *App) runParamFuzz(ctx context.Context) error {
	baseDir := filepath.Dir(a.cfg.Lists.Domains)
	reconDir := filepath.Join(baseDir, "recon")
	rawDir := filepath.Join(reconDir, "raw", StepParamFuzz)
	paramsDir := filepath.Join(a.fuzzingBaseDir(), "params")
	if err := os.MkdirAll(rawDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(paramsDir, 0o755); err != nil {
		return err
	}

	modePaths := map[string]string{
		"query":  filepath.Join(paramsDir, "query_hits.jsonl"),
		"body":   filepath.Join(paramsDir, "body_hits.jsonl"),
		"header": filepath.Join(paramsDir, "header_hits.jsonl"),
		"cookie": filepath.Join(paramsDir, "cookie_hits.jsonl"),
	}
	modeWriters := make(map[string]*bufio.Writer, len(modePaths))
	modeFiles := make(map[string]*os.File, len(modePaths))
	for mode, path := range modePaths {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		modeFiles[mode] = f
		modeWriters[mode] = bufio.NewWriter(f)
	}
	defer func() {
		for _, w := range modeWriters {
			_ = w.Flush()
		}
		for _, f := range modeFiles {
			_ = f.Close()
		}
	}()

	clients := &http.Client{
		Timeout: paramFuzzRequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	allURLsPath := filepath.Join(reconDir, "all_urls.txt")
	endpoints := a.collectParamFuzzEndpoints(allURLsPath)
	if len(endpoints) == 0 {
		a.logger.Printf("%s: no eligible endpoints in %s", StepParamFuzz, allURLsPath)
		_ = os.WriteFile(filepath.Join(reconDir, "params_candidates.txt"), []byte{}, 0o644)
		return nil
	}
	if len(endpoints) > paramFuzzMaxEndpoints {
		a.logger.Printf("%s: limiting endpoints from %d to %d for safe runtime", StepParamFuzz, len(endpoints), paramFuzzMaxEndpoints)
		endpoints = endpoints[:paramFuzzMaxEndpoints]
	}

	endpointParams, globalParams := extractParamCandidates(endpoints)
	for _, key := range paramFuzzCommonParams {
		globalParams[key] = struct{}{}
	}
	a.discoverParamsWithArjun(ctx, endpoints, rawDir, endpointParams, globalParams)
	a.discoverParamsWithX8(ctx, endpoints, rawDir, endpointParams, globalParams)

	var globalList []string
	for key := range globalParams {
		globalList = append(globalList, key)
	}
	sort.Strings(globalList)
	if err := os.WriteFile(filepath.Join(reconDir, "params_candidates.txt"), []byte(strings.Join(globalList, "\n")), 0o644); err != nil {
		return err
	}

	metrics := map[string]struct {
		requests int
		hits     int
	}{
		"query":  {},
		"body":   {},
		"header": {},
		"cookie": {},
	}
	lastByHost := make(map[string]time.Time)

	for _, endpoint := range endpoints {
		params := sortedParamKeys(endpointParams[endpoint])
		if len(params) == 0 {
			params = globalList
		}
		if len(params) > paramFuzzMaxParamsPerEndpoint {
			params = params[:paramFuzzMaxParamsPerEndpoint]
		}

		baseGET, err := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodGet, nil, nil, "")
		if err != nil {
			a.logger.Printf("%s: baseline GET failed for %s: %v", StepParamFuzz, endpoint, err)
			continue
		}
		basePOSTForm, _ := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodPost, map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}, []byte(""), "")
		basePOSTJSON, _ := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodPost, map[string]string{
			"Content-Type": "application/json",
		}, []byte(`{}`), "")

		for _, key := range params {
			mutatedURL := mutateURLQuery(endpoint, key, "BFLOWFUZZ123")
			if mutatedURL != "" {
				obs, err := a.sendParamFuzzRequest(ctx, clients, lastByHost, mutatedURL, http.MethodGet, nil, nil, "")
				if err == nil {
					metrics["query"] = struct {
						requests int
						hits     int
					}{requests: metrics["query"].requests + 1, hits: metrics["query"].hits}
					if reasons := paramFuzzReasons(baseGET, obs); len(reasons) > 0 {
						metrics["query"] = struct {
							requests int
							hits     int
						}{requests: metrics["query"].requests, hits: metrics["query"].hits + 1}
						_ = writeJSONLine(modeWriters["query"], paramFuzzHit{
							Timestamp:    time.Now().UTC().Format(time.RFC3339),
							Mode:         "query",
							Endpoint:     endpoint,
							Method:       http.MethodGet,
							Param:        key,
							Vector:       "url-query",
							MutatedURL:   mutatedURL,
							Reasons:      reasons,
							BaselineCode: baseGET.StatusCode,
							MutatedCode:  obs.StatusCode,
							BaselineLen:  baseGET.Length,
							MutatedLen:   obs.Length,
							BaselineMS:   baseGET.DurationMS,
							MutatedMS:    obs.DurationMS,
							BaselineLoc:  baseGET.Location,
							MutatedLoc:   obs.Location,
						})
					}
				}
			}

			bodyForm := []byte(url.Values{key: []string{"BFLOWFUZZ123"}}.Encode())
			if basePOSTForm.StatusCode > 0 {
				obs, err := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodPost, map[string]string{
					"Content-Type": "application/x-www-form-urlencoded",
				}, bodyForm, "")
				if err == nil {
					metrics["body"] = struct {
						requests int
						hits     int
					}{requests: metrics["body"].requests + 1, hits: metrics["body"].hits}
					if reasons := paramFuzzReasons(basePOSTForm, obs); len(reasons) > 0 {
						metrics["body"] = struct {
							requests int
							hits     int
						}{requests: metrics["body"].requests, hits: metrics["body"].hits + 1}
						_ = writeJSONLine(modeWriters["body"], paramFuzzHit{
							Timestamp:    time.Now().UTC().Format(time.RFC3339),
							Mode:         "body",
							Endpoint:     endpoint,
							Method:       http.MethodPost,
							Param:        key,
							Vector:       "x-www-form-urlencoded",
							MutatedURL:   endpoint,
							Reasons:      reasons,
							BaselineCode: basePOSTForm.StatusCode,
							MutatedCode:  obs.StatusCode,
							BaselineLen:  basePOSTForm.Length,
							MutatedLen:   obs.Length,
							BaselineMS:   basePOSTForm.DurationMS,
							MutatedMS:    obs.DurationMS,
							BaselineLoc:  basePOSTForm.Location,
							MutatedLoc:   obs.Location,
						})
					}
				}
			}

			if basePOSTJSON.StatusCode > 0 {
				jsonBody, _ := json.Marshal(map[string]string{key: "BFLOWFUZZ123"})
				obs, err := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodPost, map[string]string{
					"Content-Type": "application/json",
				}, jsonBody, "")
				if err == nil {
					metrics["body"] = struct {
						requests int
						hits     int
					}{requests: metrics["body"].requests + 1, hits: metrics["body"].hits}
					if reasons := paramFuzzReasons(basePOSTJSON, obs); len(reasons) > 0 {
						metrics["body"] = struct {
							requests int
							hits     int
						}{requests: metrics["body"].requests, hits: metrics["body"].hits + 1}
						_ = writeJSONLine(modeWriters["body"], paramFuzzHit{
							Timestamp:    time.Now().UTC().Format(time.RFC3339),
							Mode:         "body",
							Endpoint:     endpoint,
							Method:       http.MethodPost,
							Param:        key,
							Vector:       "json",
							MutatedURL:   endpoint,
							Reasons:      reasons,
							BaselineCode: basePOSTJSON.StatusCode,
							MutatedCode:  obs.StatusCode,
							BaselineLen:  basePOSTJSON.Length,
							MutatedLen:   obs.Length,
							BaselineMS:   basePOSTJSON.DurationMS,
							MutatedMS:    obs.DurationMS,
							BaselineLoc:  basePOSTJSON.Location,
							MutatedLoc:   obs.Location,
						})
					}
				}
			}
		}

		for _, headerKey := range paramFuzzHeaderKeys {
			obs, err := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodGet, map[string]string{
				headerKey: "BFLOWFUZZ123",
			}, nil, "")
			if err != nil {
				continue
			}
			metrics["header"] = struct {
				requests int
				hits     int
			}{requests: metrics["header"].requests + 1, hits: metrics["header"].hits}
			if reasons := paramFuzzReasons(baseGET, obs); len(reasons) > 0 {
				metrics["header"] = struct {
					requests int
					hits     int
				}{requests: metrics["header"].requests, hits: metrics["header"].hits + 1}
				_ = writeJSONLine(modeWriters["header"], paramFuzzHit{
					Timestamp:    time.Now().UTC().Format(time.RFC3339),
					Mode:         "header",
					Endpoint:     endpoint,
					Method:       http.MethodGet,
					Param:        headerKey,
					Vector:       "request-header",
					MutatedURL:   endpoint,
					Reasons:      reasons,
					BaselineCode: baseGET.StatusCode,
					MutatedCode:  obs.StatusCode,
					BaselineLen:  baseGET.Length,
					MutatedLen:   obs.Length,
					BaselineMS:   baseGET.DurationMS,
					MutatedMS:    obs.DurationMS,
					BaselineLoc:  baseGET.Location,
					MutatedLoc:   obs.Location,
				})
			}
		}

		cookieNames := make(map[string]struct{})
		for _, c := range paramFuzzCommonCookies {
			cookieNames[c] = struct{}{}
		}
		for _, c := range baseGET.Cookies {
			cookieNames[c] = struct{}{}
		}
		var cookieList []string
		for c := range cookieNames {
			cookieList = append(cookieList, c)
		}
		sort.Strings(cookieList)
		if len(cookieList) > paramFuzzMaxParamsPerEndpoint {
			cookieList = cookieList[:paramFuzzMaxParamsPerEndpoint]
		}
		for _, cookieName := range cookieList {
			obs, err := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodGet, nil, nil, cookieName+"=BFLOWFUZZ123")
			if err != nil {
				continue
			}
			metrics["cookie"] = struct {
				requests int
				hits     int
			}{requests: metrics["cookie"].requests + 1, hits: metrics["cookie"].hits}
			if reasons := paramFuzzReasons(baseGET, obs); len(reasons) > 0 {
				metrics["cookie"] = struct {
					requests int
					hits     int
				}{requests: metrics["cookie"].requests, hits: metrics["cookie"].hits + 1}
				_ = writeJSONLine(modeWriters["cookie"], paramFuzzHit{
					Timestamp:    time.Now().UTC().Format(time.RFC3339),
					Mode:         "cookie",
					Endpoint:     endpoint,
					Method:       http.MethodGet,
					Param:        cookieName,
					Vector:       "cookie",
					MutatedURL:   endpoint,
					Reasons:      reasons,
					BaselineCode: baseGET.StatusCode,
					MutatedCode:  obs.StatusCode,
					BaselineLen:  baseGET.Length,
					MutatedLen:   obs.Length,
					BaselineMS:   baseGET.DurationMS,
					MutatedMS:    obs.DurationMS,
					BaselineLoc:  baseGET.Location,
					MutatedLoc:   obs.Location,
				})
			}
		}
	}

	for mode, data := range metrics {
		a.logger.Printf("%s: mode=%s requests=%d hits=%d", StepParamFuzz, mode, data.requests, data.hits)
	}
	return nil
}

func (a *App) runInjectionChecks(ctx context.Context) error {
	baseDir := filepath.Dir(a.cfg.Lists.Domains)
	reconDir := filepath.Join(baseDir, "recon")
	injectionDir := filepath.Join(a.fuzzingBaseDir(), "injection")
	if err := os.MkdirAll(injectionDir, 0o755); err != nil {
		return err
	}

	outputFiles := map[string]string{
		"sqli":   filepath.Join(injectionDir, "sqli_hits.jsonl"),
		"nosqli": filepath.Join(injectionDir, "nosqli_hits.jsonl"),
		"xpath":  filepath.Join(injectionDir, "xpath_hits.jsonl"),
		"ldap":   filepath.Join(injectionDir, "ldap_hits.jsonl"),
	}
	writers := make(map[string]*bufio.Writer, len(outputFiles))
	files := make(map[string]*os.File, len(outputFiles))
	for family, path := range outputFiles {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		files[family] = f
		writers[family] = bufio.NewWriter(f)
	}
	defer func() {
		for _, w := range writers {
			_ = w.Flush()
		}
		for _, f := range files {
			_ = f.Close()
		}
	}()

	endpoints := a.collectParamFuzzEndpoints(filepath.Join(reconDir, "all_urls.txt"))
	if len(endpoints) > injectionMaxEndpoints {
		a.logger.Printf("%s: limiting endpoints from %d to %d", StepInjectionCheck, len(endpoints), injectionMaxEndpoints)
		endpoints = endpoints[:injectionMaxEndpoints]
	}

	globalParams := a.loadParamCandidates(filepath.Join(reconDir, "params_candidates.txt"))
	if len(globalParams) == 0 {
		globalParams = append([]string{}, paramFuzzCommonParams...)
		sort.Strings(globalParams)
	}

	clients := &http.Client{
		Timeout: paramFuzzRequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	lastByHost := make(map[string]time.Time)
	metrics := map[string]struct {
		requests int
		hits     int
	}{
		"sqli":   {},
		"nosqli": {},
		"xpath":  {},
		"ldap":   {},
	}

	for _, endpoint := range endpoints {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			continue
		}
		paramSet := make(map[string]struct{})
		for key := range parsed.Query() {
			name := normalizeParamName(key)
			if name != "" {
				paramSet[name] = struct{}{}
			}
		}
		for _, p := range globalParams {
			paramSet[p] = struct{}{}
		}
		params := sortedParamKeys(paramSet)
		if len(params) > injectionMaxParamsPerEndpoint {
			params = params[:injectionMaxParamsPerEndpoint]
		}
		if len(params) == 0 {
			continue
		}

		baseGET, err := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodGet, nil, nil, "")
		if err != nil {
			a.logger.Printf("%s: baseline GET failed for %s: %v", StepInjectionCheck, endpoint, err)
			continue
		}
		basePOSTJSON, _ := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodPost, map[string]string{
			"Content-Type": "application/json",
		}, []byte(`{}`), "")

		for _, family := range injectionFamilies {
			for _, param := range params {
				for _, payload := range family.Payloads {
					mutatedURL := mutateURLQuery(endpoint, param, payload)
					if mutatedURL != "" {
						obs, reqErr := a.sendParamFuzzRequest(ctx, clients, lastByHost, mutatedURL, http.MethodGet, nil, nil, "")
						if reqErr == nil {
							metrics[family.Name] = struct {
								requests int
								hits     int
							}{requests: metrics[family.Name].requests + 1, hits: metrics[family.Name].hits}
							reasons := injectionReasons(baseGET, obs, family.Keywords)
							if len(reasons) > 0 {
								metrics[family.Name] = struct {
									requests int
									hits     int
								}{requests: metrics[family.Name].requests, hits: metrics[family.Name].hits + 1}
								_ = writeJSONLine(writers[family.Name], injectionHit{
									Timestamp:    time.Now().UTC().Format(time.RFC3339),
									Family:       family.Name,
									Endpoint:     endpoint,
									Method:       http.MethodGet,
									Param:        param,
									Payload:      payload,
									Vector:       "url-query",
									MutatedURL:   mutatedURL,
									Reasons:      reasons,
									BaselineCode: baseGET.StatusCode,
									MutatedCode:  obs.StatusCode,
									BaselineLen:  baseGET.Length,
									MutatedLen:   obs.Length,
									BaselineMS:   baseGET.DurationMS,
									MutatedMS:    obs.DurationMS,
									BaselineLoc:  baseGET.Location,
									MutatedLoc:   obs.Location,
								})
							}
						}
					}

					if family.Name == "nosqli" && basePOSTJSON.StatusCode > 0 {
						body, _ := json.Marshal(map[string]string{param: payload})
						obs, reqErr := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodPost, map[string]string{
							"Content-Type": "application/json",
						}, body, "")
						if reqErr == nil {
							metrics[family.Name] = struct {
								requests int
								hits     int
							}{requests: metrics[family.Name].requests + 1, hits: metrics[family.Name].hits}
							reasons := injectionReasons(basePOSTJSON, obs, family.Keywords)
							if len(reasons) > 0 {
								metrics[family.Name] = struct {
									requests int
									hits     int
								}{requests: metrics[family.Name].requests, hits: metrics[family.Name].hits + 1}
								_ = writeJSONLine(writers[family.Name], injectionHit{
									Timestamp:    time.Now().UTC().Format(time.RFC3339),
									Family:       family.Name,
									Endpoint:     endpoint,
									Method:       http.MethodPost,
									Param:        param,
									Payload:      payload,
									Vector:       "json-body",
									MutatedURL:   endpoint,
									Reasons:      reasons,
									BaselineCode: basePOSTJSON.StatusCode,
									MutatedCode:  obs.StatusCode,
									BaselineLen:  basePOSTJSON.Length,
									MutatedLen:   obs.Length,
									BaselineMS:   basePOSTJSON.DurationMS,
									MutatedMS:    obs.DurationMS,
									BaselineLoc:  basePOSTJSON.Location,
									MutatedLoc:   obs.Location,
								})
							}
						}
					}
				}
			}
		}
	}

	for family, row := range metrics {
		a.logger.Printf("%s: family=%s requests=%d hits=%d", StepInjectionCheck, family, row.requests, row.hits)
	}
	return nil
}

func (a *App) runServerInputChecks(ctx context.Context) error {
	baseDir := filepath.Dir(a.cfg.Lists.Domains)
	reconDir := filepath.Join(baseDir, "recon")
	outDir := filepath.Join(a.fuzzingBaseDir(), "server-input")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	outputFiles := map[string]string{
		"os_command":     filepath.Join(outDir, "os_command_hits.jsonl"),
		"path_traversal": filepath.Join(outDir, "path_traversal_hits.jsonl"),
		"file_inclusion": filepath.Join(outDir, "file_inclusion_hits.jsonl"),
	}
	writers := make(map[string]*bufio.Writer, len(outputFiles))
	files := make(map[string]*os.File, len(outputFiles))
	for family, path := range outputFiles {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		files[family] = f
		writers[family] = bufio.NewWriter(f)
	}
	defer func() {
		for _, w := range writers {
			_ = w.Flush()
		}
		for _, f := range files {
			_ = f.Close()
		}
	}()

	endpoints := a.collectParamFuzzEndpoints(filepath.Join(reconDir, "all_urls.txt"))
	if len(endpoints) > serverInputMaxEndpoints {
		a.logger.Printf("%s: limiting endpoints from %d to %d", StepServerInputChk, len(endpoints), serverInputMaxEndpoints)
		endpoints = endpoints[:serverInputMaxEndpoints]
	}

	globalParams := a.loadParamCandidates(filepath.Join(reconDir, "params_candidates.txt"))
	if len(globalParams) == 0 {
		globalParams = append([]string{}, paramFuzzCommonParams...)
		sort.Strings(globalParams)
	}

	clients := &http.Client{
		Timeout: paramFuzzRequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	lastByHost := make(map[string]time.Time)
	metrics := map[string]struct {
		requests int
		hits     int
	}{
		"os_command":     {},
		"path_traversal": {},
		"file_inclusion": {},
	}

	for _, endpoint := range endpoints {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			continue
		}
		paramSet := make(map[string]struct{})
		for key := range parsed.Query() {
			name := normalizeParamName(key)
			if name != "" {
				paramSet[name] = struct{}{}
			}
		}
		for _, p := range globalParams {
			paramSet[p] = struct{}{}
		}
		params := prioritizeServerInputParams(sortedParamKeys(paramSet))
		if len(params) > serverInputMaxParamsPerEP {
			params = params[:serverInputMaxParamsPerEP]
		}
		if len(params) == 0 {
			continue
		}

		baseGET, err := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodGet, nil, nil, "")
		if err != nil {
			a.logger.Printf("%s: baseline GET failed for %s: %v", StepServerInputChk, endpoint, err)
			continue
		}

		for _, family := range serverInputFamilies {
			for _, param := range params {
				for _, payload := range family.Payloads {
					mutatedURL := mutateURLQuery(endpoint, param, payload)
					if mutatedURL == "" {
						continue
					}
					obs, reqErr := a.sendParamFuzzRequest(ctx, clients, lastByHost, mutatedURL, http.MethodGet, nil, nil, "")
					if reqErr != nil {
						continue
					}
					metrics[family.Name] = struct {
						requests int
						hits     int
					}{requests: metrics[family.Name].requests + 1, hits: metrics[family.Name].hits}
					reasons := injectionReasons(baseGET, obs, family.Keywords)
					if len(reasons) == 0 {
						continue
					}
					metrics[family.Name] = struct {
						requests int
						hits     int
					}{requests: metrics[family.Name].requests, hits: metrics[family.Name].hits + 1}
					_ = writeJSONLine(writers[family.Name], injectionHit{
						Timestamp:    time.Now().UTC().Format(time.RFC3339),
						Family:       family.Name,
						Endpoint:     endpoint,
						Method:       http.MethodGet,
						Param:        param,
						Payload:      payload,
						Vector:       "url-query",
						MutatedURL:   mutatedURL,
						Reasons:      reasons,
						BaselineCode: baseGET.StatusCode,
						MutatedCode:  obs.StatusCode,
						BaselineLen:  baseGET.Length,
						MutatedLen:   obs.Length,
						BaselineMS:   baseGET.DurationMS,
						MutatedMS:    obs.DurationMS,
						BaselineLoc:  baseGET.Location,
						MutatedLoc:   obs.Location,
					})
				}
			}
		}
	}

	for family, row := range metrics {
		a.logger.Printf("%s: family=%s requests=%d hits=%d", StepServerInputChk, family, row.requests, row.hits)
	}
	return nil
}

func (a *App) runAdvancedInjectionChecks(ctx context.Context) error {
	baseDir := filepath.Dir(a.cfg.Lists.Domains)
	reconDir := filepath.Join(baseDir, "recon")
	outDir := filepath.Join(a.fuzzingBaseDir(), "adv-injection")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	outputFiles := map[string]string{
		"xxe":  filepath.Join(outDir, "xxe_hits.jsonl"),
		"soap": filepath.Join(outDir, "soap_hits.jsonl"),
		"ssrf": filepath.Join(outDir, "ssrf_hits.jsonl"),
		"smtp": filepath.Join(outDir, "smtp_hits.jsonl"),
	}
	writers := make(map[string]*bufio.Writer, len(outputFiles))
	files := make(map[string]*os.File, len(outputFiles))
	for family, path := range outputFiles {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		files[family] = f
		writers[family] = bufio.NewWriter(f)
	}
	defer func() {
		for _, w := range writers {
			_ = w.Flush()
		}
		for _, f := range files {
			_ = f.Close()
		}
	}()

	endpoints := a.collectParamFuzzEndpoints(filepath.Join(reconDir, "all_urls.txt"))
	if len(endpoints) > advInjectionMaxEndpoints {
		a.logger.Printf("%s: limiting endpoints from %d to %d", StepAdvInjection, len(endpoints), advInjectionMaxEndpoints)
		endpoints = endpoints[:advInjectionMaxEndpoints]
	}

	globalParams := a.loadParamCandidates(filepath.Join(reconDir, "params_candidates.txt"))
	if len(globalParams) == 0 {
		globalParams = append([]string{}, paramFuzzCommonParams...)
		sort.Strings(globalParams)
	}

	clients := &http.Client{
		Timeout: paramFuzzRequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	lastByHost := make(map[string]time.Time)
	metrics := map[string]struct {
		requests int
		hits     int
	}{
		"xxe":  {},
		"soap": {},
		"ssrf": {},
		"smtp": {},
	}

	for _, endpoint := range endpoints {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			continue
		}
		paramSet := make(map[string]struct{})
		for key := range parsed.Query() {
			name := normalizeParamName(key)
			if name != "" {
				paramSet[name] = struct{}{}
			}
		}
		for _, p := range globalParams {
			paramSet[p] = struct{}{}
		}
		params := prioritizeAdvancedInjectionParams(sortedParamKeys(paramSet))
		if len(params) > advInjectionMaxParamsPerEP {
			params = params[:advInjectionMaxParamsPerEP]
		}
		if len(params) == 0 {
			continue
		}

		baseGET, err := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodGet, nil, nil, "")
		if err != nil {
			a.logger.Printf("%s: baseline GET failed for %s: %v", StepAdvInjection, endpoint, err)
			continue
		}

		for _, family := range advInjectionFamilies {
			for _, param := range params {
				for _, payload := range family.Payloads {
					mutatedURL := mutateURLQuery(endpoint, param, payload)
					if mutatedURL == "" {
						continue
					}

					headers := map[string]string(nil)
					var body []byte
					method := http.MethodGet
					vector := "url-query"
					targetURL := mutatedURL

					if family.Name == "xxe" || family.Name == "soap" {
						method = http.MethodPost
						vector = "xml-body"
						targetURL = endpoint
						headers = map[string]string{"Content-Type": "application/xml"}
						body = []byte(payload)
						if family.Name == "soap" {
							headers["SOAPAction"] = "urn:bflow:probe"
						}
					}

					obs, reqErr := a.sendParamFuzzRequest(ctx, clients, lastByHost, targetURL, method, headers, body, "")
					if reqErr != nil {
						continue
					}
					metrics[family.Name] = struct {
						requests int
						hits     int
					}{requests: metrics[family.Name].requests + 1, hits: metrics[family.Name].hits}
					reasons := injectionReasons(baseGET, obs, family.Keywords)
					if len(reasons) == 0 {
						continue
					}
					metrics[family.Name] = struct {
						requests int
						hits     int
					}{requests: metrics[family.Name].requests, hits: metrics[family.Name].hits + 1}
					_ = writeJSONLine(writers[family.Name], injectionHit{
						Timestamp:    time.Now().UTC().Format(time.RFC3339),
						Family:       family.Name,
						Endpoint:     endpoint,
						Method:       method,
						Param:        param,
						Payload:      payload,
						Vector:       vector,
						MutatedURL:   targetURL,
						Reasons:      reasons,
						BaselineCode: baseGET.StatusCode,
						MutatedCode:  obs.StatusCode,
						BaselineLen:  baseGET.Length,
						MutatedLen:   obs.Length,
						BaselineMS:   baseGET.DurationMS,
						MutatedMS:    obs.DurationMS,
						BaselineLoc:  baseGET.Location,
						MutatedLoc:   obs.Location,
					})
				}
			}
		}
	}

	for family, row := range metrics {
		a.logger.Printf("%s: family=%s requests=%d hits=%d", StepAdvInjection, family, row.requests, row.hits)
	}
	return nil
}
