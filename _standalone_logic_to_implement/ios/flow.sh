#!/bin/bash

source ./flow.conf
mkdir -p "${APP_DIR}"

# ============================================================================
# 1. Preparation
# ============================================================================

copy_app_from_iphone() {
    # Step 1.1: (Manual) Copy app from iPhone
    # scp -r "root@${IPHONE_IP}:/var/containers/Bundle/Application/XXXXX-XXXXX/" "./${APP_DIR}/"
    : # Manual step, placeholder
}

locate_and_extract_app_name() {
    # Step 1.2: Locate .app folder and extract app name
    cd "./${APP_DIR}/" || exit 1
    app_name=$(find . -type d -name "*.app" -print -quit)
    if [ -z "$app_name" ]; then
        echo "Error: No .app folder found."
        exit 1
    else
        echo "Found .app folder: $app_name"
        # Extract ONLY the name (no path, no .app extension)
        APP_NAME=$(basename "$app_name" .app)
        echo "Extracted app name: $APP_NAME"
        # Update flow.conf (backup original, then modify)
        sed -i.bak "s|^APP_NAME=.*|APP_NAME=\"${APP_NAME}\"|" "../flow.conf"
        echo "Updated flow.conf: APP_NAME is now \"$APP_NAME\""
    fi
}

repackage_into_ipa() {
    # Step 1.3: Repackage into IPA
    mkdir -p Payload
    mv "$app_name" Payload/
    zip -qr "${APP_NAME}.ipa" Payload/
    echo "Created IPA: ${APP_NAME}.ipa"
}

# ============================================================================
# 2. Info.plist Analysis
# ============================================================================

extract_url_schemes() {
    # Step 2.1: Extract URL schemes from Info.plist
    echo "[2.1] Extracting URL schemes from Info.plist..."
    xmlstarlet sel -t -v 'plist/dict/array/dict[key = "CFBundleURLSchemes"]/array/string' -nl Info.plist 2>/dev/null | sort -uf | tee ${BASE_DIR}/${EXTRACT_DIR}/url_schemes.txt
}

search_endpoints() {
    # Step 2.2: Search Info.plist for endpoints
    echo "[2.2] Searching Info.plist for endpoints..."
    grep -Eo 'https?://[^"]+' Info.plist 2>/dev/null | sort -uf | tee ${BASE_DIR}/${EXTRACT_DIR}/endpoints.txt
}

search_base64() {
    # Step 2.3: Search Info.plist for Base64 encoded data
    echo "[2.3] Searching Info.plist for Base64 encoded data..."
    grep -Po '(?:[a-zA-Z0-9+/]{4})*(?:[a-zA-Z0-9+/]{4}|[a-zA-Z0-9+/]{3}=|[a-zA-Z0-9+/]{2}==)' Info.plist | tee ${BASE_DIR}/${EXTRACT_DIR}/base64.txt
}

# ============================================================================
# 3. Binary Analysis
# ============================================================================

search_webview_usage() {
    # Step 3.1: Search binary for WebView usage
    echo "[3.1] Searching binary for WebView usage..."
    rabin2 -zzzqq $APP_DIR/$APP_NAME.app/$APP_NAME/ | grep -Pi 'hasOnlySecureContent|javaScriptEnabled|UIWebView|WKWebView' >rabin2_binary_output.txt
}

search_sensitive_keywords() {
    # Step 3.2: Search binary for sensitive keywords
    echo "[3.2] Searching binary for sensitive keywords..."
    rabin2 -zzzqq $APP_DIR/$APP_NAME.app/$APP_NAME/ | grep -Pi '(access|token|password|key|secret|url)' >${BASE_DIR}/${EXTRACT_DIR}/rabin2_binary_output_sensitive_data.txt
}

weak_hashes() {
    # Step 3.3: TODO: Search binary for weak hash algorithms and insecure functions
    # (Use MobSF for static analysis)
    # docker run -d --name mobsf -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
    :
}

# ============================================================================
# 4. Endpoint and Data Extraction
# ============================================================================

run_appinfoscanner() {
    # Step 4.1: Use AppInfoScanner to extract endpoints from binary or IPA
    echo "[4.1] Running AppInfoScanner..."
    python3 /home/rojo/hack/tools_external/AppInfoScanner/app.py ios -i ${APP_DIR}/Decrypted.ipa
}

# ============================================================================
# 5. File System Analysis
# ============================================================================

search_sensitive_files() {
    # Step 5.1: Search app directory for sensitive files
    local search_dir="$1"
    local wordlist="${BASE_DIR}/wordlists/sensitive_keywords.txt"
    local report_dir="reports"
    local report_file="${report_dir}/sensitive_files.log"
    mkdir -p "$report_dir"
    >"$report_file"
    if [ ! -f "$wordlist" ]; then
        echo "Wordlist file not found: $wordlist"
        return 1
    fi
    if [ ! -d "$search_dir" ]; then
        echo "Directory to search not found: $search_dir"
        return 1
    fi
    echo "Searching for sensitive files in $search_dir..."
    while IFS= read -r keyword || [ -n "$keyword" ]; do
        [[ -z "$keyword" || "$keyword" =~ ^# ]] && continue
        echo "Searching for *$keyword* ..."
        results=$(find "$search_dir" -iname "*$keyword*")
        if [ -n "$results" ]; then
            echo "$results"
            echo "=== Results for keyword: $keyword ===" >>"$report_file"
            echo "$results" >>"$report_file"
            echo >>"$report_file"
        fi
    done <"$wordlist"
    echo "Sensitive file search complete. Results logged in $report_file"
}

analyze_nsuserdefaults() {
    # Step 5.2: Analyze NSUserDefaults storage (Preferences/*.plist)
    scp root@${IPHONE_IP}:/var/mobile/Containers/Data/Application/${APP_UUID}/Library/Preferences/${APP_BUNDLE} ./
    plistutil -f xml -i ${APP_BUNDLE}.plist >${APP_BUNDLE}.plist.xml
}

cache_db() {
    # Step 5.3: TODO: Analyze Cache.db for sensitive data
    :
}

search_plists() {
    # Step 5.4: TODO: Search property lists for sensitive data
    :
}

verify_logout() {
    # Step 5.5: TODO: Verify cache and storage are cleared on logout
    :
}

# ============================================================================
# 6. Deeplink Testing
# ============================================================================
deeplink_testing() {
    # TODO: Extract deeplinks and URL schemes
    # TODO: Create HTML template for manual deeplink testing
    # TODO: Set up local HTTP server for deeplink testing
    # TODO: Fuzz deeplinks with Frida
    :
}

# ============================================================================
# 7. Dynamic Analysis with Frida
# ============================================================================
dynamic_frida() {
    # TODO: List running processes with Frida
    # TODO: Trace methods in app binary
    # TODO: Run Frida scripts for class/method hooks
    :
}

# ============================================================================
# 8. Objection Usage
# ============================================================================
objection_usage() {
    # TODO: Explore app with Objection
    # TODO: Dump keychain data
    # TODO: Dump NSUserDefaults data
    # TODO: Bypass jailbreak detection
    # TODO: Bypass SSL pinning
    :
}

# ============================================================================
# 9. System Monitoring
# ============================================================================
system_monitoring() {
    # TODO: Monitor system logs for app activity
    # TODO: Monitor file changes during app use
    :
}

# ============================================================================
# 10. Review and Reporting
# ============================================================================
review_reporting() {
    # TODO: Consolidate findings from all steps
    # TODO: Verify no sensitive data persists after logout
    :
}

main() {
    copy_app_from_iphone
    locate_and_extract_app_name
    repackage_into_ipa
    extract_url_schemes
    search_endpoints
    search_base64
    search_webview_usage
    search_sensitive_keywords
    weak_hashes
    run_appinfoscanner
    search_sensitive_files "${APP_DIR}"
    analyze_nsuserdefaults
    cache_db
    search_plists
    verify_logout
    deeplink_testing
    dynamic_frida
    objection_usage
    system_monitoring
    review_reporting
}

main
