# iOS Application Testing Checklist

## Preparation
- [ ] Dump app with Frida

## 1. Info.plist Analysis
- [ ] Extract URL schemes from Info.plist
- [ ] Search Info.plist for endpoints
- [ ] Search Info.plist for Base64 encoded data

## 2. Binary Analysis
- [ ] Locate app binary in Payload/*.app/
- [ ] Search binary for WebView usage
- [ ] Search binary for sensitive keywords (endpoints, tokens, secrets)
- [ ] Search binary for weak hash algorithms and insecure functions

## 3. Endpoint and Data Extraction
- [ ] Use AppInfoScanner to extract endpoints from binary or IPA

## 4. File System Analysis
- [ ] Search app directory for sensitive files
- [ ] Analyze NSUserDefaults storage (Preferences/*.plist)
- [ ] Analyze Cache.db for sensitive data
- [ ] Search property lists for sensitive data
- [ ] Verify cache and storage are cleared on logout

## 5. Deeplink Testing
- [ ] Extract deeplinks and URL schemes
- [ ] Create HTML template for manual deeplink testing
- [ ] Set up local HTTP server for deeplink testing
- [ ] Fuzz deeplinks with Frida

## 6. Dynamic Analysis with Frida
- [ ] List running processes with Frida
- [ ] Trace methods in app binary
- [ ] Run Frida scripts for class/method hooks

## 7. Objection Usage
- [ ] Explore app with Objection
- [ ] Dump keychain data
- [ ] Dump NSUserDefaults data
- [ ] Bypass jailbreak detection
- [ ] Bypass SSL pinning

## 8. System Monitoring
- [ ] Monitor system logs for app activity
- [ ] Monitor file changes during app use

## 9. Review and Reporting
- [ ] Consolidate findings from all steps
- [ ] Verify no sensitive data persists after logout
