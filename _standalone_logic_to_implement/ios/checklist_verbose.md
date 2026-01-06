# iOS Application Testing Checklist

## Preparation

* [ ] [Dump app with Frida](#run-frida-scripts-for-classmethod-hooks)

## 1. Info.plist Analysis

* [ ] [Extract URL schemes from Info.plist](#extract-url-schemes-from-infoplist)
* [ ] [Search Info.plist for endpoints](#search-infoplist-for-endpoints)
* [ ] [Search Info.plist for Base64 encoded data](#search-infoplist-for-base64-encoded-data)

## 2. Binary Analysis

* [ ] [Locate app binary in Payload/\*.app/](#locate-app-binary-in-payloadapp)
* [ ] [Search binary for WebView usage](#search-binary-for-webview-usage)
* [ ] [Search binary for sensitive keywords (endpoints, tokens, secrets)](#search-binary-for-sensitive-keywords-endpoints-tokens-secrets)
* [ ] [Search binary for weak hash algorithms and insecure functions](#search-binary-for-weak-hash-algorithms-and-insecure-functions)

## 3. Endpoint and Data Extraction

* [ ] [Use AppInfoScanner to extract endpoints from binary or IPA](#use-appinfoscanner-to-extract-endpoints-from-binary-or-ipa)

## 4. File System Analysis

* [ ] [Search app directory for sensitive files](#search-app-directory-for-sensitive-files)
* [ ] [Analyze NSUserDefaults storage (Preferences/\*.plist)](#analyze-nsuserdefaults-storage-preferencesplist)
* [ ] [Analyze Cache.db for sensitive data](#analyze-cachedb-for-sensitive-data)
* [ ] [Search property lists for sensitive data](#search-property-lists-for-sensitive-data)
* [ ] [Verify cache and storage are cleared on logout](#verify-cache-and-storage-are-cleared-on-logout)

## 5. Deeplink Testing

* [ ] [Extract deeplinks and URL schemes](#extract-deeplinks-and-url-schemes)
* [ ] [Create HTML template for manual deeplink testing](#create-html-template-for-manual-deeplink-testing)
* [ ] [Set up local HTTP server for deeplink testing](#set-up-local-http-server-for-deeplink-testing)
* [ ] [Fuzz deeplinks with Frida](#fuzz-deeplinks-with-frida)

## 6. Dynamic Analysis with Frida

* [ ] [List running processes with Frida](#list-running-processes-with-frida)
* [ ] [Trace methods in app binary](#trace-methods-in-app-binary)
* [ ] [Run Frida scripts for class/method hooks](#run-frida-scripts-for-classmethod-hooks)

## 7. Objection Usage

* [ ] [Explore app with Objection](#explore-app-with-objection)
* [ ] [Dump keychain data](#dump-keychain-data)
* [ ] [Dump NSUserDefaults data](#dump-nsuserdefaults-data)
* [ ] [Bypass jailbreak detection](#bypass-jailbreak-detection)
* [ ] [Bypass SSL pinning](#bypass-ssl-pinning)

## 8. System Monitoring

* [ ] [Monitor system logs for app activity](#monitor-system-logs-for-app-activity)
* [ ] [Monitor file changes during app use](#monitor-file-changes-during-app-use)

## 9. Review and Reporting

* [ ] [Consolidate findings from all steps](#consolidate-findings-from-all-steps)
* [ ] [Verify no sensitive data persists after logout](#verify-no-sensitive-data-persists-after-logout)

---

Let me know if you'd like this exported to a `.md` file or integrated into a report template.


## Dump app with Frida
1. **run frida-server on iPhone (via ssh)**
```sh
ssh root@iphone
iPhone:~ root# frida-server &
```
2. **edit dump.py in frida-ios-dump dir**
```sh
cd frida-ios-dump
nano dump.py
User = 'root'
Password = 'alpine'
Host = '192.168.0.248' # iphone ip
Port = 22 # default ssh port
KeyFileName = None
```
3. **plug usb in**
4. **get the app bundle name**
```sh
frida-ps -Ua
```
5. **frida-ios-dump on pc**
```sh
python3 dump.py com.app.name
```

## Extract URL schemes from Info.plist
```sh
xmlstarlet sel -t -v 'plist/dict/array/dict[key = "CFBundleURLSchemes"]/array/string' -nl Info.plist | sort -uf
```

## Search Info.plist for endpoints
```sh
grep -Eo 'https?://[^"]+' Info.plist
```

## Search Info.plist for Base64 encoded data
```sh
grep -Po '(?:[a-zA-Z0-9+/]{4})*(?:[a-zA-Z0-9+/]{4}|[a-zA-Z0-9+/]{3}=|[a-zA-Z0-9+/]{2}==)' Info.plist
```

## Locate app binary in Payload/*.app/
```sh
cd Payload/*.app/
ls -l
```

## Search binary for WebView usage
```sh
rabin2 -zzzqq someapp | grep -Pi 'hasOnlySecureContent|javaScriptEnabled|UIWebView|WKWebView'
```

## Search binary for sensitive keywords (endpoints, tokens, secrets)
```sh
rabin2 -zzzqq someapp | grep -Pi '(access|token|password|key|secret|url)'
```

## Search binary for weak hash algorithms and insecure functions
- Use `MobSF` for static analysis:
  1. Start MobSF server:
     ```sh
     docker run -d --name mobsf -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
     ```
  2. Upload the binary via the MobSF web interface.

## Use AppInfoScanner to extract endpoints from binary or IPA
- Download and run AppInfoScanner:
  ```sh
  python3 app_info_scanner.py -i decrypted.ipa
  ```

## Search app directory for sensitive files
```sh
cd APPLICATION
find . -iname '*keyword*'
```

## Analyze NSUserDefaults storage (Preferences/*.plist)
```sh
scp root@[IPHONE_IP]:/path/to/preferences/com.someapp.dev.plist ./
plistutil -f xml -i com.someapp.dev.plist
```

## Analyze Cache.db for sensitive data
```sh
scp root@[IPHONE_IP]:/path/to/caches/Cache.db ./
sqlite3 Cache.db
```

## Search property lists for sensitive data
```sh
grep -i 'password\|token\|key\|secret' *.plist
```

## Verify cache and storage are cleared on logout
- Log out of the app and repeat the above checks to ensure sensitive data is removed.

## Extract deeplinks and URL schemes
- Use the URL schemes extracted from Info.plist.

## Create HTML template for manual deeplink testing
```sh
for scheme in $(cat url_schemes.txt); do
    echo "<a href='${scheme}://test'>${scheme}://test</a><br>" >> deeplinks.html
done
```

## Set up local HTTP server for deeplink testing
```sh
python3 -m http.server 9000
```

## Fuzz deeplinks with Frida
```sh
frida -U -no-pause --codeshare ivan-sincek/ios-deeplink-fuzzing -f com.someapp.dev
```

## List running processes with Frida
```sh
frida-ps -Uai
```

## Trace methods in app binary
```sh
frida-trace -U -n com.someapp.dev
```

## Run Frida scripts for class/method hooks
```sh
frida -U -no-pause --codeshare ivan-sincek/ios-hook-classes-methods -f com.someapp.dev
```

## Explore app with Objection
```sh
objection -g com.someapp.dev explore
```

## Dump keychain data
```sh
ios keychain dump
```

## Dump NSUserDefaults data
```sh
ios nsuserdefaults get
```

## Bypass jailbreak detection
```sh
ios jailbreak disable --quiet
```

## Bypass SSL pinning
```sh
ios sslpinning disable --quiet
```

## Monitor system logs for app activity
```sh
idevicesyslog -p [PID]
```

## Monitor file changes during app use
```sh
./filemon -c -f com.someapp.dev
```

## Consolidate findings from all steps
- Review all logs and outputs, summarize findings.

## Verify no sensitive data persists after logout
- Log out and repeat sensitive data checks to confirm data is cleared.

