# Cross-Site Request Forgery (CSRF) Vulnerability in Go Web Application

# Vulnerability Case
During a routine code review of Acme Corp's Go-based web application, we discovered that several HTTP endpoints configured with the standard `net/http` package lack any implementation of CSRF protection, notably the Gorilla CSRF middleware. This vulnerability was identified by tracing inbound HTTP requests where no unique CSRF tokens were generated or verified, leaving endpoints susceptible to Cross-Site Request Forgery attacks. An attacker could leverage this misconfiguration to induce authenticated users to perform unauthorized actions by embedding crafted requests within malicious webpages. Subsequent testing demonstrated that cookie-based session management was in use, amplifying the risk. The finding highlights a **moderate-risk oversight** in enforcing CSRF defenses in the application's routing logic.

```go
package main

import (
        "fmt"
        "net/http"
)

func main() {
        // Vulnerable route without CSRF protection
        http.HandleFunc("/transaction", transactionHandler)
        fmt.Println("Server is running on port 8080...")
        http.ListenAndServe(":8080", nil)
}

func transactionHandler(w http.ResponseWriter, r *http.Request) {
        // Expected to validate a CSRF token here,
        // but missing verification exposes the endpoint.
        if r.Method == http.MethodPost {
                // Business logic for processing a sensitive transaction
                // is executed without proper CSRF token validation.
                w.WriteHeader(http.StatusOK)
                w.Write([]byte("Transaction processed"))
        } else {
                w.WriteHeader(http.StatusMethodNotAllowed)
                w.Write([]byte("Only POST method allowed"))
        }
}
```

The exposed vulnerability resides in a Go web application utilizing the standard `net/http` package for routing and session management via cookie-based authentication. Although the Gorilla CSRF library exists to mitigate such risks, its protective middleware was not applied in this instance.

The absence of CSRF token validation enables a potential attacker to craft malicious webpages that automatically submit HTTP POST requests to the vulnerable `/transaction` endpoint if an authenticated user visits the attacker-controlled site. Such exploitation could lead to unauthorized financial or state-changing operations, data manipulation, or other critical actions, depending on the business logic executed by the endpoint. The business impact can be significant, ranging from financial losses and compromised data integrity to erosion of user trust and potential regulatory implications.


context: go.net.csrf.gorilla-csrf.go-net-http-route-without-gorilla-csrf-protection.go-net-http-route-without-gorilla-csrf-protection The application does not appear to verify inbound requests which can lead to a Cross-site request forgery (CSRF) vulnerability. If the application uses cookie-based authentication, an attacker can trick users into sending authenticated HTTP requests without their knowledge from any arbitrary domain they visit. To prevent this vulnerability start by identifying if the framework or library leveraged has built-in features or offers plugins for CSRF protection. CSRF tokens should be unique and securely random. The `Synchronizer Token` or `Double Submit Cookie` patterns with defense-in-depth mechanisms such as the `sameSite` cookie flag can help prevent CSRF. For more information, see: [Cross-site request forgery prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

# Vulnerability Breakdown
This vulnerability involves a lack of CSRF protection in a Go web application using the standard `net/http` package.

1. **Key vulnerability elements**:
   - Missing CSRF token generation and validation at HTTP endpoints
   - Absence of Gorilla CSRF middleware or equivalent protection
   - Cookie-based session management making the application susceptible to CSRF
   - Exploitation possible via crafted HTTP requests from attacker-controlled sites
   - High-risk endpoints like `/transaction` exposed without protection

2. **Potential attack vectors**:
   - Malicious websites with hidden forms that automatically submit to vulnerable endpoints
   - Social engineering campaigns tricking users into visiting attacker-controlled pages
   - Email phishing with links to pages containing CSRF exploits
   - Forum posts or ads with embedded CSRF attack code

3. **Severity assessment**:
   - Network-based attack vector (remotely exploitable)
   - High complexity to execute (requires victim to visit attacker-controlled URL)
   - No privileges required on the target system
   - User interaction required (victim must visit malicious page)
   - Primarily impacts integrity through unauthorized state changes
   - Could enable unauthorized transactions or account modifications

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): High (H) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): Required (R) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): None (N) 
   - Integrity (I): High (H) 
   - Availability (A): None (N) 

CVSS Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N

# Description
A Cross-Site Request Forgery (CSRF) vulnerability exists in Acme Corp's Go-based web application due to the absence of CSRF protection mechanisms in HTTP endpoints implemented with the standard `net/http` package. The application relies on cookie-based session management but fails to implement CSRF token validation, notably missing the Gorilla CSRF middleware.

```go
func transactionHandler(w http.ResponseWriter, r *http.Request) {
	// Missing CSRF token validation
	if r.Method == http.MethodPost {
		// Processes sensitive transaction without verifying the request source
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Transaction processed"))
	}
}

```

This vulnerability allows attackers to craft malicious websites containing hidden forms or JavaScript code that automatically submit requests to vulnerable endpoints (e.g., `/transaction`). When authenticated users visit these sites, their browsers will include session cookies in the requests, making them appear legitimate to the server. The absence of CSRF token validation means the server cannot distinguish between genuine user-initiated requests and those triggered by attackers.

# CVSS
**Score**: 5.2 \
**Vector**: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N \
**Severity**: Medium

The Medium severity rating (5.2) is based on the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely from any network location.

- **High Attack Complexity (AC:H)**: Exploiting this vulnerability requires the attacker to create a malicious site and successfully lure the victim to visit the attacker-controlled URL. This social engineering aspect increases the complexity of a successful attack, as it's contingent on user behavior that can be unpredictable and difficult to influence.

- **No Privileges Required (PR:N)**: The attacker doesn't need any privileges on the target system to execute the attack.

- **User Interaction Required (UI:R)**: The attack requires the victim to visit a malicious website while having an active session with the vulnerable application. This requirement reduces the severity.

- **Unchanged Scope (S:U)**: The vulnerability impacts only the vulnerable application and doesn't allow the attacker to affect other components.

- **No Confidentiality Impact (C:N)**: The vulnerability itself doesn't directly expose sensitive information.

- **High Integrity Impact (I:H)**: The vulnerability allows unauthorized modification of data, potentially including financial transactions, account changes, or other sensitive operations.

- **No Availability Impact (A:N)**: The vulnerability doesn't directly impact the availability of the system.

The score is lower than it would be with Low complexity due to the challenges in successfully luring authenticated users to visit attacker-controlled sites.

# Exploitation Scenarios
**Scenario 1: Financial Transaction Hijacking**
An attacker creates a malicious website containing a hidden HTML form that automatically submits to the vulnerable `/transaction` endpoint when the page loads:

```html
<html>
  <body onload="document.getElementById('csrf-form').submit();">
    <form id="csrf-form" action="https://acme-app.com/transaction" method="POST">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="toAccount" value="attacker-account-number" />
    </form>
  </body>
</html>

```

When an authenticated user visits this page, their browser automatically sends a POST request to the `/transaction` endpoint including their session cookies. Since the application lacks CSRF protection, it processes the transaction as if it were legitimately initiated by the user, transferring funds to the attacker's account.

**Scenario 2: Account Takeover**
If the application has endpoints for changing user details, an attacker could craft a malicious site that submits requests to update email addresses and passwords:

```html
<body>
  <form id="email-form" action="https://acme-app.com/settings/update-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com" />
  </form>
  <form id="password-form" action="https://acme-app.com/settings/update-password" method="POST">
    <input type="hidden" name="new_password" value="attackerPassword123" />
  </form>
  <script>
    document.getElementById('email-form').submit();
    setTimeout(() => document.getElementById('password-form').submit(), 1000);
  </script>
</body>

```

This could give the attacker full control over the victim's account, potentially exposing sensitive information and enabling further malicious actions.

# Impact Analysis
**Business Impact:**
- Financial losses from unauthorized transactions initiated through CSRF attacks
- Loss of customer trust due to account compromises and unauthorized actions
- Potential regulatory compliance issues related to inadequate security controls
- Reputational damage if CSRF attacks lead to publicized security incidents
- Costs associated with incident response, investigation, and recovery
- Potential legal consequences if customer data or finances are compromised

**Technical Impact:**
- Unauthorized state-changing operations performed on behalf of authenticated users
- Potential data integrity issues from malicious modifications
- Account compromise if credential-changing endpoints are vulnerable
- Possible escalation to more severe attacks if administrative functions lack CSRF protection
- Chain of exploitation if CSRF can be used to upload malicious content or modify security settings
- Bypass of proper authorization flows and business logic validations

# Technical Details
The vulnerability stems from the Go web application's failure to implement CSRF protection for its HTTP endpoints. The application uses the standard `net/http` package for routing and handling requests, but doesn't implement token-based CSRF mitigation.

```go
package main
import (
	"fmt"
	"net/http"
)

func main() {
	// Route registration without CSRF protection middleware
	http.HandleFunc("/transaction", transactionHandler)
	http.ListenAndServe(":8080", nil)
}

func transactionHandler(w http.ResponseWriter, r *http.Request) {
	// No CSRF token validation before processing
	if r.Method == http.MethodPost {
		// Transaction is processed regardless of request origin
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Transaction processed"))
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

```

**CSRF Attack Mechanics:**

1. The application uses cookie-based authentication, which browsers automatically include in requests to the domain, regardless of which site initiates the request.

2. When a user authenticates with the application, their browser receives a session cookie which is stored and associated with the application's domain.

3. If the user then visits a malicious website while their session is active, that website can include HTML forms or JavaScript that submits requests to the vulnerable endpoints.

4. The browser includes the session cookie in these cross-origin requests due to the default browser behavior.

5. Since the application doesn't validate CSRF tokens (which would verify the request originated from a legitimate page), it processes the request as legitimate.

**Why Gorilla CSRF Middleware Would Help:**

The Gorilla CSRF middleware works by:

1. Generating a unique token for each user session
2. Including this token in forms rendered by the application
3. Requiring the same token to be included in subsequent requests
4. Validating that incoming requests contain the correct token

Malicious sites cannot access the CSRF token from the legitimate site due to the Same-Origin Policy, thus preventing them from including the correct token in forged requests.

# Remediation Steps
## Implement Gorilla CSRF Protection Middleware

**Priority**: P0

Integrate the Gorilla CSRF middleware into the application to generate and validate CSRF tokens:

```go
package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
)

func main() {
	// Create a new router with Gorilla Mux
	r := mux.NewRouter()
	
	// Register routes
	r.HandleFunc("/transaction", transactionHandler).Methods("POST")
	
	// Generate a strong random key (32 bytes)
	csrfKey := []byte("32-byte-long-auth-key")
	
	// Use CSRF protection middleware
	csrfMiddleware := csrf.Protect(
		csrfKey,
		csrf.Secure(true), // Set to false for HTTP during development
		csrf.Path("/"),
	)
	
	// Add a handler to serve forms with CSRF tokens
	r.HandleFunc("/form", formHandler)
	
	// Wrap the router with the CSRF middleware
	fmt.Println("Server is running on port 8080...")
	http.ListenAndServe(":8080", csrfMiddleware(r))
}

func formHandler(w http.ResponseWriter, r *http.Request) {
	// Include the CSRF token in the form
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<form method="POST" action="/transaction">
		<input type="hidden" name="%s" value="%s">
		<input type="submit" value="Submit">
	</form>`, csrf.FieldName, csrf.Token(r))
}

func transactionHandler(w http.ResponseWriter, r *http.Request) {
	// CSRF validation is handled by the middleware
	// Only requests with valid tokens will reach this handler
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Transaction processed"))
}

```

This implementation:
1. Uses Gorilla Mux router instead of the standard HTTP handler
2. Applies the Gorilla CSRF middleware to all routes
3. Generates and includes CSRF tokens in forms
4. Automatically validates tokens for all incoming requests
## Implement SameSite Cookie Attribute

**Priority**: P1

Add an additional layer of protection by setting the SameSite attribute on session cookies:

```go
func setSessionCookie(w http.ResponseWriter, sessionID string) {
	// Create a secure cookie with SameSite attribute
	cookie := http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,           // Require HTTPS
		SameSite: http.SameSiteStrictMode, // Prevent CSRF
	}
	http.SetCookie(w, &cookie)
}

```

The SameSite attribute with 'Strict' value prevents the browser from sending cookies in any cross-site requests. This provides defense-in-depth protection against CSRF attacks even if token validation is somehow bypassed. For APIs that need to be accessed from other sites, consider using SameSiteLaxMode instead, which allows cookies in top-level navigations.


# References
* CWE-352 | [Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)
* A01:2021 | [Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
* CSRF Prevention | [Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
* gorilla/csrf | [Gorilla CSRF - Cross Site Request Forgery prevention middleware for Go web applications](https://github.com/gorilla/csrf)
* RFC 6265 | [HTTP State Management Mechanism - SameSite Cookies](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-02#section-8.8)
