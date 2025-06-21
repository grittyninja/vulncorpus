# Open Redirect Vulnerability in Go Web Application

# Vulnerability Case
During our assessment of Acme Corp's Go-based web application using the standard `net/http` package, we discovered an open redirect vulnerability within an endpoint that dynamically crafts HTTP redirects based on unsanitized user input from the query parameter `request`. The vulnerability was identified during a source code review and corroborated with log analysis, which revealed that the user-supplied URL was directly used in the redirection mechanism without proper allowlisting or validation. This deficiency enables attackers to craft malicious URLs that, when followed by unsuspecting users, could lead to phishing or malware distribution. Given the business-critical nature of the web-facing API, exploitation could undermine the trust of Acme Corp’s user base and expose the organization to potential reputational and financial damage.

```go
package main

import (
	"net/http"
)

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	// Vulnerable: User-controlled input directly used to construct the redirect URL.
	redirectURL := r.URL.Query().Get("request")
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func main() {
	http.HandleFunc("/redirect", redirectHandler)
	http.ListenAndServe(":8080", nil)
}
```

The vulnerability stems from the direct use of the user-input parameter `request` to construct the HTTP redirection target, enabling attackers to inject arbitrary URLs into the response. An adversary could exploit this by sending a crafted URL that redirects users to a malicious site, thereby facilitating phishing, session hijacking, or drive-by download attacks. The utilization of Go’s native HTTP libraries without implementing domain allowlisting or input sanitization methods poses a significant risk in real-world deployments, particularly for organizations that handle sensitive user data or require high trust in web communications.


context: go.lang.security.injection.open-redirect.open-redirect An HTTP redirect was found to be crafted from user-input `$REQUEST`. This can lead to open redirect vulnerabilities, potentially allowing attackers to redirect users to malicious web sites. It is recommend where possible to not allow user-input to craft the redirect URL. When user-input is necessary to craft the request, it is recommended to follow OWASP best practices to restrict the URL to domains in an allowlist.

# Vulnerability Breakdown
This vulnerability involves an open redirect flaw in Acme Corp's Go-based web application that enables attackers to redirect users to arbitrary external domains.

1. **Key vulnerability elements**:
   - Direct use of the query parameter `request` to construct a redirect URL
   - No validation or sanitization of user input
   - No domain allowlisting for permitted redirect targets
   - Implementation in a public-facing web API using standard Go net/http package

2. **Potential attack vectors**:
   - Crafting malicious links pointing to the vulnerable endpoint with an external URL as the `request` parameter
   - Distributing these links through email, social media, or other channels
   - Social engineering users to click on seemingly legitimate URLs from a trusted domain
   - Pairing the redirect with additional attack techniques like session hijacking

3. **Severity assessment**:
   - The vulnerability primarily impacts integrity through misdirection
   - No direct confidentiality impact as it doesn't expose sensitive information
   - Requires user interaction (clicking the malicious link)
   - Network-accessible attack vector
   - High complexity due to specific attack requirements and victim interaction needed

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): High (H) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): Required (R) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): None (N) 
   - Integrity (I): Low (L) 
   - Availability (A): None (N) 

# Description
An open redirect vulnerability has been identified in Acme Corp's Go-based web application. The vulnerability exists in the `/redirect` endpoint, which constructs HTTP redirects based on unsanitized user input from the query parameter `request`. The application directly uses this parameter in the `http.Redirect()` function without any validation or allowlisting of permitted destinations.

```go
func redirectHandler(w http.ResponseWriter, r *http.Request) {
	// Vulnerable: User-controlled input directly used to construct the redirect URL.
	redirectURL := r.URL.Query().Get("request")
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

```

This vulnerability enables attackers to craft malicious URLs that, when followed by unsuspecting users, redirect them to arbitrary external websites. These redirects could facilitate phishing attacks (by redirecting to fake login pages), malware distribution, or other social engineering attacks. The issue is particularly concerning because users initially see the legitimate Acme Corp domain in their browser, which establishes trust before the redirection occurs.

# CVSS
**Score**: 3.0 \
**Vector**: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N \
**Severity**: Low

The Low severity rating (3.0) is based on the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability is remotely exploitable by anyone who can send HTTP requests to the web application.
- **High Attack Complexity (AC:H)**: While crafting the malicious URL is straightforward, successful exploitation requires several specific conditions to be met. The attacker must successfully distribute the malicious URL through social engineering channels, and the victim must explicitly click on the link. Additionally, the exploitation depends on the victim's trust in the initial domain and their failure to notice the subsequent redirection. These specific requirements increase the attack complexity.
- **No Privileges Required (PR:N)**: No authentication or authorization is needed to exploit the vulnerability.
- **User Interaction Required (UI:R)**: A user must click on the malicious link for the attack to succeed, and the effectiveness depends on the user not recognizing the redirection to a malicious site.
- **Unchanged Scope (S:U)**: The vulnerability affects only the user's session, not other components or services.
- **No Confidentiality Impact (C:N)**: The vulnerability itself doesn't directly disclose information.
- **Low Integrity Impact (I:L)**: The vulnerability can cause users to take unintended actions by visiting malicious sites, potentially leading to credential theft or malware installation.
- **No Availability Impact (A:N)**: The vulnerability doesn't affect system availability.

The severity is classified as Low rather than Medium due to the High attack complexity and the requirement for specific victim interaction. While open redirect vulnerabilities are often considered lower risk when isolated, they can still become dangerous when used as part of sophisticated social engineering attacks targeting Acme Corp's users.

# Exploitation Scenarios
**Scenario 1: Credential Harvesting Phishing Attack**
An attacker creates a URL like `https://acme-corp.com/redirect?request=https://fake-acme-login.com` and distributes it via email, social media, or messaging platforms. The link appears legitimate because it begins with the trusted acme-corp.com domain. When users click the link, they're redirected to a malicious site that mimics Acme Corp's login page. Users, believing they're on the legitimate site, enter their credentials, which are captured by the attacker.

**Scenario 2: Malware Distribution Campaign**
An attacker crafts a URL such as `https://acme-corp.com/redirect?request=https://malware-distribution.com/acme-document.exe` and sends it to Acme Corp's customers or partners claiming it contains important documentation. When users click the link, they're redirected to download malware disguised as a legitimate document or application. The initial trusted domain helps bypass user suspicion and security awareness training.

**Scenario 3: Corporate Phishing with Context**
An attacker conducts research on Acme Corp and crafts a targeted attack using the open redirect. They create a URL like `https://acme-corp.com/redirect?request=https://quarterly-report-review.com` and send it to employees claiming it contains quarterly financial data requiring review. The contextually relevant attack combined with the trusted initial domain significantly increases the likelihood of success, potentially leading to corporate credential theft or malware deployment within the organization.

# Impact Analysis
**Business Impact:**
- Erosion of user trust when they discover they were redirected from a legitimate Acme Corp URL to a malicious site
- Potential reputational damage if the vulnerability is exploited in widespread phishing campaigns
- Financial losses from remediation costs and potential legal liabilities if customer data is compromised
- Increased support burden from users reporting suspicious redirects or seeking assistance after falling victim to attacks
- Loss of business if customers perceive Acme Corp's web security as inadequate

**Technical Impact:**
- Facilitates phishing attacks against Acme Corp's user base by leveraging the company's domain reputation
- Enables social engineering attacks that bypass traditional security awareness training ("check the URL before entering credentials")
- Creates an attack vector that could be combined with other vulnerabilities for more sophisticated attacks
- Undermines the web's trust model, which relies heavily on domain verification
- May contribute to session hijacking or cross-site request forgery if chained with other vulnerabilities

# Technical Details
The vulnerability exists in the `redirectHandler` function of Acme Corp's Go-based web application. The issue stems from improper input handling where user-supplied data from the query parameter `request` is directly used in an HTTP redirect without validation.

```go
func redirectHandler(w http.ResponseWriter, r *http.Request) {
	// Vulnerable: User-controlled input directly used to construct the redirect URL.
	redirectURL := r.URL.Query().Get("request")
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func main() {
	http.HandleFunc("/redirect", redirectHandler)
	http.ListenAndServe(":8080", nil)
}

```

**Exploitation Mechanics:**

1. The attacker constructs a URL pointing to the vulnerable endpoint with a malicious redirection target:
   `https://acme-corp.com/redirect?request=https://malicious-site.com`

2. When a user clicks this link, their browser sends a request to Acme Corp's server.

3. The server extracts the value of the `request` parameter (`https://malicious-site.com`) and uses it directly in the `http.Redirect()` function.

4. The server responds with an HTTP 302 (Found) status code and a `Location` header containing the malicious URL.

5. The user's browser automatically follows the redirect to the malicious site.

The vulnerability is particularly effective because:

1. Users initially see the legitimate `acme-corp.com` domain in the URL, establishing trust.
2. Modern browsers typically hide the redirect process from users, making the transition to the malicious site seamless.
3. The server's HTTP response gives no indication to the user that they're being redirected to an untrusted site.
4. The original URL with the trusted domain may remain in browser history or bookmarks, enabling repeated exploitation.

The root cause is the absence of any validation logic such as:
- Checking if the URL is relative (starts with `/`)
- Validating against an allowlist of permitted domains
- Verifying URL structure and scheme

Go's standard library doesn't provide built-in protection against open redirects, making it the developer's responsibility to implement proper validation.

# Remediation Steps
## Implement Domain Allowlisting for Redirects

**Priority**: P0

Modify the redirect handler to validate URLs against an allowlist of trusted domains:

```go
package main

import (
	"net/http"
	"net/url"
	"strings"
)

// Define an allowlist of domains that are permitted for redirects
var trustedDomains = map[string]bool{
	"acme-corp.com":        true,
	"www.acme-corp.com":    true,
	"support.acme-corp.com": true,
	"docs.acme-corp.com":   true,
	// Add other trusted domains as needed
}

func isValidRedirectURL(redirectURL string) bool {
	// Accept relative URLs (starting with /)
	if strings.HasPrefix(redirectURL, "/") {
		return true
	}
	
	// Parse the URL
	parsedURL, err := url.Parse(redirectURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return false
	}
	
	// Only allow HTTP/HTTPS schemes
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return false
	}
	
	// Check if the host or any parent domain is in our allowlist
	host := parsedURL.Host
	
	// Remove port number if present
	if colonIndex := strings.IndexByte(host, ':'); colonIndex != -1 {
		host = host[:colonIndex]
	}
	
	// Check exact domain match
	if trustedDomains[host] {
		return true
	}
	
	// Check for subdomains of trusted domains
	for domain := range trustedDomains {
		if strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	
	return false
}

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	redirectURL := r.URL.Query().Get("request")
	
	// Validate the redirect URL
	if !isValidRedirectURL(redirectURL) {
		// Log the rejected redirect attempt
		// logger.Warn("Rejected redirect to untrusted domain", "url", redirectURL, "ip", r.RemoteAddr)
		
		// Redirect to a safe default page instead
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	
	// Redirect to the validated URL
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func main() {
	http.HandleFunc("/redirect", redirectHandler)
	http.ListenAndServe(":8080", nil)
}

```

This solution implements a robust validation mechanism that:
1. Allows relative URLs (internal redirects) automatically
2. Validates absolute URLs against an allowlist of trusted domains
3. Supports subdomains of trusted domains
4. Rejects malformed URLs or non-HTTP/HTTPS schemes
5. Gracefully handles invalid redirects by sending users to a safe default page

The allowlist should be regularly reviewed and updated as needed.
## Implement Indirect Reference Map for External Redirects

**Priority**: P1

Replace direct URL parameters with indirect references that map to pre-approved destinations:

```go
package main

import (
	"net/http"
	"strings"
)

// Map of indirect references to actual URLs
var redirectMap = map[string]string{
	"docs":     "https://docs.acme-corp.com",
	"support":  "https://support.acme-corp.com",
	"blog":     "https://blog.acme-corp.com",
	"partners": "https://partners.acme-corp.com",
	// Add other valid redirect destinations
}

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	// Get the indirect reference from the request parameter
	redirectKey := r.URL.Query().Get("to")
	
	// Clean the input to prevent manipulation
	redirectKey = strings.ToLower(strings.TrimSpace(redirectKey))
	
	// Look up the actual URL from the map
	destinationURL, exists := redirectMap[redirectKey]
	
	// If the key doesn't exist in our map, redirect to home page
	if !exists {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	
	// Safe to redirect to pre-approved destination
	http.Redirect(w, r, destinationURL, http.StatusFound)
}

func main() {
	http.HandleFunc("/redirect", redirectHandler)
	http.ListenAndServe(":8080", nil)
}

```

This approach:
1. Eliminates direct user control over redirect destinations
2. Uses a pre-defined mapping of keys to approved URLs
3. Simplifies URLs for legitimate use cases (e.g., `/redirect?to=docs` instead of long URLs)
4. Provides complete control over all possible redirect targets
5. Makes it easier to update or change destination URLs without changing application code

This pattern is particularly effective for applications that only need to redirect to a limited set of known external sites.


# References
* CWE-601 | [URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A01:2021 | [Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
* OTG-CLIENT-004 | [Testing for Client-side URL Redirect](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect)
