# Missing Subresource Integrity (SRI) Attribute on Externally Hosted JavaScript

# Vulnerability Case
During the security assessment of Acme Corp's customer portal, we observed that an externally hosted JavaScript library loaded from a public CDN lacked the necessary subresource integrity (SRI) attribute. This omission was identified during a manual review of the page’s source code, where the absence of a base64-encoded cryptographic hash rendered the external file unverified. The affected asset, a jQuery library hosted on Google CDN, exemplifies how missing SRI parameters expose the application to risk. Without SRI, compromised delivery from the CDN can result in malicious tampering of the external resource, increasing the likelihood of cross-site scripting (XSS) and session hijacking attacks. The infrastructure, running on an NGINX web server and leveraging industry-standard CDN technology, amplifies the potential business impact.

```html
<!-- Vulnerable HTML snippet: Missing SRI attribute -->
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
```

An attacker exploiting this vulnerability could intercept or manipulate the network traffic between the CDN and the client. By injecting malicious code into the loaded JavaScript, the adversary may execute arbitrary code within the context of the user’s browser—effectively performing XSS attacks that compromise session tokens or perform unauthorized actions. The lack of an SRI attribute prevents the browser from verifying the integrity and authenticity of the external resource, thereby undermining the trusted supply chain model. Consequently, successful exploitation could lead to serious business ramifications, including unauthorized data access, erosion of customer trust, and potential regulatory consequences.


context: html.security.audit.missing-integrity.missing-integrity This tag is missing an 'integrity' subresource integrity attribute. The 'integrity' attribute allows for the browser to verify that externally hosted files (for example from a CDN) are delivered without unexpected manipulation. Without this attribute, if an attacker can modify the externally hosted resource, this could lead to XSS and other types of attacks. To prevent this, include the base64-encoded cryptographic hash of the resource (file) you’re telling the browser to fetch in the 'integrity' attribute for all externally hosted files.

# Vulnerability Breakdown
This vulnerability involves the absence of Subresource Integrity (SRI) verification for externally hosted JavaScript libraries, creating a supply chain risk.

1. **Key vulnerability elements**:
   - jQuery library loaded from Google CDN without SRI verification
   - Missing integrity attribute that would provide cryptographic verification
   - External dependency hosted on third-party infrastructure outside Acme Corp's control
   - NGINX web server environment with standard CDN implementation

2. **Potential attack vectors**:
   - Man-in-the-middle attacks intercepting CDN traffic (requires adjacent network position)
   - Compromise of the CDN infrastructure (rare but high impact)
   - DNS poisoning redirecting CDN requests to malicious servers
   - BGP hijacking affecting CDN routing
   - Cache poisoning attacks against the CDN

3. **Severity assessment**:
   - Adjacent attack vector requiring logically adjacent network positioning
   - High attack complexity requiring sophisticated techniques to compromise the CDN or traffic
   - No privileges required to execute the attack
   - No user interaction required beyond visiting the affected page
   - Potential for unauthorized data access and injection of malicious code

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Adjacent (A) 
   - Attack Complexity (AC): High (H) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): Low (L) 
   - Integrity (I): Low (L) 
   - Availability (A): None (N) 

# Description
Acme Corp's customer portal is vulnerable to script tampering due to missing Subresource Integrity (SRI) attributes on externally hosted JavaScript libraries. Specifically, the jQuery library loaded from Google's CDN lacks the necessary cryptographic hash verification that would prevent the execution of modified scripts.

```html
<!-- Vulnerable HTML snippet: Missing SRI attribute -->
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>

```

Without the integrity attribute, the browser has no mechanism to verify that the content received from the CDN matches what was expected. This creates a significant supply chain security risk as any compromise of the CDN, or the connection between the user and the CDN, could result in the execution of malicious JavaScript within the context of the Acme Corp website. Such execution could lead to various attacks, including cross-site scripting (XSS), session hijacking, and data theft.

# CVSS
**Score**: 4.2 \
**Vector**: CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N \
**Severity**: Medium

The Medium severity rating (4.2) is justified by multiple factors. The vulnerability is classified with an Adjacent attack vector (AV:A) because successful exploitation requires the attacker to be positioned within the logical network path between users and the CDN, such as through man-in-the-middle attacks or network infrastructure compromise. This is more restricted than a purely Network-based vector.

The attack complexity is High (AC:H) as it necessitates either compromising a major CDN like Google's or successfully executing sophisticated traffic interception techniques. No privileges (PR:N) or user interaction (UI:N) are required beyond a user simply visiting the affected page.

The scope remains unchanged (S:U) as effects are limited to the application's own security context. The impact is assessed as Low for both confidentiality (C:L) and integrity (I:L) because while attackers could access some sensitive data and perform unauthorized modifications through injected scripts, this access is limited to what's available in the browser context. There is no direct impact on availability (A:N) as the attack doesn't cause denial of service.

While the severity is Medium, this vulnerability should not be underestimated as it creates a significant supply chain risk that could be exploited as part of a sophisticated attack chain.

# Exploitation Scenarios
**Scenario 1: Man-in-the-Middle Attack**
An attacker positioned between users and the CDN (e.g., on public WiFi, through compromised network equipment, or via ISP interception) intercepts requests for the jQuery library. The attacker responds with a modified version containing keylogging functionality and a script that exfiltrates sensitive user information. Users on the compromised network receive this malicious version, and their browsers execute it without verification due to the missing integrity attribute. This scenario requires the attacker to have a position logically adjacent to either the victim or the network path to the CDN.

**Scenario 2: CDN Compromise**
An advanced persistent threat actor compromises Google's CDN infrastructure or persuades the CDN provider to serve modified content through social engineering. When users visit Acme Corp's customer portal, they receive a malicious version of jQuery that contains code to harvest login credentials and credit card information entered on the site. Without SRI, the browser has no way to detect that the script has been modified and executes the malicious code in the context of the Acme Corp domain.

**Scenario 3: DNS Poisoning**
An attacker executes a DNS poisoning attack against ajax.googleapis.com, causing users' DNS resolvers to direct requests to a malicious server instead of Google's CDN. The malicious server returns altered JavaScript that, when executed, creates an invisible iframe on Acme Corp's page that mimics login forms to capture credentials. Without SRI verification, the browser cannot detect the substitution and runs the malicious code. This attack requires the attacker to have access to network infrastructure in a position that can influence DNS resolution for targeted users.

# Impact Analysis
**Business Impact:**
- Unauthorized access to customer accounts if credentials are stolen via injected scripts
- Financial losses from fraudulent transactions if payment information is compromised
- Erosion of customer trust when security incidents become public
- Potential regulatory penalties under data protection laws like GDPR or CCPA
- Remediation costs including forensic investigation, breach notification, and credit monitoring services
- Reputational damage affecting customer acquisition and retention

**Technical Impact:**
- Execution of arbitrary JavaScript in the context of the Acme Corp domain
- Cross-site scripting (XSS) attacks enabling session hijacking and cookie theft
- Client-side data exfiltration including form inputs, authentication tokens, and user information
- Modification of webpage content to create phishing opportunities
- Potential for persistent compromise if the attacker modifies client-side storage mechanisms
- Bypassing of same-origin policy protections through trusted script context
- Potential leverage for further attacks against both users and the application

# Technical Details
Subresource Integrity (SRI) is a security feature that enables browsers to verify that resources fetched from external sources (like CDNs) are delivered without unexpected manipulation. It works by providing a cryptographic hash of the expected resource content in the HTML tag that loads the resource.

In the identified vulnerability, the jQuery library is loaded from Google's CDN without implementing SRI:

```html
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>

```

When a browser encounters this tag, it fetches the JavaScript file but has no way to verify that the content received matches what the developer intended. This creates several security risks:

1. **Trust Chain Weakness**: The application implicitly trusts that Google's CDN will always serve the correct, unmodified version of jQuery.

2. **Expanded Attack Surface**: Any compromise in the chain between the user and the CDN becomes a potential attack vector:
   - CDN infrastructure compromise (rare but catastrophic)
   - Network-level interception (requiring adjacent positioning)
   - DNS or routing attacks (requiring infrastructure access)

3. **Adjacent Network Positioning Requirement**: For most practical attack scenarios, the attacker would need to be positioned in one of these ways:
   - On the same physical network as the victim (e.g., public WiFi)
   - At an Internet exchange point or ISP handling traffic between the victim and CDN
   - In control of network infrastructure that can influence routing or DNS resolution

4. **Script Execution Context**: Any malicious code injected into the jQuery file executes with the same privileges as the rest of the application's JavaScript - within the origin of Acme Corp's customer portal.

The missing integrity attribute means the browser cannot perform the verification step that would prevent modified scripts from executing. This verification would typically involve:

1. Computing a hash of the received resource
2. Comparing it against the hash specified in the integrity attribute
3. Refusing to execute the resource if the hashes don't match

This vulnerability is particularly concerning because jQuery is a fundamental library that typically has extensive access to the DOM and often runs early in the page load process, giving it significant capabilities to modify the page and intercept user interactions.

# Remediation Steps
## Implement Subresource Integrity Attributes

**Priority**: P0

Add integrity attributes containing cryptographic hashes to all externally hosted resources:

```html
<!-- Fixed: Added SRI attribute with SHA-384 hash -->
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js" 
        integrity="sha384-ZvpUoO/+PpLXR1lu4jmpXWu80pZlYUAfxl5NsBMWOEPSjUn/6Z/hRTt8+pR6L4N2" 
        crossorigin="anonymous"></script>

```

To generate the proper hash for a resource:

1. Use online tools like SRI Hash Generator or the following command line:
   ```bash
   curl -s https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js | openssl dgst -sha384 -binary | openssl base64 -A
   
```

2. Verify the hash is correct by checking official sources or computing it from multiple locations

3. Add both the integrity attribute with the hash and the crossorigin="anonymous" attribute to all external script and link tags

4. Implement a build process or developer tools that automatically generate and verify SRI hashes
## Implement Content Security Policy with SRI Requirements

**Priority**: P1

Deploy a Content Security Policy that enforces Subresource Integrity for all external scripts and stylesheets:

```html
<!-- Add to HTTP headers or meta tag -->
<meta http-equiv="Content-Security-Policy" content="require-sri-for script style">

```

This CSP directive forces the browser to reject any script or stylesheet from external sources that doesn't have a valid integrity attribute, providing defense-in-depth against missing SRI attributes.

For comprehensive protection, implement a full CSP that also restricts script sources:

```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https://ajax.googleapis.com require-sri-for; style-src 'self' https://fonts.googleapis.com require-sri-for; object-src 'none'; base-uri 'self'; frame-ancestors 'self';">

```

Preferably, set the policy via HTTP headers rather than meta tags to ensure it cannot be bypassed by script injection:

```
Content-Security-Policy: require-sri-for script style; script-src 'self' https://ajax.googleapis.com; style-src 'self' https://fonts.googleapis.com;

```

Test the CSP implementation thoroughly to ensure it doesn't break legitimate functionality.


# References
* CWE-353 | [Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)
* CWE-494 | [Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)
* A08:2021 | [Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
* A05:2021 | [Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
* SRI | [Subresource Integrity - MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)
