# Unvalidated Redirect Vulnerability in Spring Boot Application

# Vulnerability Case
During our security audit of Acme Corp's Java-based web application, we identified an unvalidated redirect vulnerability in the endpoint responsible for handling user-supplied destination URLs. The redirection logic accepts a parameter directly via a GET request without validating it against an allowlist, enabling an attacker to redirect users to arbitrary external sites. This issue was uncovered during manual code review and dynamic testing of the endpoint under abnormal input conditions. Such a flaw could be exploited to facilitate phishing attacks or deliver malware, undermining user trust and the overall security posture of the application. The affected stack includes Java, Spring Boot, and Tomcat, reflecting a common enterprise web infrastructure.

```java
@RestController
public class RedirectController {

    @GetMapping("/redirect")
    public void redirectTo(@RequestParam("destination") String destination,
                           HttpServletResponse response) throws IOException {
        // Vulnerable: The destination URL is accepted without validation or filtering.
        response.sendRedirect(destination);
    }
}
```

The vulnerability stems from the application's direct usage of the user-supplied parameter in the HTTP redirection method (`response.sendRedirect`) without validating it against an allowlist of trusted domains. An attacker can craft a malicious URL leading to phishing or malware-hosting sites by manipulating the `destination` parameter. Exploitation involves sending a crafted link to victim users, who then unwittingly navigate to an attacker-controlled page designed to harvest credentials or distribute malware. This can result in significant business impacts including reputational damage, decreased user trust, and potential legal or regulatory ramifications.


context: java.lang.security.audit.unvalidated-redirect.unvalidated-redirect Application redirects to a destination URL specified by a user-supplied parameter that is not validated. This could direct users to malicious locations. Consider using an allowlist to validate URLs.

# Vulnerability Breakdown
This vulnerability involves an unvalidated redirection flaw in Acme Corp's Java-based web application that allows attackers to craft malicious URLs redirecting users to arbitrary external domains.

1. **Key vulnerability elements**:
   - Direct use of user-supplied `destination` parameter in `response.sendRedirect()`
   - No validation or filtering of URL parameters
   - Spring Boot REST controller implementation
   - No allowlist of trusted domains implemented
   - Java, Spring Boot, and Tomcat enterprise stack

2. **Potential attack vectors**:
   - Crafting malicious links containing the vulnerable endpoint with a redirect to phishing sites
   - Distributing these links through email, social media, or other channels
   - Social engineering users to click on seemingly legitimate URLs from a trusted domain
   - Redirecting users to sites hosting malware or credential-harvesting forms

3. **Severity assessment**:
   - The vulnerability primarily impacts integrity through social engineering
   - Potential confidentiality impact through subsequent phishing attacks
   - Requires user interaction (clicking the malicious link)
   - Network-based attack vector enabling remote exploitation
   - Low complexity to execute

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
An unvalidated redirect vulnerability exists in Acme Corp's Java-based web application, specifically in a Spring Boot controller endpoint that handles redirection to user-supplied destination URLs. When a request is made to the `/redirect` endpoint with a `destination` parameter, the application performs a redirect to the specified URL without any validation or filtering.

```java
@RestController
public class RedirectController {

    @GetMapping("/redirect")
    public void redirectTo(@RequestParam("destination") String destination,
                           HttpServletResponse response) throws IOException {
        // Vulnerable: The destination URL is accepted without validation or filtering.
        response.sendRedirect(destination);
    }
}

```

This vulnerability allows attackers to craft malicious URLs that redirect users to arbitrary external websites, including those designed for phishing attacks or malware distribution. Because the initial URL appears to come from a trusted domain (the Acme Corp application), users are more likely to trust the redirect, increasing the effectiveness of social engineering attacks.

# CVSS
**Score**: 5.4 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N \
**Severity**: Medium

The Medium severity rating (5.4) is based on the following factors:

- **Network (N) attack vector**: The vulnerability is exploitable remotely by anyone who can send links to users of the application
- **Low (L) attack complexity**: Exploitation is straightforward, requiring only the creation of a malicious URL with the redirect parameter
- **No privileges (N) required**: No authentication is needed to create or distribute the malicious URL
- **User interaction (R) required**: Exploitation depends on a user clicking the malicious link
- **Unchanged (U) scope**: The vulnerability does not allow impact beyond the vulnerable component itself
- **Low (L) confidentiality impact**: While the vulnerability itself doesn't directly expose sensitive data, it facilitates phishing attacks that could lead to credential theft
- **Low (L) integrity impact**: Users can be misled into visiting malicious websites, damaging the integrity of their browsing experience
- **None (N) availability impact**: The vulnerability does not directly affect the availability of the application

The severity is rated as Medium rather than High because the vulnerability requires user interaction and primarily serves as a stepping stone for other attacks rather than directly compromising system security. However, its effectiveness in social engineering makes it a significant security concern that should be addressed promptly.

# Exploitation Scenarios
**Scenario 1: Credential Harvesting Phishing Attack**
An attacker crafts a URL like `https://acme-corp.com/redirect?destination=https://acme-corp-login.attacker.com` that points to a fake login page mimicking Acme Corp's authentication portal. The attacker sends this URL via email to Acme Corp customers claiming they need to verify their account information. When users click the link, they initially see the legitimate acme-corp.com domain in their browser, establishing trust. The application then redirects them to the attacker's phishing site, which looks identical to the real login page. Users, believing they're on the authentic site, enter their credentials, which are captured by the attacker.

**Scenario 2: Malware Distribution**
An attacker creates a URL such as `https://acme-corp.com/redirect?destination=https://malware-distribution.com/fake-document.exe` and posts it on social media or forums, claiming it links to an important document or software update from Acme Corp. Users who click the link are redirected to a malicious site that attempts to download malware to their devices. The initial legitimacy of the acme-corp.com domain in the URL lowers users' suspicions, increasing the likelihood they'll proceed with the download.

**Scenario 3: Social Engineering with URL Encoding**
To make the attack less obvious, an attacker URL-encodes the malicious destination, creating a link like `https://acme-corp.com/redirect?destination=https%3A%2F%2Facme-corp-support.attacker.com`. The attacker then sends targeted messages to employees claiming to be from IT support, requesting they verify their account details for security purposes. The encoded URL makes it difficult for even vigilant users to identify the redirect, increasing the success rate of the phishing attempt.

# Impact Analysis
**Business Impact:**
- Erosion of customer trust when malicious redirects are associated with the company's domain
- Potential reputational damage, especially if the vulnerability is exploited in widespread phishing campaigns
- Increased customer support costs dealing with affected users
- Possible regulatory scrutiny if the vulnerability contributes to data breaches
- Legal liability if customer data is compromised through attacks facilitated by this vulnerability
- Damage to brand reputation and customer relationships
- Loss of business from customers concerned about security practices

**Technical Impact:**
- Facilitates highly effective phishing attacks by leveraging the organization's domain reputation
- Enables attackers to bypass security awareness training that teaches users to verify domain names
- Creates a persistent attack vector that can be exploited until patched
- May result in credential theft leading to account takeovers
- Could facilitate malware distribution to users and potentially internal systems
- Undermines other security controls by exploiting established trust relationships
- Potential for session hijacking if users are already authenticated to the application

# Technical Details
The vulnerability exists in a Spring Boot controller method that accepts a user-supplied URL and performs a redirect without any validation:

```java
@RestController
public class RedirectController {

    @GetMapping("/redirect")
    public void redirectTo(@RequestParam("destination") String destination,
                           HttpServletResponse response) throws IOException {
        // Vulnerable: The destination URL is accepted without validation or filtering.
        response.sendRedirect(destination);
    }
}

```

**Exploitation Mechanics:**

1. The `redirectTo` method accepts a `destination` parameter from the request without any validation
2. The value of this parameter is passed directly to `response.sendRedirect()`
3. This causes the server to respond with a 302 Found status code and a Location header containing the unvalidated URL
4. The user's browser automatically follows this redirect to the specified destination

**Technical Vulnerability Factors:**

1. **No Input Validation**: The code lacks any validation of the `destination` parameter
2. **No URL Allowlisting**: There's no check against a list of approved domains
3. **No Origin Verification**: The application doesn't verify that redirects stay within trusted domains
4. **Direct Use of User Input**: The parameter is used directly in a security-sensitive operation

This pattern is particularly dangerous because:

- The HTTP redirect happens server-side, giving it legitimacy
- The initial request is to a trusted domain, which may bypass security controls
- Users typically don't inspect redirect chains, only the initial URL
- The vulnerability exists in a Spring Boot application, which might have many endpoints and a large attack surface

In the HTTP response, the vulnerable code would generate something like:

```http
HTTP/1.1 302 Found
Location: https://malicious-site.com
Content-Length: 0

```

Browsers automatically follow this redirect, taking users to the malicious destination. The fact that this occurs from a trusted domain significantly increases the effectiveness of social engineering attacks.

# Remediation Steps
## Implement URL Allowlist Validation

**Priority**: P0

Modify the controller to validate the destination URL against an allowlist of trusted domains:

```java
@RestController
public class RedirectController {

    private final Set<String> ALLOWED_DOMAINS = new HashSet<>(Arrays.asList(
        "acme-corp.com",
        "trusted-partner.com",
        "acme-resources.com"
    ));
    
    @GetMapping("/redirect")
    public void redirectTo(@RequestParam("destination") String destination,
                          HttpServletResponse response) throws IOException {
        // Validate the URL is safe before redirecting
        if (isValidRedirectUrl(destination)) {
            response.sendRedirect(destination);
        } else {
            // Log the blocked redirect attempt
            logger.warn("Blocked potential open redirect to: " + destination);
            // Redirect to default page or show error
            response.sendRedirect("/error?msg=invalid_redirect");
        }
    }
    
    private boolean isValidRedirectUrl(String url) {
        try {
            // Parse the URL to extract the host
            URI uri = new URI(url);
            String host = uri.getHost();
            
            // Null host means relative URL, which is safe
            if (host == null) {
                return true;
            }
            
            // Check if the host ends with any allowed domain
            return ALLOWED_DOMAINS.stream()
                .anyMatch(domain -> host.equals(domain) || host.endsWith("." + domain));
                
        } catch (URISyntaxException e) {
            // Invalid URL format
            return false;
        }
    }
}

```

This implementation validates redirect URLs against a defined set of trusted domains, blocking any redirects to external sites. It also safely handles relative URLs (which stay within the application) and logs blocked redirect attempts for security monitoring.
## Implement Indirect Reference Map for External Redirects

**Priority**: P1

Instead of directly accepting destination URLs, implement an indirect reference pattern where specific keys map to pre-approved destinations:

```java
@RestController
public class RedirectController {

    private final Map<String, String> REDIRECT_MAP = Map.of(
        "account", "https://accounts.acme-corp.com/manage",
        "support", "https://support.acme-corp.com",
        "docs", "https://docs.acme-corp.com",
        "partner", "https://trusted-partner.com/acme-integration"
    );
    
    @GetMapping("/redirect")
    public void redirectTo(@RequestParam("target") String target,
                          HttpServletResponse response) throws IOException {
        // Look up the actual URL from the map of approved destinations
        String destination = REDIRECT_MAP.get(target);
        
        if (destination != null) {
            response.sendRedirect(destination);
        } else {
            // Log the invalid redirect attempt
            logger.warn("Invalid redirect target requested: " + target);
            // Redirect to default page or show error
            response.sendRedirect("/");
        }
    }
}

```

This approach completely eliminates the possibility of open redirects by never accepting raw URLs from users. Instead, it uses a predefined mapping of keys to valid destinations, ensuring that only pre-approved redirects can occur. The controller now accepts a `target` parameter (like "account" or "support") and maps it to a known-good URL.


# References
* CWE-601 | [URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)
* A01:2021 | [Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
