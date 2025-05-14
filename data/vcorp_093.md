# Open Redirect Vulnerability in Java Spring Controller

# Vulnerability Case
During a security audit of Acme Corp's Java Spring application, we identified an insecure redirect issue in a web controller that handles user-initiated redirects. Manual code reviews and dynamic testing revealed that the controller accepts a user-supplied parameter to determine the redirection destination without any whitelist or validation in place. This endpoint, built on Java 11 with Spring Boot 2.4.3 and Spring MVC, directly passes the parameter for an HTTP redirection. The lack of proper validation exposes the application to open redirect attacks that could be leveraged in phishing or social engineering campaigns.

```java
@RestController
public class RedirectController {

    @GetMapping("/redirect")
    public ResponseEntity<Void> redirectUser(@RequestParam("target") String target) {
        // Vulnerable: Direct use of user-supplied URL parameter without validation.
        return ResponseEntity.status(HttpStatus.FOUND)
            .location(URI.create(target))
            .build();
    }
}
```

The vulnerability arises because the `target` parameter is not subject to any validation or canonicalization, allowing an attacker to inject an arbitrary URL. By crafting a malicious link pointing to a phishing site, an attacker can trick users into believing they are navigating to a trusted Acme Corp page, thus exposing sensitive credentials or initiating malware downloads. Exploitation of this flaw can lead to significant business impacts including reputational damage, erosion of user trust, and potential legal liabilities stemming from data compromise and misuse of corporate branding.


context: java.spring.security.audit.spring-unvalidated-redirect.spring-unvalidated-redirect Application redirects a user to a destination URL specified by a user supplied parameter that is not validated.

# Vulnerability Breakdown
This vulnerability involves an unvalidated redirect in Acme Corp's Java Spring application that accepts a user-controlled URL parameter and performs redirection without any validation or sanitization.

1. **Key vulnerability elements**:
   - Unvalidated user input (`target` parameter) directly used in `URI.create()` method
   - No whitelist validation of acceptable redirect destinations
   - No URL canonicalization before processing
   - Implementation in a Spring Boot 2.4.3 REST controller
   - Direct construction of a `302 Found` redirect response

2. **Potential attack vectors**:
   - Crafting malicious links containing trusted Acme Corp domain with redirect to phishing sites
   - Distributing these links via email, messaging, or social media
   - Using the trusted domain to bypass security awareness training about checking URLs
   - Embedding malicious redirects in legitimate-looking communications

3. **Severity assessment**:
   - The vulnerability primarily impacts integrity through social engineering
   - Direct exploitation requires user interaction (clicking the malicious link)
   - No direct confidentiality impact as it doesn't expose sensitive information
   - No direct availability impact
   - Network-accessible attack vector increases potential attacker pool

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
An open redirect vulnerability has been identified in Acme Corp's Java Spring application within the `RedirectController`. This controller accepts a user-supplied `target` parameter and uses it directly to create a URL for redirection without any validation or sanitization.

```java
@RestController
public class RedirectController {

    @GetMapping("/redirect")
    public ResponseEntity<Void> redirectUser(@RequestParam("target") String target) {
        // Vulnerable: Direct use of user-supplied URL parameter without validation.
        return ResponseEntity.status(HttpStatus.FOUND)
            .location(URI.create(target))
            .build();
    }
}

```

This vulnerability allows attackers to craft malicious URLs that initially point to the legitimate Acme Corp domain but redirect users to arbitrary external websites. For example, a URL like `https://acme-corp.com/redirect?target=https://malicious-site.com` would appear to link to Acme Corp but would immediately redirect the user to the attacker's site.

The flaw can be exploited in phishing campaigns where attackers leverage the trusted Acme Corp domain to increase the credibility of their malicious links. Users who have been trained to verify domain names before clicking may still fall victim since the URL initially contains the legitimate Acme Corp domain.

# CVSS
**Score**: 4.2 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N \
**Severity**: Medium

The Medium severity rating (4.2) is justified by the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely over any network, allowing a wide range of potential attackers to create malicious redirect links.

- **Low Attack Complexity (AC:L)**: Exploitation is straightforward and requires no special conditions or preparation. An attacker simply needs to craft a URL with the redirect parameter pointing to their malicious site.

- **No Privileges Required (PR:N)**: The vulnerable endpoint is publicly accessible and requires no authentication or authorization to exploit.

- **User Interaction Required (UI:R)**: Successful exploitation depends on a user clicking the malicious link, which reduces the severity compared to automatically exploitable vulnerabilities.

- **Unchanged Scope (S:U)**: The vulnerability affects only the user who clicks the link and doesn't directly impact other components outside the vulnerable service.

- **No Confidentiality Impact (C:N)**: The redirect itself does not directly expose sensitive information from the system.

- **Low Integrity Impact (I:L)**: The main impact is on integrity, as it allows an attacker to control where users are directed, potentially leading them to malicious sites. However, this is limited to redirecting users rather than modifying actual system data.

- **No Availability Impact (A:N)**: The vulnerability does not impact the availability of the system.

While the direct technical impact is limited to redirection, this vulnerability becomes dangerous when combined with social engineering techniques, allowing attackers to leverage Acme Corp's trusted domain name to increase the success rate of phishing campaigns.

# Exploitation Scenarios
**Scenario 1: Credential Harvesting Phishing Attack**
An attacker crafts a malicious URL like `https://acme-corp.com/redirect?target=https://acme-corp-login.attacker.com` and sends it to Acme Corp customers via email, claiming they need to verify their account information. The initial domain (acme-corp.com) appears legitimate, increasing the likelihood that users will trust and click the link. Upon clicking, users are redirected to the attacker's site, which mimics Acme Corp's login page. When unsuspecting users enter their credentials, the attacker captures them for unauthorized access.

**Scenario 2: Corporate Phishing Campaign**
An attacker targets Acme Corp employees by sending an internal-looking email containing a link like `https://acme-corp.com/redirect?target=https://sharepoint-docs.attacker.com/quarterly_report`. The email appears to come from management and requests review of a quarterly report. Employees who click the link are redirected to a malicious site that either harvests corporate credentials or delivers malware designed to compromise the internal network.

**Scenario 3: Malware Distribution**
An attacker creates a URL such as `https://acme-corp.com/redirect?target=https://malware-delivery.attacker.com/acme-update.exe` and distributes it through forums, social media, or direct messages claiming it's an update for an Acme Corp product. Users who trust the initial Acme Corp domain click the link and are redirected to download malware disguised as legitimate software. The malware could be ransomware, spyware, or other malicious code that compromises the user's system.

# Impact Analysis
**Business Impact:**
- Reputational damage as Acme Corp's domain is used to facilitate phishing attacks
- Erosion of customer trust when they discover the company's website redirected them to malicious sites
- Potential loss of customers who lose confidence in the company's security practices
- Legal liabilities if customer data is compromised through phishing facilitated by this vulnerability
- Regulatory penalties if the vulnerability leads to compliance violations
- Brand damage from misuse of corporate identity in social engineering attacks
- Increased customer support costs for handling security incidents and customer concerns

**Technical Impact:**
- Enables attackers to bypass domain-based security controls by leveraging a trusted domain
- Undermines security awareness training that emphasizes checking domain names before clicking
- Facilitates more effective social engineering by adding credibility to phishing attempts
- Potentially enables distribution of malware through a trusted channel
- May lead to credential theft for Acme Corp services or other sites if users reuse passwords
- Could serve as an initial attack vector for more sophisticated compromise attempts
- Provides attackers with a persistent mechanism to conduct campaigns until the vulnerability is fixed

# Technical Details
The vulnerability exists in the `RedirectController` class which implements a REST endpoint for redirection. The issue stems from directly using unsanitized user input to create a redirect URL without any validation:

```java
@RestController
public class RedirectController {

    @GetMapping("/redirect")
    public ResponseEntity<Void> redirectUser(@RequestParam("target") String target) {
        // Vulnerable: Direct use of user-supplied URL parameter without validation.
        return ResponseEntity.status(HttpStatus.FOUND)
            .location(URI.create(target))
            .build();
    }
}

```

**Key Technical Issues:**

1. **Lack of Input Validation**: The code accepts any string as the `target` parameter and attempts to create a URI from it without validating that it points to an allowed destination.

2. **Direct Use in Security-Sensitive Operation**: The unvalidated input is directly used in `URI.create()` and then passed to `ResponseEntity.location()`, creating an HTTP 302 Found redirect response.

3. **No Canonicalization**: The input URL is not normalized or canonicalized, which could allow various encoding tricks to bypass simple pattern matching if implemented incorrectly.

4. **Spring MVC Request Parameter Handling**: Spring's `@RequestParam` annotation automatically extracts the parameter from the query string, making the endpoint readily accessible via GET requests.

**Exploitation Mechanics:**

An attacker constructs a URL pointing to the vulnerable endpoint with the `target` parameter set to their malicious destination:

```
https://acme-corp.com/redirect?target=https://malicious-site.com

```

When a user visits this URL, the following occurs:

1. The request is routed to the `redirectUser()` method
2. The value `https://malicious-site.com` is extracted as the `target` parameter
3. This value is passed directly to `URI.create()` to create a URI object
4. The response includes a `Location: https://malicious-site.com` header
5. The user's browser automatically follows the redirect to the malicious site

The browser shows the initial legitimate domain (acme-corp.com) briefly before redirecting, which helps convince users of the link's legitimacy, especially in email clients or messaging apps that display preview information for URLs.

# Remediation Steps
## Implement URL Whitelist Validation

**Priority**: P0

Modify the controller to validate redirect URLs against a whitelist of allowed domains:

```java
@RestController
public class RedirectController {

    // List of allowed domains for redirection
    private static final List<String> ALLOWED_DOMAINS = Arrays.asList(
        "acme-corp.com",
        "support.acme-corp.com",
        "docs.acme-corp.com"
    );
    
    @GetMapping("/redirect")
    public ResponseEntity<Void> redirectUser(@RequestParam("target") String target) {
        // Validate the URL against the whitelist
        if (!isUrlAllowed(target)) {
            // Redirect to default page if validation fails
            return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create("/home"))
                .build();
        }
        
        return ResponseEntity.status(HttpStatus.FOUND)
            .location(URI.create(target))
            .build();
    }
    
    private boolean isUrlAllowed(String url) {
        try {
            // Parse the URL
            URI uri = new URI(url);
            String host = uri.getHost();
            
            // Validate against whitelist
            if (host == null) {
                // Relative URLs are allowed (they stay on the same domain)
                return url.startsWith("/");
            }
            
            // Check if the host matches or is a subdomain of an allowed domain
            return ALLOWED_DOMAINS.stream()
                .anyMatch(domain -> host.equals(domain) || 
                          (host.endsWith("." + domain) && host.length() > domain.length() + 1));
                          
        } catch (URISyntaxException e) {
            // Invalid URL format
            return false;
        }
    }
}

```

This implementation validates all redirect URLs against a predefined whitelist of allowed domains, ensuring that users can only be redirected to trusted destinations. Relative URLs (starting with '/') are allowed as they remain on the same domain.
## Implement Indirect Reference Mapping

**Priority**: P1

Replace direct URL parameters with indirect references to predefined destinations:

```java
@RestController
public class RedirectController {

    // Map of allowed redirect destinations
    private static final Map<String, String> REDIRECT_MAP = Map.of(
        "home", "/home",
        "support", "https://support.acme-corp.com",
        "docs", "https://docs.acme-corp.com/api",
        "partner", "https://partner.acme-corp.com/login"
    );
    
    @GetMapping("/redirect")
    public ResponseEntity<Void> redirectUser(@RequestParam("id") String redirectId) {
        // Look up the destination URL from the predefined map
        String destination = REDIRECT_MAP.getOrDefault(redirectId, "/home");
        
        return ResponseEntity.status(HttpStatus.FOUND)
            .location(URI.create(destination))
            .build();
    }
}

```

This approach eliminates the possibility of open redirects by never accepting direct URLs from users. Instead, it uses a key-based system where each key maps to a predefined, validated URL. For example, `/redirect?id=support` would redirect to the support site. This provides complete control over all possible redirect destinations.


# References
* CWE-601 | [URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* CWE-116 | [Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)
