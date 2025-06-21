# Missing Secure Flag on Authentication Cookie

# Vulnerability Case
During a routine security audit of Acme Corp's Java-based web application running on Apache Tomcat, it was observed that the authentication session cookie was being set without the 'secure' flag. This vulnerability was identified during a code review of the cookie management routine in the application, where the absence of a call to `setSecure(true)` was noted. The issue was reproduced on a staging environment where HTTPS was employed, yet the cookie was transmitted on both HTTP and HTTPS channels. The discovery highlighted a potential risk where session cookies could be intercepted during insecure HTTP communications, posing a significant security risk.

```java
// Vulnerable cookie creation in a Java Servlet application
Cookie sessionCookie = new Cookie("JSESSIONID", sessionId);
// Missing secure flag: should be sessionCookie.setSecure(true);
response.addCookie(sessionCookie);
```

The lack of the 'secure' flag allows an attacker with network access to intercept the authentication cookie over an HTTP connection, potentially leading to session hijacking and unauthorized access. In a real-world setting, exploiting this vulnerability could result in significant business impact including loss of sensitive user data and a compromise of the session management mechanisms in a critical web application.


context: java.lang.security.audit.cookie-missing-secure-flag.cookie-missing-secure-flag A cookie was detected without setting the 'secure' flag. The 'secure' flag for cookies prevents the client from transmitting the cookie over insecure channels such as HTTP. Set the 'secure' flag by calling '$COOKIE.setSecure(true);'

# Vulnerability Breakdown
This vulnerability involves a Java web application setting the JSESSIONID authentication cookie without the 'secure' flag, allowing it to be transmitted over insecure HTTP connections.

1. **Key vulnerability elements**:
   - Authentication session cookie (JSESSIONID) created without the `setSecure(true)` property
   - Cookie visible in plaintext during HTTP transmission
   - Affects a Java Servlet application running on Apache Tomcat
   - Vulnerability persists even when HTTPS is available
   - JSESSIONID cookie directly tied to user authentication state

2. **Potential attack vectors**:
   - Man-in-the-middle attacks on insecure networks (coffee shops, airports)
   - Network traffic sniffing on shared infrastructure
   - SSL stripping attacks that force downgrade from HTTPS to HTTP
   - Mixed-content scenarios where parts of the application use HTTP

3. **Severity assessment**:
   - Primarily impacts confidentiality of user session data
   - Requires specific attack conditions (network positioning)
   - No direct impact on system integrity or availability
   - Critical authentication information exposed

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Adjacent (A) 
   - Attack Complexity (AC): High (H) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): None (N) 
   - Availability (A): None (N) 

# Description
A security vulnerability has been identified in Acme Corp's Java-based web application running on Apache Tomcat, where the authentication session cookie (JSESSIONID) is being set without the 'secure' flag. This configuration error allows the session cookie to be transmitted over unencrypted HTTP connections, not just HTTPS.

```java
// Vulnerable code example
Cookie sessionCookie = new Cookie("JSESSIONID", sessionId);
// Missing secure flag: should be sessionCookie.setSecure(true);
response.addCookie(sessionCookie);

```

When cookies lack the 'secure' flag, they are transmitted in every request to the corresponding domain, regardless of protocol. This means that even if a user initially authenticates over HTTPS, their session cookie may be sent unencrypted in subsequent HTTP requests, exposing it to potential interception by network attackers. The JSESSIONID cookie is particularly sensitive as it directly represents the user's authenticated session, and its compromise would allow an attacker to completely hijack the user's session.

# CVSS
**Score**: 5.3 \
**Vector**: CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N \
**Severity**: Medium

The Medium severity rating (CVSS score 5.3) reflects several key factors:

- **Adjacent Attack Vector (AV:A)**: Exploitation requires the attacker to have access to the victim's network or be positioned between the victim and the application. This significantly limits the attack surface compared to remotely exploitable vulnerabilities.

- **High Attack Complexity (AC:H)**: Successfully exploiting this vulnerability requires specific conditions - the attacker must be able to perform network eavesdropping or man-in-the-middle attacks, which demand technical expertise and favorable network circumstances.

- **No Privileges Required (PR:N)**: The attacker doesn't need any privileges on the target system to exploit this vulnerability - simply the ability to capture network traffic.

- **No User Interaction (UI:N)**: The vulnerability can be exploited without requiring any action from a legitimate user beyond normal application usage.

- **Unchanged Scope (S:U)**: The impact remains confined to the vulnerable component rather than affecting other components.

- **High Confidentiality Impact (C:H)**: The most significant impact is on confidentiality, as an attacker can gain full access to the user's session, potentially exposing all data the legitimate user can access.

- **No Integrity or Availability Impact (I:N, A:N)**: This vulnerability by itself doesn't directly allow data modification or cause system disruption.

While the vulnerability provides access to authentication session data (high confidentiality impact), the considerable attack complexity and adjacent attack vector requirements moderate the overall severity.

# Exploitation Scenarios
**Scenario 1: Public Wi-Fi Attack**
An employee of Acme Corp is working from a coffee shop using public Wi-Fi. An attacker on the same network uses packet sniffing tools like Wireshark to capture network traffic. The employee accesses the web application, initially connecting via HTTPS. However, when the application serves some resources over HTTP or redirects to an HTTP page, the JSESSIONID cookie is transmitted unencrypted. The attacker captures this cookie, adds it to their browser, and gains complete access to the employee's authenticated session without needing credentials.

**Scenario 2: Mixed Content Exploitation**
The Acme Corp web application primarily uses HTTPS but embeds some resources (like images or scripts) that are loaded over HTTP. A user logs into the application securely, but when their browser requests these HTTP resources, it sends the JSESSIONID cookie in cleartext with each request. An attacker monitoring network traffic captures this cookie from the unencrypted HTTP requests and uses it to hijack the user's session.

**Scenario 3: SSL Stripping Attack**
An attacker with network positioning conducts an SSL stripping attack using tools like sslstrip. When a user types "acmecorp.com" in their browser (without explicitly specifying https://), the attacker intercepts the initial request and maintains an HTTPS connection to the server while establishing an HTTP connection with the victim. All traffic between the attacker and victim occurs over HTTP, allowing the attacker to see all cookies being transmitted, including the JSESSIONID cookie. The attacker can then use this cookie to impersonate the user.

# Impact Analysis
**Business Impact:**
- Potential unauthorized access to sensitive customer information, leading to privacy breaches
- Regulatory compliance violations (GDPR, CCPA, HIPAA, etc.) resulting in financial penalties
- Damage to company reputation and loss of customer trust if a breach occurs
- Financial costs associated with incident response, forensic investigation, and remediation
- Potential legal liability from affected users whose sessions were compromised
- Business disruption during emergency patching and forced user re-authentication

**Technical Impact:**
- Complete session hijacking allowing attackers to impersonate legitimate users
- Unauthorized access to all functionality and data available to the compromised user account
- Potential for privilege escalation if an administrative user's session is compromised
- Bypass of authentication mechanisms without leaving traces in authentication logs
- Limited forensic capability to detect exploitation, as the attacker uses a legitimate session
- Risk of sensitive data exposure depending on what information is accessible in the user session
- Potential for further attacks using the hijacked session as an entry point

# Technical Details
The vulnerability stems from improper configuration of cookie security attributes in the Java Servlet-based web application. Specifically, the JSESSIONID cookie, which is used by Apache Tomcat to maintain session state, is created without the 'secure' flag.

```java
// Current vulnerable implementation
Cookie sessionCookie = new Cookie("JSESSIONID", sessionId);
// The secure flag is not set
response.addCookie(sessionCookie);

```

When a cookie lacks the 'secure' flag, web browsers will transmit it in every request to the domain, regardless of whether the connection uses HTTP or HTTPS. This behavior creates a security risk because:

1. Even if a user initially logs in via HTTPS, if they navigate to any HTTP URL within the same domain (or if the application serves mixed content), the JSESSIONID cookie will be sent in cleartext.

2. The JSESSIONID cookie directly represents the user's authenticated session in Java web applications. Possession of this cookie is equivalent to having the user's authentication credentials for the duration of the session.

3. Network packet analysis tools like Wireshark can easily extract cookies from unencrypted HTTP traffic, making interception straightforward for attackers with network access.

The HTTP protocol transmits cookies in plaintext as part of the request headers. For example:

```
GET /app/dashboard HTTP/1.1
Host: acmecorp.com
Cookie: JSESSIONID=58A01F5D7E9CB6852E5B4C10B32B49B5
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...

```

Anyone who can capture this HTTP request can extract the session identifier and use it to impersonate the user. The attack is particularly dangerous because:

1. It's passive - no active interference with the victim's connection is required beyond capturing traffic.
2. It's undetectable to the victim - their session continues to function normally.
3. It bypasses even strong authentication methods - once authenticated, only the cookie matters.

The vulnerability was confirmed in the staging environment where HTTPS was implemented, but cookies were still transmitted over both HTTP and HTTPS channels, demonstrating that the application has the infrastructure for secure communication but isn't properly configuring cookie security.

# Remediation Steps
## Set Secure Flag on Authentication Cookies

**Priority**: P0

Immediately modify all code that creates authentication cookies to include the 'secure' flag:

```java
// Corrected implementation
Cookie sessionCookie = new Cookie("JSESSIONID", sessionId);
sessionCookie.setSecure(true);  // Add this line to set the secure flag
response.addCookie(sessionCookie);

```

If you're using a framework or configuration-based approach, you may need to update configuration files instead. For Tomcat specifically, you can enforce secure cookies for all sessions by adding this to your web.xml:

```xml
<session-config>
    <cookie-config>
        <secure>true</secure>
    </cookie-config>
</session-config>

```

Additionally, for Spring-based applications, you can configure it in your SecurityConfig class:

```java
http.sessionManagement()
    .sessionFixation().migrateSession()
    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
    .and()
    .securityContext().requireExplicitSave(false)
    .and()
    .servletApi().servletSecurityContextRepository(this::getSecurityContextRepository);

```
## Implement HTTP Strict Transport Security (HSTS)

**Priority**: P1

Configure HSTS to instruct browsers to only connect to your application over HTTPS, even if the user specifies HTTP in the URL. This provides an additional layer of protection beyond the secure cookie flag.

Add the following HTTP header to all responses:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains

```

In a Java servlet application, you can add this in a filter:

```java
public class HstsFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) 
            throws IOException, ServletException {
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        httpResponse.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        chain.doFilter(request, response);
    }
    // Other required methods omitted for brevity
}

```

For Tomcat, you can also configure it in the server.xml file:

```xml
<Connector port="8443" protocol="HTTP/1.1" SSLEnabled="true"
    maxThreads="150" scheme="https" secure="true"
    clientAuth="false" sslProtocol="TLS">
    <UpgradeProtocol className="org.apache.coyote.http2.Http2Protocol" />
    <Header name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
</Connector>

```


# References
* CWE-614 | [Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)
* A05:2021 | [Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
* A02:2021 | [Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
* CWE-311 | [Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)
* ASVS-3.4.1 | [OWASP ASVS v4.0 - Verify that cookies have the 'Secure' attribute set](https://owasp.org/www-project-application-security-verification-standard/)
