# HTTP Response Splitting via NGINX Header Injection

# Vulnerability Case
During our assessment of Acme Corp's web infrastructure, we discovered a header injection vulnerability in the NGINX configuration that handles dynamic URL path parameters. Specifically, the implementation directly injects the unsanitized `$$VARIABLE` captured from the path into an HTTP response header, without ensuring that whitespace or newline characters are absent. This flaw, identified during targeted fuzzing of the endpoint, enables an attacker to craft a malicious request that includes newline characters to split the HTTP response. Running on a Linux-based stack with NGINX 1.18.0 on Ubuntu, this vulnerability poses significant risks such as cache poisoning, cross-site scripting, and potential bypass of security controls, thereby impacting business operations and user trust.

```nginx
server {
  listen 80;
  server_name acme.example.com;

  location /api/resource/ {
    # Capture dynamic URL segment from the request path
    if ($uri ~ "^/api/resource/([^/]+)") {
      set $dynamic_param $1;
    }
    # Vulnerability: The unsanitized parameter is directly used in the header
    add_header X-Dynamic-Value "$dynamic_param";
    proxy_pass http://backend_service;
  }
}
```

An attacker can exploit this vulnerability by injecting newline characters (e.g., `%0d%0a`) in the URL path parameter to manipulate the HTTP response headers, leading to HTTP response splitting. By appending a crafted value such as `malicious%0d%0aX-Injected-Header: injected` the attacker can force the server to include an additional header of their choosing. This technique may allow for subsequent attacks such as cache poisoning, cross-site scripting, or even modification of client-side behaviors, all of which can severely compromise the integrity of web sessions and the overall business environment.


context: generic.nginx.security.header-injection.header-injection The $$VARIABLE path parameter is added as a header in the response. This could allow an attacker to inject a newline and add a new header into the response. This is called HTTP response splitting. To fix, do not allow whitespace in the path parameter: '[^\s]+'.

# Vulnerability Breakdown
This vulnerability involves the improper handling of unsanitized user input in NGINX configuration where dynamic URL path parameters are directly included in response headers without validation.

1. **Key vulnerability elements**:
   - Dynamic path parameter (`$dynamic_param`) captured from URL using regex
   - Direct inclusion of unsanitized parameter in `X-Dynamic-Value` response header
   - No validation to prevent newline characters (CRLF sequences - CR: carriage return, LF: line feed)
   - Running on Linux with NGINX 1.18.0 in production environment

2. **Potential attack vectors**:
   - Injection of CRLF sequences (`%0d%0a` URL-encoded) to split HTTP responses
   - Insertion of arbitrary HTTP headers into server responses
   - Cache poisoning attacks affecting multiple users
   - Cross-site scripting through header manipulation
   - Security control bypass by injecting headers that modify browser security settings

3. **Severity assessment**:
   - Network-accessible (remotely exploitable)
   - Low complexity to exploit
   - No privileges required
   - No user interaction needed
   - Primarily impacts integrity and potentially confidentiality
   - Enables additional attack vectors like cache poisoning

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): Low (L) 
   - Integrity (I): Low (L) 
   - Availability (A): None (N) 

# Description
A header injection vulnerability exists in Acme Corp's NGINX configuration that handles dynamic URL path parameters. The implementation directly injects unsanitized variables captured from the path into HTTP response headers, without checking for whitespace or newline characters.

The vulnerable configuration extracts a path segment using a regular expression and adds it as an `X-Dynamic-Value` header without validation:

```nginx
server {
  listen 80;
  server_name acme.example.com;

  location /api/resource/ {
    # Capture dynamic URL segment from the request path
    if ($uri ~ "^/api/resource/([^/]+)") {
      set $dynamic_param $1;
    }
    # Vulnerability: The unsanitized parameter is directly used in the header
    add_header X-Dynamic-Value "$dynamic_param";
    proxy_pass http://backend_service;
  }
}

```

This vulnerability allows attackers to inject newline characters (CRLF sequences) into response headers, leading to HTTP response splitting. An attacker can craft a malicious URL path containing encoded newlines (`%0d%0a`) to insert additional headers into the response, potentially enabling cache poisoning, cross-site scripting, and security control bypasses.

# CVSS
**Score**: 6.4 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N \
**Severity**: Medium

The vulnerability receives a Medium severity rating (CVSS score 6.4) based on the following factors:

- **Attack Vector (Network)**: The vulnerability is remotely exploitable by anyone who can send HTTP requests to the server.

- **Attack Complexity (Low)**: Exploitation is straightforward and requires no special conditions or timing. An attacker only needs to craft a URL with encoded CRLF characters.

- **Privileges Required (None)**: No authentication or authorization is needed to exploit the vulnerability.

- **User Interaction (None)**: Exploitation doesn't require any action from a user or administrator.

- **Scope (Unchanged)**: The vulnerability doesn't allow the attacker to affect resources beyond the vulnerable component's security scope.

- **Confidentiality (Low)**: While the vulnerability itself doesn't directly expose sensitive data, manipulating headers could potentially lead to information disclosure through advanced techniques like cache poisoning.

- **Integrity (Low)**: The attacker can modify response headers, which affects the integrity of the HTTP response. This could lead to cache poisoning or security control manipulation.

- **Availability (None)**: The vulnerability doesn't directly impact the availability of the system.

# Exploitation Scenarios
**Scenario 1: Basic Header Injection**
An attacker constructs a malicious URL with encoded CRLF characters:

```
https://acme.example.com/api/resource/legitimate-value%0d%0aX-Injected-Header:%20malicious-value

```

When processed by the server, this generates a response with the following headers:

```
HTTP/1.1 200 OK
...
X-Dynamic-Value: legitimate-value
X-Injected-Header: malicious-value
...

```

The attacker has successfully injected a custom header into the response.

**Scenario 2: Cache Poisoning Attack**
The attacker targets a popular resource and manipulates the response headers to poison a shared cache:

```
https://acme.example.com/api/resource/popular-item%0d%0aCache-Control:%20public,%20max-age=31536000

```

If this response is cached by an intermediate proxy or CDN, subsequent legitimate users requesting `/api/resource/popular-item` may receive the manipulated response for an extended period (1 year), even if the application logic or content changes.

**Scenario 3: Cross-Site Scripting via Set-Cookie**
The attacker injects a malicious cookie that contains JavaScript:

```
https://acme.example.com/api/resource/normal-value%0d%0aSet-Cookie:%20session=document.cookie;SameSite=None;path=/

```

This forces the victim's browser to set a cookie that, when processed by certain vulnerable applications, could lead to cookie theft or other client-side attacks.

**Scenario 4: Security Control Bypass**
The attacker disables browser XSS protections by injecting the X-XSS-Protection header:

```
https://acme.example.com/api/resource/data%0d%0aX-XSS-Protection:%200

```

This makes the browser more vulnerable to any XSS vulnerabilities that might exist in the application, potentially allowing the attacker to execute malicious scripts that would otherwise be blocked.

# Impact Analysis
**Business Impact:**
- Potential brand and reputation damage if cache poisoning affects multiple users
- Increased security risk to users whose browsers receive manipulated security headers
- Possible regulatory compliance issues if the vulnerability leads to data breaches
- Loss of user trust if security is compromised
- Resources required for incident response and remediation
- Potential business disruption if critical services are affected

**Technical Impact:**
- HTTP response manipulation allowing insertion of arbitrary headers
- Cache poisoning that could affect multiple users over extended periods
- Bypassing of browser security controls like Content-Security-Policy or X-XSS-Protection
- Potential cross-site scripting attacks via header manipulation
- Cookie injection or manipulation affecting user sessions
- Possible information disclosure through carefully crafted responses
- Undermining of security assumptions in downstream systems
- Potential for more sophisticated attacks using this vulnerability as an entry point

# Technical Details
The vulnerability exists in the NGINX configuration where a dynamic parameter from the URL path is extracted and directly inserted into an HTTP response header without sanitization.

```nginx
# Vulnerable NGINX Configuration
server {
  listen 80;
  server_name acme.example.com;

  location /api/resource/ {
    # Capture dynamic URL segment from the request path
    if ($uri ~ "^/api/resource/([^/]+)") {
      set $dynamic_param $1;
    }
    # Vulnerability: The unsanitized parameter is directly used in the header
    add_header X-Dynamic-Value "$dynamic_param";
    proxy_pass http://backend_service;
  }
}

```

**Vulnerability Mechanics:**

The critical issue is in the regex pattern `([^/]+)`, which captures any character except a forward slash. This pattern doesn't exclude control characters like CR (carriage return, `\r`, hex `0x0D`) and LF (line feed, `\n`, hex `0x0A`).

In HTTP, headers are separated by CRLF sequences (`\r\n`). When a user-controlled value containing CRLF is inserted into a header, it effectively ends that header and starts a new one, allowing header injection.

**HTTP Response Structure:**

A typical HTTP response has this structure:
```
HTTP/1.1 200 OK\r\n
Content-Type: text/html\r\n
X-Dynamic-Value: some-value\r\n
\r\n
<html>...</html>

```

When the vulnerability is exploited with a URL like `/api/resource/value%0D%0AX-Injected:%20malicious`, the resulting response becomes:

```
HTTP/1.1 200 OK\r\n
Content-Type: text/html\r\n
X-Dynamic-Value: value\r\n
X-Injected: malicious\r\n
\r\n
<html>...</html>

```

**Exploitation Techniques:**

1. **URL Encoding**: CRLF sequences are encoded in URLs as `%0D%0A`

2. **Detection**: Attackers can test for this vulnerability by injecting a unique header and checking if it appears in the response

3. **Advanced Attacks**: Beyond simple header injection, sophisticated attacks include:
   - Injecting multiple headers by chaining CRLF sequences
   - Setting sensitive headers like Content-Security-Policy
   - Injecting a complete second response with its own status line and body

**Impact Factors:**

- Proxy servers and caching mechanisms may normalize or filter headers, sometimes mitigating but sometimes amplifying the impact
- Modern browsers have some built-in protections against certain header-based attacks
- The specific impact varies based on the application architecture and how responses are processed

# Remediation Steps
## Sanitize URL Path Parameters

**Priority**: P0

Modify the NGINX configuration to reject whitespace and control characters in the path parameter:

```nginx
server {
  listen 80;
  server_name acme.example.com;

  location /api/resource/ {
    # Updated regex to exclude whitespace characters and control characters
    if ($uri ~ "^/api/resource/([^\s/]+)") {
      set $dynamic_param $1;
    }
    # Only add the header if the parameter was properly set (no whitespace/control chars)
    if ($dynamic_param) {
      add_header X-Dynamic-Value "$dynamic_param";
    }
    proxy_pass http://backend_service;
  }
}

```

The key change is in the regular expression pattern, which now explicitly excludes whitespace characters (`\s`). This prevents CRLF injection by rejecting any requests with control characters in the path parameter.

Also, by checking if `$dynamic_param` is set before adding the header, you ensure that only properly validated parameters are included in responses.
## Implement Additional Security Headers

**Priority**: P1

Add security headers to improve overall application security and reduce the impact of potential attacks:

```nginx
server {
  listen 80;
  server_name acme.example.com;

  # Set security headers for all responses
  add_header Content-Security-Policy "default-src 'self';" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header X-Frame-Options "SAMEORIGIN" always;
  add_header X-XSS-Protection "1; mode=block" always;

  location /api/resource/ {
    # Sanitized path parameter capture
    if ($uri ~ "^/api/resource/([^\s/]+)") {
      set $dynamic_param $1;
    }
    if ($dynamic_param) {
      add_header X-Dynamic-Value "$dynamic_param";
    }
    proxy_pass http://backend_service;
  }
}

```

The `always` parameter ensures these headers are added to all responses, including error pages. These headers provide defense-in-depth by:

1. `Content-Security-Policy`: Restricts sources from which content can be loaded
2. `X-Content-Type-Options`: Prevents MIME type sniffing
3. `X-Frame-Options`: Prevents clickjacking attacks
4. `X-XSS-Protection`: Enables browser's built-in XSS filters

These mitigations help limit the impact of various attacks, including those that might be enabled by header injection.


# References
* CWE-113 | [Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')](https://cwe.mitre.org/data/definitions/113.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* A05:2021 | [Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
* ngx_http_headers_module | [NGINX Documentation on HTTP Headers Module](https://nginx.org/en/docs/http/ngx_http_headers_module.html)
