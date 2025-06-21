# Insecure Redirect in Nginx Configuration Due to Missing HTTPS Scheme

# Vulnerability Case
During the security assessment of Acme Corp's web application, we identified an insecure redirect in the Nginx configuration used to manage incoming HTTP requests. The configuration omits an explicit HTTPS scheme in its redirection rules, causing Nginx to forward requests using the original protocol. This was discovered while reviewing configuration files and log traces, which revealed that clients initially connecting via HTTP were redirected without enforcing encrypted communication. The finding was observed in an environment running Nginx 1.18 on Docker containers deployed in an AWS EC2 instance.

```nginx
server {
  listen 80;
  server_name acme-corp.com;

  location /old-ui {
    # Insecure redirect: No https scheme specified.
    return 301 acme-corp.com$request_uri;
  }
}
```

Without an explicit HTTPS scheme in the redirect location, Nginx uses the incoming request's scheme, meaning that if a client requests the site over HTTP, it will be redirected using HTTP rather than HTTPS. An attacker could exploit this behavior by intercepting or downgrading the initial HTTP request, initiating a man-in-the-middle (MitM) attack to capture sensitive data such as session cookies or credentials. The business impact is significant as this vulnerability undermines data confidentiality during transit, violates compliance mandates for secure communications, and erodes customer trust in Acme Corp's security infrastructure.


context: generic.nginx.security.insecure-redirect.insecure-redirect Detected an insecure redirect in this nginx configuration. If no scheme is specified, nginx will forward the request with the incoming scheme. This could result in unencrypted communications. To fix this, include the 'https' scheme.

# Vulnerability Breakdown
This vulnerability involves an improper Nginx configuration that fails to enforce HTTPS when redirecting users, potentially exposing sensitive data to interception.

1. **Key vulnerability elements**:
   - Nginx configuration that redirects requests without specifying the HTTPS scheme
   - Port 80 (HTTP) listener that fails to upgrade connections to secure protocol
   - Use of relative URL in the redirect destination (`acme-corp.com$request_uri`)
   - Running on Nginx 1.18 in a Docker container on AWS EC2

2. **Potential attack vectors**:
   - Man-in-the-Middle (MitM) attacks intercepting initial HTTP traffic
   - SSL stripping attacks that force downgrades from HTTPS to HTTP
   - Network-level eavesdropping on unencrypted communications
   - Targeted attacks against users on insecure networks (public WiFi)

3. **Severity assessment**:
   - Primarily impacts confidentiality through potential data exposure
   - Requires user interaction (visiting HTTP version of site)
   - Network-accessible vulnerability increases exposure
   - Low complexity to exploit with readily available MitM tools

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): Required (R) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): Low (L) 
   - Integrity (I): None (N) 
   - Availability (A): None (N) 

# Description
An insecure redirect vulnerability exists in Acme Corp's Nginx configuration (version 1.18) running in Docker containers on AWS EC2. The configuration fails to specify the HTTPS scheme when redirecting users from the `/old-ui` path, causing the web server to maintain the original protocol used by the client.

```nginx
server {
  listen 80;
  server_name acme-corp.com;
  location /old-ui {
    # Insecure redirect: No https scheme specified.
    return 301 acme-corp.com$request_uri;
  }
}

```

When a user accesses the site via HTTP, the redirect maintains the insecure HTTP protocol instead of upgrading to HTTPS. This creates an opportunity for man-in-the-middle attacks where malicious actors can intercept network traffic, potentially capturing sensitive information such as session cookies, authentication credentials, or personal data. The vulnerability undermines transport layer security and violates security best practices that mandate encryption for all web traffic.

# CVSS
**Score**: 4.2 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N \
**Severity**: Medium

This vulnerability receives a Medium severity rating (CVSS score 4.2) based on the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability is exploitable remotely by anyone who can intercept network traffic.
- **Low Attack Complexity (AC:L)**: Exploitation requires no specialized conditions and can be accomplished with common attack tools like packet sniffers or proxy tools.
- **No Privileges Required (PR:N)**: An attacker needs no specific privileges on either the client or server to exploit this vulnerability.
- **User Interaction Required (UI:R)**: A user must visit the HTTP version of the site for the vulnerability to be exploitable. This slightly reduces the severity.
- **Unchanged Scope (S:U)**: The vulnerability affects only the component that contains it (web traffic).
- **Low Confidentiality Impact (C:L)**: The vulnerability allows limited information disclosure through potential MitM attacks.
- **No Integrity Impact (I:N)**: The vulnerability doesn't directly compromise data integrity.
- **No Availability Impact (A:N)**: The vulnerability doesn't affect system availability.

While the technical complexity of exploitation is low, the actual impact is limited to specific scenarios where users access the HTTP version of the site and attackers are positioned to intercept that traffic. This combination of factors results in the Medium severity rating.

# Exploitation Scenarios
**Scenario 1: Man-in-the-Middle Attack on Public WiFi**
A malicious actor sets up a rogue access point at a coffee shop, creating a WiFi network named similarly to the legitimate network. When a victim connects to this network and visits acme-corp.com by typing the URL without explicitly specifying https://, their browser makes an initial HTTP request. The Nginx server responds with a 301 redirect that maintains HTTP instead of upgrading to HTTPS. The attacker, controlling the network path, can intercept this unencrypted traffic and capture sensitive information such as session cookies, potentially allowing them to hijack the user's authenticated session.

**Scenario 2: Network-Level Interception by ISP or State Actor**
A state-sponsored actor with access to Internet Service Provider infrastructure monitors network traffic for users accessing certain domains. When a user visits acme-corp.com/old-ui via HTTP, the redirect remains on HTTP due to the misconfiguration. The unencrypted nature of the connection allows the actor to passively collect user data, session information, and potentially sensitive business information that would otherwise be protected by HTTPS encryption.

**Scenario 3: SSL Stripping Attack**
An attacker using tools like SSLstrip positions themselves between users and the Acme Corp website. The tool actively intercepts HTTPS requests and converts them to HTTP. When the user's traffic reaches the Nginx server via HTTP, the server's misconfigured redirect maintains the HTTP protocol. The attacker can then continue monitoring the entire session in plaintext, even if the user originally intended to use HTTPS, because the server never forces an upgrade to the secure protocol.

# Impact Analysis
**Business Impact:**
- Potential exposure of sensitive customer data could lead to regulatory violations under frameworks like GDPR, CCPA, or industry-specific regulations
- Loss of customer trust if security incidents occur due to this vulnerability
- Possible breach disclosure requirements if sensitive data is compromised
- Legal liability for failing to implement standard security practices for data in transit
- Non-compliance with security standards like PCI-DSS that mandate encryption of payment-related traffic
- Reputational damage if the vulnerability is publicly disclosed or exploited

**Technical Impact:**
- Exposure of session cookies enabling session hijacking and unauthorized account access
- Potential credential theft if login forms are submitted over an unencrypted connection
- Undermining of other security controls that rely on transport layer security
- Interception of sensitive data transmitted between client and server
- Bypassing of content security policies or other browser security mechanisms
- Potential for persistent man-in-the-middle positioning due to cached insecure redirects
- Invalidation of security guarantees provided by HTTPS such as data integrity and server authentication

# Technical Details
The vulnerability is caused by an improper redirect configuration in Nginx that fails to specify the protocol scheme (HTTP or HTTPS) in the redirection URL. When no scheme is specified, Nginx defaults to using the scheme of the incoming request.

In the vulnerable configuration:

```nginx
server {
  listen 80;
  server_name acme-corp.com;
  location /old-ui {
    # Insecure redirect: No https scheme specified.
    return 301 acme-corp.com$request_uri;
  }
}

```

The `return 301 acme-corp.com$request_uri;` directive creates a 301 (Permanent Redirect) response, but the redirection URL lacks the `https://` prefix. This means:

1. When a user accesses `http://acme-corp.com/old-ui`, the server returns a redirect to `http://acme-corp.com/old-ui` (maintaining HTTP)
2. When a user accesses `https://acme-corp.com/old-ui`, the server returns a redirect to `https://acme-corp.com/old-ui` (maintaining HTTPS)

The preservation of the HTTP scheme in the first case creates the security vulnerability. A proper implementation should always redirect to HTTPS regardless of the incoming protocol.

The vulnerability is exploitable because:

1. Many users may access the site by typing the domain name without explicitly specifying `https://`
2. Search engine links, bookmarks, or external references might use HTTP URLs
3. Attackers can force HTTP connections through various techniques like DNS poisoning

The attack vector is significant because it enables passive monitoring of supposedly secure communications. Unlike many web vulnerabilities that require active exploitation, this one allows attackers to simply observe traffic that should have been encrypted but remains in plaintext due to the misconfiguration.

# Remediation Steps
## Specify HTTPS Scheme in Redirect URLs

**Priority**: P0

Modify the Nginx configuration to explicitly specify the HTTPS scheme in all redirect URLs:

```nginx
server {
  listen 80;
  server_name acme-corp.com;
  location /old-ui {
    # Secure redirect with explicit https scheme
    return 301 https://acme-corp.com$request_uri;
  }
}

```

This ensures that all HTTP requests are upgraded to HTTPS during the redirect, regardless of the original protocol used by the client. The explicit `https://` prefix forces browsers to establish a secure connection for the redirected request.
## Implement HTTP Strict Transport Security (HSTS)

**Priority**: P1

Add HSTS headers to force browsers to always use HTTPS for future connections to the domain:

```nginx
server {
  listen 443 ssl;
  server_name acme-corp.com;
  
  # SSL configuration
  ssl_certificate /path/to/certificate.crt;
  ssl_certificate_key /path/to/private.key;
  
  # HSTS configuration (6 months, include subdomains)
  add_header Strict-Transport-Security "max-age=15768000; includeSubDomains" always;
  
  # Your other server configuration...
  
  location /old-ui {
    # Other configuration as needed
  }
}

server {
  listen 80;
  server_name acme-corp.com;
  
  # Redirect all HTTP traffic to HTTPS
  return 301 https://$host$request_uri;
}

```

HTST instructs browsers to always use HTTPS for future requests to the domain, even if the user types an HTTP URL. This provides an additional layer of protection against protocol downgrade attacks. The `max-age` parameter (in seconds) determines how long browsers should remember to use HTTPS for the domain.


# References
* CWE-319 | [Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
* A05:2021 | [Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
* CWE-350 | [Reliance on Reverse DNS Resolution for a Security-Critical Action](https://cwe.mitre.org/data/definitions/350.html)
* A07:2021 | [Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
