# H2C Smuggling in Nginx Reverse Proxy

# Vulnerability Case
During a routine assessment of Acme Corp's externally exposed Nginx reverse proxies, we identified conditions that could allow H2C smuggling. Our analysis revealed that certain proxy configurations were forwarding HTTP/1.1 Upgrade headers without strict validation, permitting requests with an Upgrade value of `h2c` rather than the mandatory `websocket` value. This misconfiguration was discovered by crafting and sending nonstandard HTTP requests during our testing phase, where malformed headers led to an unintended upgrade to HTTP/2 on cleartext channels. As a result, an attacker might bypass reverse proxy access controls, establishing a long-lived HTTP session directly with the back-end server.

```plaintext
# Example vulnerable request scenario:
GET / HTTP/1.1
Host: vulnerable.acme-corp.com
Connection: Upgrade, HTTP2-Settings
Upgrade: h2c
HTTP2-Settings: AAMAAABkAAQAAP__
```

In a typical production environment, Acme Corp utilizes Nginx (e.g., version 1.18) configured as a reverse proxy for backend services on Linux-based infrastructure. The vulnerability arises when the proxy does not filter out non-WebSocket Upgrade headers, allowing an attacker to inject an `Upgrade: h2c` header. Exploitation methods include sending specially crafted HTTP/1.1 requests that trigger a protocol switch, thereby bypassing standard reverse proxy security controls. This can lead to unauthorized direct access to backend servers, establish persistent sessions, and potentially facilitate lateral movement or data exfiltration, thereby degrading the overall network security posture.


context: generic.nginx.security.possible-h2c-smuggling.possible-nginx-h2c-smuggling Conditions for Nginx H2C smuggling identified. H2C smuggling allows upgrading HTTP/1.1 connections to lesser-known HTTP/2 over cleartext (h2c) connections which can allow a bypass of reverse proxy access controls, and lead to long-lived, unrestricted HTTP traffic directly to back-end servers. To mitigate: WebSocket support required: Allow only the value websocket for HTTP/1.1 upgrade headers (e.g., Upgrade: websocket). WebSocket support not required: Do not forward Upgrade headers.

# Vulnerability Breakdown
This vulnerability involves Nginx reverse proxies improperly handling HTTP protocol upgrade headers, allowing attackers to establish HTTP/2 cleartext (H2C) connections directly to backend servers.

1. **Key vulnerability elements**:
   - Nginx reverse proxies forwarding HTTP/1.1 Upgrade headers without proper validation
   - Acceptance of `Upgrade: h2c` headers instead of restricting to only `websocket` value
   - Ability to bypass access controls by establishing direct HTTP/2 connections to backend servers
   - Affects exposed Nginx (v1.18) reverse proxies on Linux-based infrastructure

2. **Potential attack vectors**:
   - Sending specially crafted HTTP/1.1 requests with `Upgrade: h2c` header
   - Establishing long-lived HTTP/2 cleartext connections that bypass proxy security controls
   - Creating direct connections to backend services that should not be externally accessible
   - Using the smuggled connection for lateral movement or data exfiltration

3. **Severity assessment**:
   - Network-based attack vector (externally exploitable)
   - Low complexity exploitation requiring basic HTTP request manipulation
   - No privileges or user interaction needed
   - Changes security scope by breaking proxy security boundary
   - Impacts confidentiality and integrity through bypass of security controls

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Changed (C)
   - Confidentiality (C): Low (L) 
   - Integrity (I): Low (L) 
   - Availability (A): None (N) 

# Description
A security vulnerability was identified in Acme Corp's externally exposed Nginx reverse proxies where improper handling of HTTP/1.1 Upgrade headers enables H2C (HTTP/2 Cleartext) smuggling attacks. The misconfiguration allows HTTP/1.1 requests containing `Upgrade: h2c` headers to be forwarded to backend servers instead of strictly validating that only `Upgrade: websocket` headers are permitted.

When exploited, this vulnerability allows attackers to bypass the reverse proxy's security controls by establishing a direct HTTP/2 cleartext connection with backend servers that would normally be protected. The vulnerability essentially breaks the security boundary that the reverse proxy is designed to enforce, potentially exposing sensitive internal services to unauthorized access.

```plaintext
# Example attack request:
GET / HTTP/1.1
Host: vulnerable.acme-corp.com
Connection: Upgrade, HTTP2-Settings
Upgrade: h2c
HTTP2-Settings: AAMAAABkAAQAAP__

```

This vulnerability affects Nginx (version 1.18) reverse proxies on Linux-based infrastructure and could lead to unauthorized access to backend servers, persistent connections for data exfiltration, and potential lateral movement within the internal network.

# CVSS
**Score**: 7.2 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N \
**Severity**: High

The High severity rating (7.2) is justified by the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely over the internet since it affects externally exposed Nginx reverse proxies.

- **Low Attack Complexity (AC:L)**: Exploitation is straightforward and doesn't require special conditions or timing. An attacker only needs to send a specially crafted HTTP/1.1 request with the appropriate headers.

- **No Privileges Required (PR:N)**: The attack can be performed without any authentication or privileges - any client can send the malicious request.

- **No User Interaction (UI:N)**: The vulnerability can be exploited without requiring actions from users or administrators.

- **Changed Scope (S:C)**: The vulnerability in the Nginx reverse proxy (one security authority) affects backend servers (a different security authority). This breaks the intended security boundary between internet-facing and internal services.

- **Low Confidentiality Impact (C:L)**: While the vulnerability enables unauthorized access to backend servers, the direct impact on confidentiality is limited to the information that can be accessed through the established connection.

- **Low Integrity Impact (I:L)**: The vulnerability allows sending requests that would normally be blocked, potentially bypassing request filtering, but doesn't directly enable high-impact data modification.

- **No Availability Impact (A:N)**: The vulnerability doesn't directly affect system availability or cause denial of service conditions.

The score falls in the High range primarily due to the Changed Scope factor, reflecting how this vulnerability bypasses a critical security boundary in the network architecture.

# Exploitation Scenarios
**Scenario 1: Security Control Bypass**
An attacker sends an HTTP/1.1 request to the exposed Nginx reverse proxy with the headers `Connection: Upgrade, HTTP2-Settings` and `Upgrade: h2c`. The proxy forwards these headers to the backend server, which accepts the protocol upgrade request and establishes a direct HTTP/2 cleartext connection with the attacker. This connection bypasses security controls that the reverse proxy would normally enforce, such as Web Application Firewall (WAF) rules, rate limiting, or IP restrictions. The attacker can now directly interact with the backend server, potentially exploiting vulnerabilities that would normally be blocked by the proxy's security mechanisms.

**Scenario 2: Internal Service Access**
After establishing a direct HTTP/2 connection to a backend server through H2C smuggling, an attacker discovers that the backend server has access to internal services not directly exposed to the internet. The attacker leverages the backend server as a pivot point to send requests to these internal services, accessing sensitive internal APIs, databases, or administrative interfaces that should never be reachable from external networks.

**Scenario 3: Persistent Data Exfiltration**
An attacker exploits the H2C smuggling vulnerability to establish a long-lived HTTP/2 connection with a backend application server. Unlike typical HTTP/1.1 connections that might be more closely monitored or terminated after periods of inactivity, this connection remains open for an extended period. The attacker uses this persistent channel to slowly exfiltrate sensitive data from the backend server, keeping data transfer rates low to avoid triggering anomaly detection systems. Since the connection bypasses the reverse proxy's logging and monitoring controls, the data exfiltration goes undetected.

# Impact Analysis
**Business Impact:**
- Breach of security perimeter, exposing internal systems to direct external access
- Potential unauthorized access to sensitive customer or business data
- Regulatory compliance violations if protected data is exposed
- Reputational damage if a breach is made public
- Loss of confidence in the organization's security posture
- Financial impact from incident response, forensic investigation, and potential penalties
- Possible intellectual property theft or corporate espionage

**Technical Impact:**
- Circumvention of reverse proxy security controls, including WAF rules, rate limiting, and IP filtering
- Establishment of direct, potentially long-lived connections to backend servers
- Ability to send malicious requests that would normally be filtered or blocked
- Potential access to internal services that should not be directly accessible
- Bypass of security monitoring and logging implemented at the proxy level
- Increased attack surface by exposing backend server vulnerabilities
- Possible lateral movement within the internal network from an initial foothold
- Difficulty detecting the attack as connections may appear legitimate to backend systems

# Technical Details
The H2C smuggling vulnerability exists due to improper handling of HTTP/1.1 Upgrade headers in Nginx reverse proxy configurations. HTTP/2 can be established in two ways: over TLS (h2) or over cleartext (h2c). While h2 is commonly used and secure, h2c should generally not be exposed to untrusted networks.

Nginx reverse proxies are commonly configured to handle WebSocket connections by forwarding the `Upgrade` header. However, when this configuration doesn't explicitly restrict the `Upgrade` header value to only `websocket`, it can be exploited for protocol smuggling:

```nginx
# Vulnerable Nginx configuration
server {
    listen 80;
    server_name vulnerable.acme-corp.com;

    location / {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        
        # The vulnerability: forwarding all Upgrade headers without restriction
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

```

The exploitation process works as follows:

1. The attacker sends an HTTP/1.1 request to the Nginx reverse proxy with the following headers:

```plaintext
GET / HTTP/1.1
Host: vulnerable.acme-corp.com
Connection: Upgrade, HTTP2-Settings
Upgrade: h2c
HTTP2-Settings: AAMAAABkAAQAAP__

```

2. The Nginx reverse proxy forwards this request to the backend server, including the `Upgrade: h2c` header.

3. If the backend server supports HTTP/2 (many modern web servers do), it interprets this as a valid protocol upgrade request and responds with:

```plaintext
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: h2c

```

4. The backend server and the attacker then establish a direct HTTP/2 cleartext connection, effectively bypassing the reverse proxy's security controls for subsequent communications.

The key technical issue is that the reverse proxy is still operating under HTTP/1.1 rules and doesn't interpret or filter the protocol upgrade - it merely passes it through. Once the backend server accepts the upgrade, the communication channel effectively bypasses the security controls the reverse proxy would normally enforce.

# Remediation Steps
## Restrict HTTP Upgrade Header Processing

**Priority**: P0

If WebSocket support is required, explicitly restrict the Upgrade header to only allow the "websocket" value:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        
        # Only allow websocket upgrades, block h2c
        if ($http_upgrade != "websocket" ) {
            set $http_upgrade "";
        }
        
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

```

If WebSocket support is not required, completely block forwarding of the Upgrade header:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://backend;
        
        # Do not forward Upgrade headers at all
        proxy_set_header Upgrade "";
    }
}

```

This change prevents attackers from initiating a protocol upgrade to HTTP/2 cleartext (h2c) through the reverse proxy.
## Implement HTTP/2 Securely

**Priority**: P1

If HTTP/2 is required between clients and your services, implement it securely over TLS (h2) instead of cleartext (h2c):

```nginx
server {
    listen 443 ssl http2;  # Enable HTTP/2 over TLS
    server_name your-domain.com;
    
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    
    # Modern TLS configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    
    location / {
        proxy_pass http://backend;
        
        # Other proxy headers as needed
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}

```

This configuration ensures that HTTP/2 is only available over secure TLS connections (h2), while preventing cleartext HTTP/2 (h2c) connections. The HTTP/2 protocol is enabled at the server level with the `http2` parameter in the listen directive, but it's enforced to only work over TLS.


# References
* CWE-16 | [Configuration](https://cwe.mitre.org/data/definitions/16.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* CWE-441 | [Unintended Proxy or Intermediary ('Confused Deputy')](https://cwe.mitre.org/data/definitions/441.html)
* A05:2021 | [Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
* A01:2021 | [Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
