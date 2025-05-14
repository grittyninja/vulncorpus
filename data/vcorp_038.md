# Server-Side Request Forgery (SSRF) in Go Gin Web Application

# Vulnerability Case
During an assessment of Acme Corp's Go-based Gin web application handling dynamic URL requests, an SSRF issue was identified. The vulnerability was discovered when untrusted user input was directly concatenated with a base HTTP URL, allowing attackers to manipulate the destination host. This misconfiguration enables the application to act as a proxy and forward requests to unintended internal or external endpoints. In our tests, supplied parameters led to connections with internal administrative interfaces, highlighting potential exposure of sensitive systems. Such behavior was confirmed via controlled tests using crafted query parameters during routine penetration testing.

```go
package main

import (
    "io/ioutil"
    "log"
    "net/http"

    "github.com/gin-gonic/gin"
)

func main() {
    router := gin.Default()

    // Vulnerable endpoint: constructs target URL using untrusted user input for host
    router.GET("/fetch", func(c *gin.Context) {
        // Untrusted input: host parameter
        host := c.Query("host")
        // SSRF vulnerability: direct concatenation of unvalidated user input
        targetURL := "http://" + host + "/admin"

        resp, err := http.Get(targetURL)
        if err != nil {
            log.Printf("Error fetching target URL: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
            return
        }
        defer resp.Body.Close()

        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
            log.Printf("Error reading response body: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read response"})
            return
        }
        c.Data(http.StatusOK, "text/plain", body)
    })

    router.Run(":8080")
}
```

The vulnerability lies in the direct inclusion of the `host` query parameter into the base URL without proper validation or sanitization, as implemented in a Gin (Go framework) service. An attacker can exploit this flaw by supplying a malicious host—such as an internal IP address or a hostname pointing to a sensitive service—leading to unauthorized internal network scanning or access to administrative endpoints. Furthermore, SSRF can be leveraged to pivot through trusted interfaces, potentially exposing sensitive configuration details or executing follow-on attacks. The business impact is significant: unauthorized disclosure of sensitive information, potential remote code execution, and lateral movement within Acme Corp's network, which can severely undermine the organizational security posture.


context: go.gin.ssrf.gin-tainted-url-host.gin-tainted-url-host Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

# Vulnerability Breakdown
This vulnerability involves a server-side request forgery (SSRF) issue in Acme Corp's Go-based Gin web application, which allows attackers to manipulate HTTP requests to access unauthorized internal or external endpoints.

1. **Key vulnerability elements**:
   - Direct concatenation of untrusted user input (`host` parameter) into a target URL
   - No validation or sanitization of user-supplied hostnames
   - Lack of allowlist or blocklist for permitted destinations
   - Hardcoded path (`/admin`) appended to all requests, exposing administrative interfaces
   - Unrestricted forwarding of responses back to the client

2. **Potential attack vectors**:
   - Accessing internal services by specifying localhost or internal IP addresses
   - Accessing cloud metadata services (e.g., `169.254.169.254` on AWS)
   - Port scanning internal networks by analyzing response differences
   - Leveraging DNS rebinding to bypass restrictions
   - Using alternate IP encoding schemes to bypass rudimentary filters

3. **Severity assessment**:
   - Significant confidentiality impact due to unauthorized information disclosure
   - Potential availability impact if requests target sensitive internal services
   - Remote exploitation via network
   - Low complexity to execute
   - No privileges or user interaction required

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Changed (C)
   - Confidentiality (C): High (H) 
   - Integrity (I): Low (L) 
   - Availability (A): Low (L) 

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L

# Description
A critical Server-Side Request Forgery (SSRF) vulnerability exists in Acme Corp's Go-based Gin web application that could allow attackers to send unauthorized HTTP requests to internal networks or external systems. The vulnerable endpoint `/fetch` directly concatenates an untrusted `host` parameter with a hardcoded HTTP scheme and `/admin` path without any validation or sanitization.

```go
targetURL := "http://" + host + "/admin"
resp, err := http.Get(targetURL)

```

This implementation allows attackers to manipulate the destination of the HTTP request by supplying malicious values for the `host` parameter. For example, an attacker could specify internal IP addresses, localhost, or domain names pointing to sensitive services. The application then forwards these requests, potentially exposing administrative interfaces, internal services, or restricted resources. Furthermore, the application returns the complete response body to the client, which may contain sensitive information not intended for public access.

# CVSS
**Score**: 9.9 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L \
**Severity**: Critical

The Critical severity rating (CVSS score 9.9) is justified by the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely over the internet without requiring local network access or physical proximity

- **Low Attack Complexity (AC:L)**: Exploitation is straightforward and reliable, requiring only a simple HTTP request with a manipulated host parameter

- **No Privileges Required (PR:N)**: An attacker does not need any authentication or authorization to exploit the vulnerability

- **No User Interaction (UI:N)**: Exploitation does not require actions from a user other than the attacker

- **Changed Scope (S:C)**: The vulnerability allows the attacker to access resources beyond the vulnerable component, affecting different security domains (internal systems not normally accessible from the internet)

- **High Confidentiality Impact (C:H)**: The vulnerability allows access to sensitive internal information, potentially including administrative interfaces, configuration data, and internal services

- **Low Integrity Impact (I:L)**: Limited ability to modify data through GET requests to internal services that don't properly validate the source

- **Low Availability Impact (A:L)**: The vulnerability could impact availability of internal services through malicious requests, though the impact is limited since the application only uses GET requests

# Exploitation Scenarios
**Scenario 1: Internal Network Scanning**
An attacker discovers the vulnerable endpoint and uses it to scan the internal network by creating requests such as:
```
GET /fetch?host=10.0.0.1
GET /fetch?host=10.0.0.2
...

```
By analyzing the differences in responses, the attacker maps out active hosts on the internal network and identifies potential targets for further attacks. The attacker specifically targets the `/admin` paths of these services, potentially discovering unsecured administrative interfaces.

**Scenario 2: Cloud Metadata Service Access**
The attacker targets the application's cloud provider metadata service by sending:
```
GET /fetch?host=169.254.169.254

```
This causes the application to connect to the cloud instance metadata service, which might return sensitive information including IAM credentials, user data, and cloud configuration. The attacker uses these credentials to further compromise cloud resources.

**Scenario 3: Internal Service Exploitation**
After mapping the internal network, the attacker identifies an internal Jenkins server running on 10.0.0.45 and sends:
```
GET /fetch?host=10.0.0.45:8080

```
The application forwards the request to the Jenkins server's administrative interface, revealing job configurations, build histories, and potentially allowing the execution of arbitrary commands if the Jenkins instance isn't properly secured. The attacker then uses this access to achieve remote code execution on the Jenkins server.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive internal information and systems
- Potential data breaches exposing customer information or intellectual property
- Compromise of additional systems through lateral movement
- Regulatory compliance violations if personal data is exposed
- Reputational damage and loss of customer trust
- Financial losses from remediation efforts, incident response, and potential legal consequences

**Technical Impact:**
- Exposure of internal network topology and services
- Access to administrative interfaces not intended for public access
- Potential for obtaining cloud provider credentials and sensitive configuration
- Ability to bypass network segmentation and security controls
- Access to internal services that assume requests from trusted sources
- Potential for service disruption if malicious requests overload internal systems
- Possible remote code execution if vulnerable internal services are accessed

# Technical Details
The vulnerability exists in the `/fetch` endpoint of Acme Corp's Go-based Gin web application. The vulnerable code directly concatenates the user-supplied `host` parameter with a fixed prefix and suffix to form a URL:

```go
router.GET("/fetch", func(c *gin.Context) {
    // Untrusted input: host parameter
    host := c.Query("host")
    // SSRF vulnerability: direct concatenation of unvalidated user input
    targetURL := "http://" + host + "/admin"
    resp, err := http.Get(targetURL)
    // ... response handling ...
})

```

**Exploitation Mechanics:**

1. **Input Manipulation**: The attacker controls the `host` parameter, which is directly inserted into the URL without validation

2. **Protocol Enforcement**: The application hardcodes "http://" as the protocol, which prevents protocol-based attacks like using "file://" but still allows network-based SSRF

3. **Path Restriction**: The code appends "/admin" to all requests, which narrows the attack to administrative interfaces but doesn't mitigate the core SSRF issue

4. **Response Forwarding**: The application reads the response body and returns it directly to the client, revealing sensitive information from internal services

5. **No Network Restrictions**: The application doesn't implement any network-level controls to prevent requests to internal IP ranges or sensitive domains

**Common Attack Patterns:**

1. **Internal IP targeting**:
   - `host=127.0.0.1` (localhost)
   - `host=10.0.0.1` (private network)
   - `host=192.168.1.1` (private network)
   - `host=169.254.169.254` (AWS metadata service)

2. **DNS rebinding**:
   - Using a domain that initially resolves to a benign IP but changes to an internal IP after initial security checks

3. **Non-standard representations**:
   - Decimal notation: `host=2130706433` (equivalent to 127.0.0.1)
   - Hexadecimal: `host=0x7f000001` (equivalent to 127.0.0.1)
   - Octal: `host=0177.0.0.01` (equivalent to 127.0.0.1)

4. **URL encoding/obfuscation**:
   - `host=127.0.0.1%09` (using URL-encoded tab character)
   - `host=localhost.%00.example.com` (using null byte)

The vulnerability is particularly dangerous because it can be used as a stepping stone for further attacks, allowing attackers to pivot through the vulnerable application to reach otherwise inaccessible internal systems.

# Remediation Steps
## Implement URL Allowlist

**Priority**: P0

Implement a strict allowlist of permitted domains/hosts and reject requests to any destination not explicitly authorized:

```go
func isAllowedHost(host string) bool {
    // Define explicit allowlist of permitted external services
    allowedHosts := map[string]bool{
        "api.trusted-service.com": true,
        "cdn.acme-corp.com": true,
        "partner-api.example.com": true,
    }
    
    // Check if host is in allowlist
    return allowedHosts[host]
}

router.GET("/fetch", func(c *gin.Context) {
    host := c.Query("host")
    
    // Validate host against allowlist
    if !isAllowedHost(host) {
        c.JSON(http.StatusForbidden, gin.H{"error": "Requested host is not allowed"})
        return
    }
    
    targetURL := "http://" + host + "/admin"
    // Proceed with the request...
})

```

This approach ensures that only specifically authorized external services can be contacted, eliminating the risk of accessing internal services or malicious external endpoints.
## Block Internal Network Requests

**Priority**: P1

Implement network-level protection to prevent requests to internal IP ranges and sensitive domains:

```go
func isBlockedDestination(host string) bool {
    // Parse the host (handle potential port number)
    hostname := host
    if strings.Contains(host, ":") {
        hostname, _, _ = net.SplitHostPort(host)
    }
    
    // Check for localhost variations
    if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
        return true
    }
    
    // Resolve hostname to check for internal IPs
    ips, err := net.LookupIP(hostname)
    if err != nil {
        // If resolution fails, block by default
        return true
    }
    
    for _, ip := range ips {
        // Block private IPv4 ranges
        if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
            return true
        }
        
        // Block specific IPv4 ranges
        if ip4 := ip.To4(); ip4 != nil {
            // Check for AWS metadata service IP
            if ip4[0] == 169 && ip4[1] == 254 {
                return true
            }
        }
    }
    
    return false
}

router.GET("/fetch", func(c *gin.Context) {
    host := c.Query("host")
    
    // Block requests to internal networks
    if isBlockedDestination(host) {
        c.JSON(http.StatusForbidden, gin.H{"error": "Requested destination is blocked"})
        return
    }
    
    targetURL := "http://" + host + "/admin"
    // Proceed with the request...
})

```

This implementation prevents requests to internal networks, loopback addresses, and cloud metadata services, significantly reducing the SSRF attack surface.


# References
* CWE-918 | [Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
* A10:2021 | [Server-Side Request Forgery (SSRF)](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
