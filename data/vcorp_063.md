# Server-Side Request Forgery (SSRF) via Unvalidated URL Host Parameter

# Vulnerability Case
During the security assessment of Acme Corp's Go-based microservice deployed on Linux containers orchestrated via Kubernetes, I discovered that user input is directly used to construct the base URL for outbound HTTP requests. This vulnerability was identified through both static code review and behavioral monitoring of API logs, revealing that the unvalidated parameter (`$REQUEST`) can be manipulated to alter the target host, thus enabling potential SSRF attacks. The affected endpoint accepts a user-supplied `url_host` query parameter, which is concatenated into the base URL before initiating an HTTP GET request. An attacker could exploit this issue by redirecting requests to internal assets, such as cloud metadata endpoints, to exfiltrate sensitive information. The finding underscores the critical importance of input validation and the use of allowlists when processing user inputs in server-side HTTP requests.

```go
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	// Retrieve user input without proper validation.
	userHost := r.URL.Query().Get("url_host")
	if userHost == "" {
		http.Error(w, "Missing url_host parameter", http.StatusBadRequest)
		return
	}

	// Vulnerable pattern: constructing URL using unvalidated user input.
	targetURL := "http://" + userHost + "/api/status"
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, "Error fetching target URL", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Error reading response", http.StatusInternalServerError)
		return
	}
	fmt.Fprintln(w, string(body))
}

func main() {
	http.HandleFunc("/fetch", handler)
	log.Println("Server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

The vulnerability stems from the insecure usage of a user-supplied input to form the base of an HTTP request, allowing an attacker to perform Server-Side Request Forgery (SSRF). By manipulating the `url_host` parameter, an attacker can redirect the service's requests to internal resources, such as private APIs or metadata services (e.g., accessing cloud provider metadata endpoints like 169.254.169.254), potentially leaking sensitive configurations or credentials. Exploitation could lead to unauthorized internal network reconnaissance, lateral movement, and broader compromise of internal systems, significantly impacting the confidentiality and integrity of critical business operations.


context: go.lang.security.injection.tainted-url-host.tainted-url-host A request was found to be crafted from user-input `$REQUEST`. This can lead to Server-Side Request Forgery (SSRF) vulnerabilities, potentially exposing sensitive data. It is recommend where possible to not allow user-input to craft the base request, but to be treated as part of the path or query parameter. When user-input is necessary to craft the request, it is recommended to follow OWASP best practices to prevent abuse, including using an allowlist.

# Vulnerability Breakdown
This vulnerability involves a Go-based microservice that accepts user input to construct the base URL for outbound HTTP requests without proper validation, enabling Server-Side Request Forgery (SSRF) attacks.

1. **Key vulnerability elements**:
   - User-controlled parameter (`url_host`) directly incorporated into URL construction
   - No validation or allowlisting of acceptable domains
   - Direct HTTP request made to the constructed URL
   - Results from the request returned to the user
   - Kubernetes-hosted service with potential access to internal network resources
   - Authentication required to access the vulnerable endpoint

2. **Potential attack vectors**:
   - Accessing cloud provider metadata endpoints (e.g., `169.254.169.254` for AWS)
   - Scanning internal networks by specifying private IP addresses
   - Accessing Kubernetes API server via internal DNS names
   - Probing internal services not meant for external access
   - Port scanning through URL manipulation

3. **Severity assessment**:
   - High confidentiality impact due to potential credential and configuration exposure
   - Low integrity impact from potential request manipulation
   - Network-based attack vector requiring no special access
   - Changed scope as it affects resources beyond the vulnerable component
   - Low privileges required to exploit (authenticated access)
   - Low complexity to exploit through simple parameter manipulation

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): Low (L) 
   - User Interaction (UI): None (N) 
   - Scope (S): Changed (C)
   - Confidentiality (C): High (H) 
   - Integrity (I): Low (L) 
   - Availability (A): None (N) 

# Description
A critical Server-Side Request Forgery (SSRF) vulnerability was discovered in Acme Corp's Go-based microservice deployed on Kubernetes. The vulnerability exists in the `/fetch` endpoint, which accepts a user-supplied `url_host` parameter and directly incorporates it into constructing a URL for an outbound HTTP request without any validation.

```go
// Vulnerable code snippet
userHost := r.URL.Query().Get("url_host")
if userHost == "" {
    http.Error(w, "Missing url_host parameter", http.StatusBadRequest)
    return
}
// Vulnerable pattern: constructing URL using unvalidated user input
targetURL := "http://" + userHost + "/api/status"
resp, err := http.Get(targetURL)

```

This vulnerability allows authenticated attackers to manipulate the application into making HTTP requests to arbitrary destinations, including internal network resources that should not be accessible externally. Exploiting this issue could lead to unauthorized access to cloud metadata services (revealing credentials), internal network enumeration, and potential access to sensitive internal APIs and services.

# CVSS
**Score**: 8.5 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N \
**Severity**: High

The High severity rating (8.5) is justified by the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely over the internet without requiring any proximity to the target system. The endpoint is accessible to authenticated users.

- **Low Attack Complexity (AC:L)**: Exploiting this vulnerability is straightforward and requires no special conditions or preparation. An attacker simply needs to modify the `url_host` parameter to point to their desired target.

- **Low Privileges Required (PR:L)**: Authentication is required to access the vulnerable endpoint. The attacker needs to have basic user-level access to the application.

- **No User Interaction (UI:N)**: Exploitation can be fully automated without requiring any actions from legitimate users or administrators.

- **Changed Scope (S:C)**: The vulnerability allows the attacker to impact resources beyond the vulnerable component itself. By redirecting requests to internal services or metadata endpoints, the attacker can access resources in different security domains.

- **High Confidentiality Impact (C:H)**: Successful exploitation could expose highly sensitive information such as cloud provider credentials, internal API tokens, and configuration data that would enable further attacks.

- **Low Integrity Impact (I:L)**: While primarily an information disclosure vulnerability, there is some potential for integrity impacts through manipulation of internal requests.

- **No Availability Impact (A:N)**: The vulnerability doesn't directly affect the availability of the service or target systems.

The severity is slightly reduced from Critical to High due to the authentication requirement, which limits the pool of potential attackers to those who already have legitimate access to the system.

# Exploitation Scenarios
**Scenario 1: Cloud Metadata Service Access**
An authenticated attacker submits a request to the vulnerable endpoint with `url_host=169.254.169.254` to access the AWS EC2 instance metadata service:

```
GET /fetch?url_host=169.254.169.254 HTTP/1.1
Host: api.acme-corp.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

```

The application constructs the URL `http://169.254.169.254/api/status`, but due to how AWS metadata service works, the attacker can then chain requests to access sensitive data:

```
GET /fetch?url_host=169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: api.acme-corp.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

```

This could reveal IAM role names, followed by obtaining the actual credentials by requesting the specific role:

```
GET /fetch?url_host=169.254.169.254/latest/meta-data/iam/security-credentials/s3-access-role HTTP/1.1
Host: api.acme-corp.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

```

**Scenario 2: Kubernetes API Server Access**
An authenticated user with malicious intent could target the internal Kubernetes API server to extract sensitive information about the cluster:

```
GET /fetch?url_host=kubernetes.default.svc HTTP/1.1
Host: api.acme-corp.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

```

The application would make a request to `http://kubernetes.default.svc/api/status`. The attacker could then explore other endpoints to enumerate pods, services, and potentially access secrets:

```
GET /fetch?url_host=kubernetes.default.svc/api/v1/namespaces/default/secrets HTTP/1.1
Host: api.acme-corp.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

```

**Scenario 3: Internal Network Scanning**
An authenticated insider could use the vulnerability to map internal network topology by scanning private IP ranges:

```
GET /fetch?url_host=10.0.0.1 HTTP/1.1
Host: api.acme-corp.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

```

By iterating through different IP addresses and port combinations, the attacker could identify live hosts and services on the internal network:

```
GET /fetch?url_host=10.0.0.1:8080 HTTP/1.1
Host: api.acme-corp.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

```

The response (or error) would indicate whether the service was able to connect to that host and port, effectively allowing for port scanning and service discovery from behind the organization's perimeter defenses.

# Impact Analysis
**Business Impact:**
- Exposure of cloud provider API credentials could lead to complete account compromise, potentially affecting all cloud-hosted resources
- Unauthorized access to internal configuration data could reveal intellectual property or proprietary information
- Potential for compliance violations (e.g., GDPR, HIPAA, PCI-DSS) if sensitive data is exposed
- Reputational damage if the vulnerability is exploited for a data breach
- Financial losses from incident response, forensic analysis, and potential regulatory fines
- Business disruption if attackers use exposed credentials to modify or delete cloud resources

**Technical Impact:**
- Complete mapping of internal network architecture, bypassing network segmentation
- Unauthorized access to sensitive endpoints that were intended to be internal-only
- Discovery and exploitation of vulnerable internal services not hardened for external access
- Potential credential theft from cloud metadata services, config files, or internal APIs
- Lateral movement opportunities through exposed internal services
- Bypass of perimeter security controls by using the vulnerable application as a proxy
- Potential access to Kubernetes cluster information, including secrets and configurations
- Chaining with other vulnerabilities to escalate privileges within the internal network

# Technical Details
The vulnerability is a classic Server-Side Request Forgery (SSRF) issue in a Go microservice. The core problem exists in the `/fetch` endpoint handler function, which directly incorporates user input into URL construction without validation:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    // Retrieve user input without proper validation.
    userHost := r.URL.Query().Get("url_host")
    if userHost == "" {
        http.Error(w, "Missing url_host parameter", http.StatusBadRequest)
        return
    }
    // Vulnerable pattern: constructing URL using unvalidated user input.
    targetURL := "http://" + userHost + "/api/status"
    resp, err := http.Get(targetURL)
    if err != nil {
        http.Error(w, "Error fetching target URL", http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        http.Error(w, "Error reading response", http.StatusInternalServerError)
        return
    }
    fmt.Fprintln(w, string(body))
}

```

**Exploitation Mechanics:**

1. The authenticated user accesses the `/fetch` endpoint with their credentials
2. The application accepts the `url_host` parameter from the HTTP request query string
3. It concatenates this parameter between `"http://"` and `"/api/status"` to form a complete URL
4. The application makes an HTTP GET request to this constructed URL
5. The response from this request is read and sent back to the client

**Key Vulnerability Factors:**

1. **No URL Validation**: The code doesn't validate that the provided host is allowed or legitimate

2. **No URL Parsing**: The application fails to properly parse and sanitize the URL components

3. **No Network Restrictions**: No restrictions on which network segments can be accessed

4. **Unrestricted Protocol**: While the code prefixes with "http://", attackers can potentially bypass this by using URL format tricks

5. **Response Reflection**: The application returns the full response to the client, allowing for effective data exfiltration

**Containerized Environment Impact:**

The vulnerability is particularly concerning in a Kubernetes environment because:

1. Container networking typically allows access to the host network and other containers

2. Kubernetes provides a DNS service that allows accessing services by name

3. Cloud-managed Kubernetes often runs with credentials that have access to the cloud provider's API

4. Container metadata services may be accessible and contain sensitive information

This combination of factors makes the SSRF vulnerability especially dangerous, as it can be used as a pivoting point to access various internal resources that would otherwise be protected from external access.

# Remediation Steps
## Implement Domain Allowlist Validation

**Priority**: P0

Replace the current implementation with strict validation against a predefined allowlist of permitted domains:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    // Retrieve user input
    userHost := r.URL.Query().Get("url_host")
    if userHost == "" {
        http.Error(w, "Missing url_host parameter", http.StatusBadRequest)
        return
    }
    
    // Define allowlist of permitted domains
    allowedHosts := map[string]bool{
        "api.trusted-partner.com": true,
        "status.acme-corp.com": true,
        "metrics.acme-corp.com": true,
    }
    
    // Validate host against allowlist
    if !allowedHosts[userHost] {
        http.Error(w, "Unauthorized host", http.StatusForbidden)
        return
    }
    
    // Construct URL with validated host
    targetURL := "http://" + userHost + "/api/status"
    
    // Proceed with request
    resp, err := http.Get(targetURL)
    if err != nil {
        http.Error(w, "Error fetching target URL", http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()
    
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        http.Error(w, "Error reading response", http.StatusInternalServerError)
        return
    }
    
    fmt.Fprintln(w, string(body))
}

```

This implementation ensures that only predefined, trusted domains can be used as the host for outbound requests, eliminating the SSRF vulnerability. Any attempt to use an unauthorized host will be rejected with a 403 Forbidden response.
## Implement Proper URL Parsing and Validation

**Priority**: P1

Enhance the validation by properly parsing the URL and implementing more comprehensive checks:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    // Retrieve user input
    userHost := r.URL.Query().Get("url_host")
    if userHost == "" {
        http.Error(w, "Missing url_host parameter", http.StatusBadRequest)
        return
    }
    
    // Parse host to validate format
    parsedHost, err := url.Parse("http://" + userHost)
    if err != nil {
        http.Error(w, "Invalid host format", http.StatusBadRequest)
        return
    }
    
    // Extract pure hostname without port or path
    hostname := parsedHost.Hostname()
    
    // Block private/local IP ranges and localhost
    if isPrivateIP(hostname) || isLoopback(hostname) {
        http.Error(w, "Access to internal hosts not allowed", http.StatusForbidden)
        return
    }
    
    // Define allowlist of permitted domains
    allowedDomains := []string{
        ".trusted-partner.com",
        ".acme-corp.com",
    }
    
    // Check if hostname matches any allowed domain
    allowed := false
    for _, domain := range allowedDomains {
        if strings.HasSuffix(hostname, domain) {
            allowed = true
            break
        }
    }
    
    if !allowed {
        http.Error(w, "Unauthorized host domain", http.StatusForbidden)
        return
    }
    
    // Construct URL with validated host (using original port if specified)
    targetURL := fmt.Sprintf("http://%s/api/status", userHost)
    
    // Proceed with request
    client := &http.Client{
        Timeout: 10 * time.Second,
    }
    
    resp, err := client.Get(targetURL)
    if err != nil {
        http.Error(w, "Error fetching target URL", http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()
    
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        http.Error(w, "Error reading response", http.StatusInternalServerError)
        return
    }
    
    fmt.Fprintln(w, string(body))
}

// Helper function to check if an address is a private IP
func isPrivateIP(host string) bool {
    ip := net.ParseIP(host)
    if ip == nil {
        return false
    }
    
    // Check RFC1918 private IP ranges
    privateRanges := []struct {
        start net.IP
        end   net.IP
    }{
        {net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")},
        {net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")},
        {net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")},
        {net.ParseIP("169.254.0.0"), net.ParseIP("169.254.255.255")}, // Link-local
    }
    
    for _, r := range privateRanges {
        if bytes.Compare(ip, r.start) >= 0 && bytes.Compare(ip, r.end) <= 0 {
            return true
        }
    }
    
    return false
}

// Helper function to check if an address is loopback
func isLoopback(host string) bool {
    ip := net.ParseIP(host)
    if ip == nil {
        return host == "localhost"
    }
    return ip.IsLoopback()
}

```

This implementation provides multiple layers of protection:
1. It properly parses the URL to extract the hostname
2. It blocks requests to private IP ranges and loopback addresses
3. It validates the domain against an allowlist using suffix matching
4. It adds a timeout to the HTTP client to prevent long-running requests


# References
* CWE-918 | [Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A10:2021 | [Server-Side Request Forgery (SSRF)](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* CWE-200 | [Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
