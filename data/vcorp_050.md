# Server-Side Request Forgery (SSRF) in Go gRPC Service

# Vulnerability Case
During Acme Corp's routine security assessment of their Go-based gRPC service, we discovered that an endpoint responsible for constructing outbound HTTP requests was vulnerable to Server-Side Request Forgery (SSRF). The service accepted a user-supplied parameter to form the base URL for an HTTP request without proper sanitization or validation. This design flaw was identified during a code review of the gRPC handlers where the tainted input was directly embedded within the host component of the constructed URL. An attacker could manipulate this behavior to force the server into making unauthorized requests to internal or trusted external systems, potentially exfiltrating sensitive data or enabling further lateral movement. The issue is particularly critical given its integration with common technology stacks including Go, gRPC, and the net/http package.

```go
package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

// Server simulates a gRPC service handling external HTTP requests.
type Server struct{}

// MyRequest represents the gRPC request containing the user-supplied host.
type MyRequest struct {
	// Untrusted input that can taint the URL host component.
	TargetHost string
}

// MyResponse represents the gRPC response carrying the content from the HTTP request.
type MyResponse struct {
	Content string
}

// HandleRequest is the gRPC handler vulnerable to SSRF.
func (s *Server) HandleRequest(ctx context.Context, req *MyRequest) (*MyResponse, error) {
	// Vulnerable pattern: Directly embedding unvalidated user input into URL construction.
	url := fmt.Sprintf("http://%s/sensitive/api", req.TargetHost)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &MyResponse{Content: string(body)}, nil
}

func main() {
	// Illustrative usage; in real deployment, the request originates from a gRPC call.
	s := &Server{}
	req := &MyRequest{TargetHost: "malicious.example.com"}
	resp, err := s.HandleRequest(context.Background(), req)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Response Content:", resp.Content)
}
```

In this scenario, the vulnerability arises from the insecure use of user-supplied input to construct the HTTP request URL. An attacker could manipulate the parameter `TargetHost` to redirect the request to internal network resources or external services considered trustworthy by the organization. This exploitation could lead to unauthorized access to sensitive internal APIs, bypass network controls, or potentially pivot into other segments of the infrastructure. The business impact includes the risk of data exfiltration, unauthorized operations on sensitive systems, and a loss of trust in the integrated trust boundaries between services.


context: go.grpc.ssrf.grpc-tainted-url-host.grpc-tainted-url-host Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

# Vulnerability Breakdown
This vulnerability involves a Go-based gRPC service that constructs outbound HTTP requests using unvalidated user input, creating a Server-Side Request Forgery (SSRF) risk.

1. **Key vulnerability elements**:
   - Direct embedding of user-supplied `TargetHost` parameter into URL construction
   - Complete lack of input validation or sanitization before URL formation
   - No allowlisting of permitted destinations
   - No network-level controls to prevent access to internal resources
   - Implementation in Go's net/http package which follows redirects by default

2. **Potential attack vectors**:
   - Targeting internal network services (e.g., `127.0.0.1:8080`)
   - Accessing cloud metadata services (e.g., `169.254.169.254` in AWS)
   - Exploiting trusted relationships with internal APIs
   - Port scanning internal networks using the server as a proxy
   - DNS rebinding attacks to bypass hostname-based restrictions

3. **Severity assessment**:
   - Network-based attack vector allows remote exploitation
   - Low complexity to exploit with simple parameter manipulation
   - Some privileges likely required to access the gRPC service
   - No user interaction needed for exploitation
   - Scope is changed as the vulnerability compromises multiple security boundaries
   - High confidentiality impact through potential data exfiltration
   - No proven integrity impact as the vulnerability case doesn't demonstrate data modification
   - Low availability impact from potential DoS against internal systems

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): Low (L) 
   - User Interaction (UI): None (N) 
   - Scope (S): Changed (C)
   - Confidentiality (C): High (H) 
   - Integrity (I): None (N) 
   - Availability (A): Low (L) 

# Description
A critical Server-Side Request Forgery (SSRF) vulnerability has been identified in Acme Corp's Go-based gRPC service. The vulnerability exists in the `HandleRequest` function where a user-supplied parameter (`TargetHost`) is directly embedded into a URL string without any validation or sanitization.

```go
// Vulnerable code snippet
func (s *Server) HandleRequest(ctx context.Context, req *MyRequest) (*MyResponse, error) {
    // Vulnerable pattern: Directly embedding unvalidated user input into URL construction.
    url := fmt.Sprintf("http://%s/sensitive/api", req.TargetHost)
    resp, err := http.Get(url)
    // ... remaining code
}

```

This implementation allows an attacker to manipulate the `TargetHost` parameter to force the server to make HTTP requests to arbitrary destinations, including internal network services that should not be accessible from external sources. The vulnerability enables an attacker to bypass network security controls and access sensitive internal systems by leveraging the trust relationship that exists between the vulnerable service and other internal components.

# CVSS
**Score**: 8.5 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:L \
**Severity**: High

The High severity rating (8.5) is based on the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability is exploitable remotely through the gRPC service.

- **Low Attack Complexity (AC:L)**: Exploitation is straightforward and requires only basic parameter manipulation without special conditions.

- **Low Privileges Required (PR:L)**: Some level of access to the gRPC service is likely needed, but elevated privileges are not required.

- **No User Interaction (UI:N)**: The vulnerability can be exploited without any action from legitimate users.

- **Changed Scope (S:C)**: The vulnerability allows an attacker to affect resources beyond the authorization scope of the vulnerable component by accessing internal network services.

- **High Confidentiality Impact (C:H)**: The vulnerability potentially enables access to sensitive internal data and systems that would otherwise be inaccessible.

- **No Integrity Impact (I:N)**: There is no proven ability to modify data through this vulnerability based on the available information. The SSRF allows for unauthorized requests and data retrieval, but there's no demonstration of data modification capabilities.

- **Low Availability Impact (A:L)**: The vulnerability could be used to cause limited disruption to internal services through excessive requests.

This high rating reflects the significant risk posed by SSRF vulnerabilities, especially in modern microservice architectures where internal services often operate with a high level of mutual trust.

# Exploitation Scenarios
**Scenario 1: Internal API Access**
An attacker with access to the gRPC service provides the value `internal-api.acme-corp.local` as the `TargetHost` parameter. The service makes a request to `http://internal-api.acme-corp.local/sensitive/api`, which is an internal API server not meant to be accessible externally. This API might not implement strong authentication controls because it assumes requests only come from trusted internal sources. The attacker gains access to sensitive business data or functionality that should be restricted.

**Scenario 2: Cloud Metadata Service Exploitation**
The attacker specifies the cloud metadata service address (e.g., `169.254.169.254` for AWS) as the `TargetHost`. The vulnerable service makes a request to `http://169.254.169.254/sensitive/api`, which fails but the attacker then tries `http://169.254.169.254/latest/meta-data/iam/security-credentials/` with a modified client, potentially retrieving cloud credentials that could be used for further attacks against the organization's cloud resources.

**Scenario 3: Local Service Probing**
The attacker uses a script to iterate through common ports on localhost (`127.0.0.1:PORT`) as the `TargetHost`, using the response status codes and timing to determine which ports have active services. This allows mapping of internal services running on the same host as the vulnerable application, providing information for further targeted attacks.

**Scenario 4: Network Segmentation Bypass**
The organization has network security controls that segregate production and development environments. An attacker targeting the vulnerable production service uses it to access resources in the development environment (e.g., `dev-database.internal:5432`) which might have weaker security controls, potentially extracting source code, test credentials, or other sensitive information.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive internal data could lead to intellectual property theft
- Potential exposure of customer information resulting in privacy violations and regulatory penalties
- Breach of internal systems could damage trust relationships with partners and customers
- Financial losses from both immediate incident response costs and potential longer-term regulatory fines
- Reputational damage if the breach becomes public, especially if customer data is compromised
- Service disruption if the vulnerability is exploited for denial of service attacks

**Technical Impact:**
- Circumvention of network security controls such as firewalls and network segmentation
- Access to internal services that operate under the assumption of a trusted network
- Potential retrieval of sensitive configuration data, API keys, or credentials from internal systems
- Mapping of internal network architecture and service discovery not intended for external access
- Possibility of lateral movement within the internal network using the vulnerable service as a proxy
- Potential for denial of service attacks against internal systems that aren't designed to handle high volumes of requests
- In cloud environments, potential access to instance metadata services revealing cloud credentials

# Technical Details
The vulnerability is a classic Server-Side Request Forgery (SSRF) issue where user-controlled input directly influences the destination of server-initiated HTTP requests. Let's examine the technical aspects in detail:

```go
func (s *Server) HandleRequest(ctx context.Context, req *MyRequest) (*MyResponse, error) {
    // Vulnerable pattern: Directly embedding unvalidated user input into URL construction.
    url := fmt.Sprintf("http://%s/sensitive/api", req.TargetHost)
    resp, err := http.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }

    return &MyResponse{Content: string(body)}, nil
}

```

**Key Technical Factors:**

1. **No URL Validation**: The code directly interpolates user input into the URL string without validating that the resulting URL points to an authorized destination.

2. **HTTP Client Behavior**: Go's `http.Get` function follows redirects by default (up to 10 redirects), which could allow an attacker to bypass simple blacklist-based protections.

3. **Error Handling**: The function returns the response body to the client, which may include error messages or sensitive data from internal services, providing useful feedback to attackers.

4. **Network Architecture Implications**: The vulnerability's severity is amplified in modern architectures where:
   - Microservices operate with high levels of mutual trust within private networks
   - Internal APIs often have minimal authentication, assuming network-level security
   - Cloud environments expose metadata services at fixed IP addresses

5. **Protocol Considerations**: While the example uses `http://`, Go's HTTP client supports multiple schemes including `https://`, `http://`, and even `file://` in some configurations, potentially allowing access to local files.

**Exploitation Techniques:**

1. **Direct IP Access**: Specifying IP addresses like `127.0.0.1`, `10.0.0.1`, or `169.254.169.254`

2. **DNS Manipulation**: Using domains that resolve to internal IPs, potentially bypassing hostname-based restrictions

3. **Port Scanning**: Adding port specifications like `internal-service:8080`

4. **URL Encoding Tricks**: Using URL encoding or double encoding to bypass simple validation rules

5. **Scheme Mixing**: Attempting other URL schemes like `file://` if supported by the HTTP client

This vulnerability is particularly dangerous because it allows attackers to pivot from the external-facing gRPC service to internal network resources that were never designed to be exposed to untrusted inputs.

# Remediation Steps
## Implement Strict URL Validation with Allowlisting

**Priority**: P0

Replace the current implementation with a strict validation approach that only allows requests to pre-approved hosts:

```go
func isAllowedHost(host string) bool {
    // Define an allowlist of approved domains/hosts
    allowedHosts := map[string]bool{
        "api1.acme-corp.com": true,
        "api2.acme-corp.com": true,
        "approved-partner.com": true,
    }
    
    // Check against the allowlist
    return allowedHosts[host]
}

func (s *Server) HandleRequest(ctx context.Context, req *MyRequest) (*MyResponse, error) {
    // Validate the host against the allowlist before making the request
    if !isAllowedHost(req.TargetHost) {
        return nil, fmt.Errorf("access denied: host '%s' is not in the allowed list", req.TargetHost)
    }
    
    // Additional validation: Parse the URL to ensure it's properly formed
    u, err := url.Parse(fmt.Sprintf("http://%s/sensitive/api", req.TargetHost))
    if err != nil {
        return nil, fmt.Errorf("invalid URL: %v", err)
    }
    
    // Double-check that the URL only contains the approved host
    if !isAllowedHost(u.Hostname()) {
        return nil, fmt.Errorf("validation error: resolved host '%s' is not allowed", u.Hostname())
    }
    
    // Proceed with the now-validated URL
    resp, err := http.Get(u.String())
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    
    return &MyResponse{Content: string(body)}, nil
}

```

This implementation ensures that:
1. Only pre-approved hosts are allowed
2. The URL is properly parsed and validated
3. A secondary validation is performed after URL parsing to prevent bypasses
4. Explicit error messages avoid leaking information about internal systems
## Redesign API to Avoid Host-Level User Input

**Priority**: P1

Fundamentally redesign the API to eliminate the need for user-controlled hosts:

```go
// ServiceClient manages outbound requests to pre-configured services
type ServiceClient struct {
    // Pre-configured service endpoints, set during application initialization
    serviceEndpoints map[string]string
    httpClient       *http.Client
}

// NewServiceClient creates a configured client with allowed endpoints
func NewServiceClient() *ServiceClient {
    // Configure with specific allowed endpoints from a secure configuration source
    return &ServiceClient{
        serviceEndpoints: map[string]string{
            "service1": "https://api1.acme-corp.com",
            "service2": "https://api2.acme-corp.com",
            "partner":  "https://approved-partner.com",
        },
        httpClient: &http.Client{
            // Configure timeout, TLS settings, etc.
            Timeout: 10 * time.Second,
        },
    }
}

// MyRequest now takes a service identifier and path instead of raw host
type MyRequest struct {
    ServiceID string // Identifies which pre-configured service to use
    Path      string // The specific API path to request
}

// HandleRequest uses pre-defined service endpoints
func (s *Server) HandleRequest(ctx context.Context, req *MyRequest) (*MyResponse, error) {
    client := NewServiceClient()
    
    // Look up the base URL for the requested service
    baseURL, exists := client.serviceEndpoints[req.ServiceID]
    if !exists {
        return nil, fmt.Errorf("unknown service: %s", req.ServiceID)
    }
    
    // Sanitize the path component
    safePath := path.Clean("/" + strings.TrimPrefix(req.Path, "/"))
    
    // Construct the full URL using the pre-defined base URL and sanitized path
    fullURL := baseURL + safePath
    
    // Make the request
    resp, err := client.httpClient.Get(fullURL)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    
    return &MyResponse{Content: string(body)}, nil
}

```

This complete redesign:
1. Eliminates direct user control of the host component entirely
2. Uses pre-configured service endpoints from secure configuration sources
3. Only allows users to specify which service to call and the path parameters
4. Sanitizes the path component to prevent directory traversal attacks
5. Creates a more maintainable and secure API design pattern


# References
* CWE-918 | [Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
* A10:2021 | [Server-Side Request Forgery (SSRF)](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A01:2021 | [Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
* A05:2021 | [Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
