# Server-Side Request Forgery (SSRF) in Golang Microservice

# Vulnerability Case
During the review of Acme Corp's Golang microservice implemented with the Gorilla toolkit, we discovered a Server-Side Request Forgery (SSRF) vulnerability in an endpoint that dynamically constructs an HTTP request. In this case, user-supplied input is accepted for the target host without proper sanitization or validation, allowing an attacker to manipulate the destination of the request. This vulnerability was identified during both manual code review and dynamic testing, where crafted input resulted in the service making unintended requests. Exploitation of this flaw can allow the attacker to access internal services or external systems trusted by Acme Corp. Particularly concerning is the ability to circumvent the appended '/api/data' path through URL manipulation techniques (using characters like '#' or '?'). The issue was found in an API endpoint intended to proxy data requests, making it a serious concern for internal network security.

```go
package main

import (
        "io/ioutil"
        "log"
        "net/http"
)

func vulnerableSSRFHandler(w http.ResponseWriter, r *http.Request) {
        // Extract untrusted input to dynamically determine the host
        target := r.URL.Query().Get("host")
        if target == "" {
                http.Error(w, "Missing host parameter", http.StatusBadRequest)
                return
        }

        // Vulnerable pattern: directly concatenating untrusted input to form the URL
        reqURL := "http://" + target + "/api/data"
        resp, err := http.Get(reqURL)
        if err != nil {
                http.Error(w, "Failed to retrieve data", http.StatusInternalServerError)
                return
        }
        defer resp.Body.Close()

        data, err := ioutil.ReadAll(resp.Body)
        if err != nil {
                http.Error(w, "Failed to read response", http.StatusInternalServerError)
                return
        }
        w.Write(data)
}

func main() {
        http.HandleFunc("/proxy", vulnerableSSRFHandler)
        log.Println("Server started on :8080")
        log.Fatal(http.ListenAndServe(":8080", nil))
}
```

The vulnerability stems from insecure handling of the user-supplied input, which is used directly to construct the HTTP request URL. An attacker could supply a malicious domain or IP address (for example, an internal service such as a cloud metadata API endpoint) in the `host` query parameter, leading the server to initiate unauthorized requests on behalf of the application. This opens avenues for lateral movement within Acme Corp's internal network, data exfiltration, credential theft from cloud metadata services, and scanning of protected systems. The exploitation could severely impact the confidentiality of sensitive business data and have limited integrity impact through unauthorized access to internal APIs. The vulnerability does not directly affect system availability.


context: go.gorilla.ssrf.gorilla-tainted-url-host.gorilla-tainted-url-host Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

# Vulnerability Breakdown
This vulnerability involves an SSRF issue in Acme Corp's Golang microservice that allows attackers to force the server to make arbitrary HTTP requests to unintended destinations.

1. **Key vulnerability elements**:
   - User-controlled input from the 'host' query parameter is directly used to construct HTTP request URLs
   - No validation or sanitization of the host value
   - No restrictions on which hosts can be contacted
   - Response data from the target is returned to the client
   - Implemented using Gorilla toolkit in Golang

2. **Potential attack vectors**:
   - Accessing internal services not meant to be publicly available
   - Contacting cloud metadata services to obtain credentials
   - Scanning of internal networks for lateral movement
   - Data exfiltration from trusted third-party services
   - Potential bypassing of network segmentation

3. **Severity assessment**:
   - High impact as it allows access to otherwise inaccessible systems
   - Can potentially compromise sensitive internal APIs and services
   - Could lead to credential theft and lateral movement
   - Allows attackers to leverage the server's trusted status

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Changed (C)
   - Confidentiality (C): High (H) 
   - Integrity (I): Low (L) 
   - Availability (A): None (N) 

# Description
A critical Server-Side Request Forgery (SSRF) vulnerability has been identified in Acme Corp's Golang microservice built with the Gorilla toolkit. The vulnerability exists in the `/proxy` endpoint, which accepts a user-supplied `host` parameter that is directly concatenated into a URL string without validation or sanitization.

```go
reqURL := "http://" + target + "/api/data"
resp, err := http.Get(reqURL)

```

This implementation allows attackers to control the destination of HTTP requests made by the server. By manipulating the `host` parameter, an attacker can force the server to make requests to arbitrary endpoints, including internal services, cloud metadata APIs, or other sensitive systems that trust the server's IP address. The vulnerability is particularly severe because the server returns the complete response from the targeted system to the attacker, potentially leaking sensitive information.

# CVSS
**Score**: 9.3 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N \
**Severity**: Critical

The Critical severity rating (CVSS score 9.3) is justified by multiple factors:

- **Network Attack Vector (AV:N)**: The vulnerability is exploitable remotely by any attacker who can send HTTP requests to the service.

- **Low Attack Complexity (AC:L)**: Exploitation is straightforward, requiring only a simple manipulation of the `host` query parameter with no special conditions needed.

- **No Privileges Required (PR:N)**: The vulnerable endpoint does not require authentication or authorization, allowing unauthenticated attackers to exploit it.

- **No User Interaction (UI:N)**: The attack can be carried out completely without any action from legitimate users.

- **Changed Scope (S:C)**: The vulnerability affects resources beyond the vulnerable component itself. The microservice can be used to access internal services, cloud metadata, or other protected systems that trust the server.

- **High Confidentiality Impact (C:H)**: An attacker can access sensitive information from internal systems, including potential credentials, API keys, and private data that should not be accessible externally.

- **Low Integrity Impact (I:L)**: While primarily an information disclosure vulnerability, attackers could potentially modify data by sending specific HTTP requests to internal services.

- **No Availability Impact (A:N)**: The vulnerability does not directly affect system availability, though secondary attacks using stolen credentials might.

# Exploitation Scenarios
**Scenario 1: Cloud Metadata Service Access**
An attacker targets the vulnerable endpoint with a request to `/proxy?host=169.254.169.254/latest/meta-data/` (AWS metadata service). Since the microservice runs in AWS, it makes an HTTP request to the metadata service and returns the response to the attacker. This allows the attacker to enumerate and access sensitive cloud instance metadata, potentially including IAM credentials with extensive privileges.

**Scenario 2: Internal Network Scanning and Reconnaissance**
The attacker systematically queries internal IP ranges via the SSRF vulnerability (e.g., `/proxy?host=10.0.0.1`). By analyzing the responses (or lack thereof), they can identify active internal systems and services. The attacker then targets discovered services to gather more information about the internal network architecture, leading to more targeted attacks.

**Scenario 3: Database Credential Theft**
After discovering an internal database service during reconnaissance, the attacker sends a request to `/proxy?host=internal-db-server:8080/status` which returns the configuration page of the database management interface. This page contains connection information, database names, and in some cases, weakly protected credentials that can be used for direct database access.

**Scenario 4: Third-Party Service Exploitation**
The attacker sends a request to `/proxy?host=api.third-party-service.com`. Because the request originates from Acme Corp's IP address, the third-party service (which whitelists Acme's IP) processes it as legitimate. The attacker can then access or modify data in the third-party service that should only be accessible to Acme Corp, bypassing IP-based access controls.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive internal systems and data
- Potential breach of customer data leading to regulatory penalties (GDPR, CCPA, etc.)
- Theft of API keys and credentials that could lead to broader compromise
- Loss of trust from customers and partners if a breach occurs
- Financial damage from direct theft, service disruption, or remediation costs
- Reputational damage if the vulnerability is exploited and made public

**Technical Impact:**
- Exposure of internal network architecture and services not intended for public access
- Access to cloud provider metadata potentially revealing IAM credentials with extensive privileges
- Circumvention of network segmentation and security boundaries
- Potential for lateral movement within the internal network
- Ability to leverage the server's trusted status to access protected third-party APIs
- Bypassing of IP-based restrictions and firewall rules
- Potential for using the server as a proxy to conduct further attacks while masking the attacker's true origin

# Technical Details
The vulnerability exists in the `vulnerableSSRFHandler` function of the Golang microservice. The function extracts the `host` parameter from the HTTP request's query string and directly concatenates it to form an HTTP URL without any validation or sanitization:

```go
func vulnerableSSRFHandler(w http.ResponseWriter, r *http.Request) {
	// Extract untrusted input to dynamically determine the host
	target := r.URL.Query().Get("host")
	if target == "" {
		http.Error(w, "Missing host parameter", http.StatusBadRequest)
		return
	}

	// Vulnerable pattern: directly concatenating untrusted input to form the URL
	reqURL := "http://" + target + "/api/data"
	resp, err := http.Get(reqURL)
	if err != nil {
		http.Error(w, "Failed to retrieve data", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response", http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

```

**Key Technical Issues:**

1. **No Host Validation**: The code doesn't verify that the host is allowlisted or legitimate. An attacker can specify any hostname or IP address.

2. **Direct String Concatenation**: Using string concatenation to build URLs is inherently unsafe. The proper approach would be to use Go's `url.URL` to build and validate URLs.

3. **Unrestricted Request Formation**: The code always appends `/api/data` to the user-supplied host, but attackers can circumvent this by using URL characters like `?`, `#`, or additional `/` characters to manipulate the final path.

4. **Full Response Exposure**: The handler returns the complete raw response from the target directly to the client, which can leak sensitive information.

5. **No Network-Level Restrictions**: There are no apparent restrictions preventing the service from making requests to internal networks or sensitive services.

**Exploitation Mechanics:**

An attacker can craft requests like:

```
GET /proxy?host=internal-service.acme.local
GET /proxy?host=169.254.169.254/latest/meta-data/iam/security-credentials/
GET /proxy?host=10.0.0.1:8080

```

The server will attempt to contact these hosts and return their responses directly to the attacker. The attacker can manipulate the path by using techniques like:

```
GET /proxy?host=internal-service.local%23

```

Here, `%23` is the URL-encoded `#` character, which makes the server request `http://internal-service.local#/api/data`, effectively canceling out the `/api/data` path that's appended by the server code.

# Remediation Steps
## Implement Host Allowlisting

**Priority**: P0

Replace the vulnerable implementation with a strict allowlist-based approach:

```go
func saferProxyHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the host parameter
	target := r.URL.Query().Get("host")
	if target == "" {
		http.Error(w, "Missing host parameter", http.StatusBadRequest)
		return
	}
	
	// Define an explicit allowlist of permitted hosts
	allowedHosts := map[string]bool{
		"api.trusted-service.com": true,
		"data.acme-partner.org": true,
		"public-dataset.example.com": true,
	}
	
	// Parse the host to handle any subdomains or ports
	parsedHost := target
	if strings.Contains(target, ":") {
		parsedHost = strings.Split(target, ":")[0]
	}
	
	// Check if the host is in our allowlist
	if !allowedHosts[parsedHost] {
		http.Error(w, "Unauthorized host", http.StatusForbidden)
		return
	}
	
	// Use the url package to properly construct and validate the URL
	parsedURL, err := url.Parse("http://" + target + "/api/data")
	if err != nil {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}
	
	// Perform the request with the validated URL
	resp, err := http.Get(parsedURL.String())
	if err != nil {
		http.Error(w, "Failed to retrieve data", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	// Only return whitelisted response headers and carefully process the body
	// to prevent leaking sensitive information
	// ...
}

```

This implementation restricts requests to a predefined set of trusted hosts and uses proper URL parsing to avoid manipulation attacks.
## Implement Network-Level Restrictions

**Priority**: P1

Configure network-level protections to prevent the service from accessing unauthorized networks:

```go
func isAllowedIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	
	// Block private IP ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16", // AWS metadata service and link-local
	}
	
	for _, cidr := range privateRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.Contains(ip) {
			return false
		}
	}
	
	return true
}

func saferProxyHandlerWithIPCheck(w http.ResponseWriter, r *http.Request) {
	// ... host validation as in the previous example ...
	
	// Perform DNS resolution and check IP addresses
	ipAddrs, err := net.LookupIP(parsedHost)
	if err != nil || len(ipAddrs) == 0 {
		http.Error(w, "Could not resolve host", http.StatusBadRequest)
		return
	}
	
	// Check if any resolved IP is allowed
	allowedIP := false
	for _, ip := range ipAddrs {
		if isAllowedIP(ip.String()) {
			allowedIP = true
			break
		}
	}
	
	if !allowedIP {
		http.Error(w, "Access to this host is restricted", http.StatusForbidden)
		return
	}
	
	// ... proceed with the request as in the previous example ...
}

```

This adds IP-based restrictions to prevent accessing private networks, cloud metadata services, and other sensitive internal resources. Combine this with the allowlist approach for comprehensive protection.


# References
* CWE-918 | [Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
* A10:2021 | [Server-Side Request Forgery (SSRF)](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
