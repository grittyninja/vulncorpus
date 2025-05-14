# Server-Side Request Forgery (SSRF) via Unvalidated URL Input in .NET Core Microservice

# Vulnerability Case
During our penetration assessment of Acme Corp's .NET Core microservices communicating via gRPC, we identified a potential SSRF vulnerability in the HTTP client integration. The vulnerability stemmed from the use of unvalidated user input to format the base URL for outgoing HTTP requests using C# string formatting methods, enabling an attacker to direct requests to arbitrary internal or external endpoints. This issue was uncovered during a detailed code review and dynamic testing of the gRPC-to-HTTP bridging functionality. An attacker could potentially exploit this oversight to access sensitive internal resources or perform network reconnaissance. The discovery highlights the risk associated with improper handling of untrusted input within a stack comprising .NET Core, HttpClient, and gRPC.

```csharp
using System;
using System.Net.Http;
using System.Threading.Tasks;

public class GrpcHttpBridge
{
    private readonly HttpClient _httpClient;

    public GrpcHttpBridge(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<string> FetchDataAsync(string userInputEndpoint)
    {
        // Vulnerability: Untrusted input directly incorporated into the HTTP request URL.
        var url = string.Format("https://{0}/api/resource", userInputEndpoint);
        var response = await _httpClient.GetAsync(url);
        return await response.Content.ReadAsStringAsync();
    }
}
```

The vulnerability arises from the direct inclusion of untrusted input `userInputEndpoint` in constructing the HTTP request URL without robust validation or allowlisting. An attacker can craft this input to target sensitive internal services (e.g., using hostnames or IP addresses that resolve to internal systems), effectively leveraging the server as a proxy for SSRF attacks. This exploitation could lead to unauthorized data retrieval, internal network scanning, or potential pivoting to services with elevated trust relationships. In a business context, such exploitation could compromise sensitive data, violate regulatory requirements, and significantly damage the organization's security posture.

context: csharp.dotnet-core.ssrf.httpclient-taint-format-grpc.httpclient-taint-format-grpc Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

# Vulnerability Breakdown
This vulnerability involves a classic Server-Side Request Forgery (SSRF) pattern in a .NET Core microservice that uses gRPC for communication.

1. **Key vulnerability elements**:
   - Direct inclusion of untrusted user input (`userInputEndpoint`) in HTTP request URL formation
   - Use of string formatting (`string.Format`) without validation or sanitization
   - Lack of allowlisting for acceptable destinations
   - HttpClient implementation that follows redirects by default
   - Microservice architecture increasing the potential attack surface of internal systems

2. **Potential attack vectors**:
   - Internal network scanning by specifying internal IP ranges
   - Accessing sensitive internal services (databases, admin interfaces, metadata services)
   - Leveraging cloud metadata endpoints (e.g., `169.254.169.254` in AWS)
   - Exploiting trust relationships between the vulnerable service and internal systems
   - Port scanning internal network by analyzing timing or response differences

3. **Severity assessment**:
   - High confidentiality impact as it could expose sensitive internal services and data
   - Low integrity impact as it might allow limited modification depending on accessible endpoints
   - Exploitable remotely through the application's interface
   - Low complexity to exploit once the vulnerability is discovered
   - Changed scope as the vulnerability impacts resources beyond the vulnerable component

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Changed (C)
   - Confidentiality (C): High (H) 
   - Integrity (I): Low (L) 
   - Availability (A): None (N) 

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N

# Description
A Server-Side Request Forgery (SSRF) vulnerability exists in Acme Corp's .NET Core microservice architecture that uses gRPC for communication. The vulnerability is located in the HTTP client integration where unvalidated user input is directly incorporated into the base URL for outgoing HTTP requests.

```csharp
public async Task<string> FetchDataAsync(string userInputEndpoint)
{
    // Vulnerability: Untrusted input directly incorporated into the HTTP request URL.
    var url = string.Format("https://{0}/api/resource", userInputEndpoint);
    var response = await _httpClient.GetAsync(url);
    return await response.Content.ReadAsStringAsync();
}

```

This implementation allows an attacker to specify arbitrary domains or IP addresses in the `userInputEndpoint` parameter, potentially directing requests to internal network resources that should not be accessible externally. The server then acts as a proxy, making requests to these endpoints and returning the responses to the attacker. This creates a significant security risk as it could expose sensitive internal services, enable network reconnaissance, or allow attackers to leverage the server's elevated trust relationships with other internal systems.

# CVSS
**Score**: 9.3 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N \
**Severity**: Critical

The Critical severity rating (9.3) is justified by multiple factors:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely over the internet, requiring no physical or adjacent network access.

- **Low Attack Complexity (AC:L)**: Exploiting the vulnerability is straightforward, requiring no special conditions or preparation. The attacker simply needs to provide a malicious input to the vulnerable endpoint.

- **No Privileges Required (PR:N)**: The vulnerability can be exploited without authentication, as the affected endpoint appears to accept user input without requiring authorization.

- **No User Interaction (UI:N)**: Exploitation occurs directly between the attacker and the vulnerable system, requiring no actions from legitimate users.

- **Changed Scope (S:C)**: This is a critical factor in the high score. The vulnerability breaks the intended security boundary, allowing attackers to leverage the vulnerable service to access other internal systems or services that would otherwise be inaccessible.

- **High Confidentiality Impact (C:H)**: The vulnerability potentially allows access to sensitive internal services, metadata, configuration information, and other confidential resources on the internal network.

- **Low Integrity Impact (I:L)**: Some limited impact to data integrity is possible if the attacker can access writable endpoints through the SSRF.

- **No Availability Impact (A:N)**: The vulnerability itself doesn't directly impact system availability, though follow-up attacks might.

The combination of these factors, particularly the changed scope and high confidentiality impact, results in the Critical rating, indicating a vulnerability that requires immediate remediation.

# Exploitation Scenarios
**Scenario 1: Internal Network Reconnaissance**
An attacker identifies the vulnerable endpoint and begins mapping the internal network by providing various internal IP addresses and common port numbers in the `userInputEndpoint` parameter. For example:

```
10.0.0.1
10.0.0.2
...
10.0.0.254

```

By analyzing the timing, response types, and error messages returned, the attacker can determine which internal hosts are active and potentially identify what services they're running. This information builds a map of the internal network architecture for further targeted attacks.

**Scenario 2: Cloud Metadata Service Exploitation**
If the vulnerable service is running in a cloud environment, an attacker could target the cloud provider's metadata service. For example, in AWS:

```
userInputEndpoint = "169.254.169.254/latest/meta-data/iam/security-credentials/"

```

This could reveal the IAM role name assigned to the instance. A follow-up request:

```
userInputEndpoint = "169.254.169.254/latest/meta-data/iam/security-credentials/[role-name]"

```

Could potentially expose temporary AWS credentials, allowing the attacker to access AWS resources with the permissions of the compromised service.

**Scenario 3: Accessing Internal Admin Interfaces**
The attacker discovers that an internal administration dashboard runs on a private network at `10.0.0.42:8080`. By setting:

```
userInputEndpoint = "10.0.0.42:8080/admin"

```

The attacker may be able to access the administration interface through the vulnerable service, bypassing network controls that would normally prevent external access. If the internal service relies on IP-based authentication or network location for security, the attacker might gain privileged access as the request comes from a trusted internal system.

# Impact Analysis
**Business Impact:**
- Potential unauthorized access to sensitive internal systems and data
- Exposure of confidential information including customer data, business logic, and proprietary algorithms
- Regulatory compliance violations and potential fines if personal data is exposed
- Damage to reputation and customer trust if a breach occurs
- Financial losses from incident response, forensics, and potential legal actions
- Possible service disruptions during remediation efforts

**Technical Impact:**
- Compromise of network architecture confidentiality through enumeration of internal systems
- Potential access to restricted internal services not intended for external users
- Exposure of sensitive configuration data, including connection strings and credentials
- Circumvention of network-level access controls and segmentation
- Potential for lateral movement within the internal network
- Access to cloud provider metadata services that may expose credentials or configuration information
- Ability to leverage trust relationships between internal services
- Possible port scanning capabilities across internal networks from a trusted position

# Technical Details
The vulnerability exists in the `GrpcHttpBridge` class that bridges gRPC communications to HTTP requests. The core issue is in the `FetchDataAsync` method:

```csharp
public async Task<string> FetchDataAsync(string userInputEndpoint)
{
    // Vulnerability: Untrusted input directly incorporated into the HTTP request URL.
    var url = string.Format("https://{0}/api/resource", userInputEndpoint);
    var response = await _httpClient.GetAsync(url);
    return await response.Content.ReadAsStringAsync();
}

```

The vulnerability stems from several technical issues:

1. **String Formatting Without Validation**: The code uses `string.Format()` to construct a URL with untrusted input directly inserted as the hostname portion, allowing attackers to specify arbitrary destinations.

2. **HttpClient Behavior**: By default, .NET's `HttpClient` will:
   - Follow redirects automatically (up to 50 by default)
   - Resolve DNS names to any IP address, including internal ones
   - Connect to any port specified in the URL
   - Handle various URL schemes (http, https)

3. **No URL Parsing or Validation**: The code lacks proper URL parsing that could detect and prevent malicious inputs like:
   - Internal IP addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
   - Localhost references (localhost, 127.0.0.1)
   - Cloud metadata service IPs (169.254.169.254)
   - Malformed URLs that might bypass simple checks

4. **Microservice Architecture Implications**: In a microservices environment, the compromised service likely has network access to other internal services, making this vulnerability particularly dangerous as it can bridge external attacks to internal systems.

5. **No Allowlisting**: There's no implementation of an allowlist approach that would restrict requests to only approved destinations.

An attacker can exploit this vulnerability by providing various inputs to the `userInputEndpoint` parameter:

- Internal IP addresses: `"10.0.0.1"`
- Internal hostnames: `"internal-db"`
- Localhost with various representations: `"localhost"`, `"127.0.0.1"`
- Cloud metadata services: `"169.254.169.254"`
- Alternative ports: `"internal-service:8080"`
- Path traversal attempts: `"legitimate-host/..%2f..%2fetc%2fpasswd"`

# Remediation Steps
## Implement URL Allowlisting

**Priority**: P0

Implement strict allowlisting for permitted external hosts and validate all user input against this allowlist before making HTTP requests:

```csharp
public class GrpcHttpBridge
{
    private readonly HttpClient _httpClient;
    private readonly HashSet<string> _allowlistedDomains;

    public GrpcHttpBridge(HttpClient httpClient, IConfiguration configuration)
    {
        _httpClient = httpClient;
        
        // Initialize allowlisted domains from configuration
        _allowlistedDomains = new HashSet<string>(configuration
            .GetSection("AllowlistedDomains")
            .Get<string[]>() ?? Array.Empty<string>(), 
            StringComparer.OrdinalIgnoreCase);
    }

    public async Task<string> FetchDataAsync(string userInputEndpoint)
    {
        // Parse and validate the input as a host
        if (!Uri.TryCreate($"https://{userInputEndpoint}", UriKind.Absolute, out var uri))
        {
            throw new ArgumentException("Invalid endpoint format", nameof(userInputEndpoint));
        }

        // Check against the allowlist
        if (!_allowlistedDomains.Contains(uri.Host))
        {
            throw new SecurityException($"Domain '{uri.Host}' is not in the allowed domains list");
        }

        // Explicitly construct the URL with a fixed path to prevent path manipulation
        var url = $"https://{uri.Host}/api/resource";
        
        var response = await _httpClient.GetAsync(url);
        return await response.Content.ReadAsStringAsync();
    }
}

```

This implementation:
1. Stores an explicit list of allowed domains from configuration
2. Validates that the user input can be parsed as a valid URI
3. Checks the host against the allowlist before proceeding
4. Reconstructs the URL using only the validated host with a fixed path
5. Throws appropriate exceptions for invalid or disallowed inputs
## Configure HttpClient with Restrictive Policies

**Priority**: P1

Configure the HttpClient with restrictive policies to prevent SSRF attempts from succeeding even if they bypass application-level checks:

```csharp
public static class HttpClientConfigurationExtensions
{
    public static IServiceCollection AddSecureHttpClient(this IServiceCollection services)
    {
        services.AddHttpClient("SecureClient")
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
            {
                // Disable automatic redirects
                AllowAutoRedirect = false,
                
                // Set a maximum connection limit
                MaxConnectionsPerServer = 10,
                
                // Custom DNS resolver to block internal addresses
                ConnectCallback = async (context, cancellationToken) =>
                {
                    // Parse the host from the request uri
                    string host = context.DnsEndPoint.Host;
                    int port = context.DnsEndPoint.Port;
                    
                    // Block common private IP ranges and localhost
                    if (IsPrivateIpAddress(host) || IsLocalhost(host))
                    {
                        throw new SecurityException($"Connection to private IP or localhost is not allowed: {host}");
                    }
                    
                    // Use system DNS resolution and connect
                    var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                    await socket.ConnectAsync(host, port, cancellationToken);
                    return new NetworkStream(socket, ownsSocket: true);
                }
            });
            
        return services;
    }
    
    private static bool IsPrivateIpAddress(string host)
    {
        // Only proceed if the host is an IP address
        if (!IPAddress.TryParse(host, out var ipAddress))
        {
            return false;
        }
        
        // Check for private IP ranges
        byte[] bytes = ipAddress.GetAddressBytes();
        if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            // 10.0.0.0/8
            if (bytes[0] == 10) return true;
            
            // 172.16.0.0/12
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
            
            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            
            // 169.254.0.0/16 (Link-local)
            if (bytes[0] == 169 && bytes[1] == 254) return true;
        }
        
        return false;
    }
    
    private static bool IsLocalhost(string host)
    {
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
            return true;
            
        if (IPAddress.TryParse(host, out var ipAddress))
        {
            // 127.0.0.0/8
            byte[] bytes = ipAddress.GetAddressBytes();
            if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && bytes[0] == 127)
                return true;
        }
        
        return false;
    }
}

```

This implementation:
1. Disables automatic redirects to prevent redirect-based attacks
2. Implements a custom DNS resolver that blocks connections to private IP ranges and localhost
3. Sets reasonable connection limits to prevent abuse
4. Can be easily registered in the application's dependency injection container


# References
* CWE-918 | [Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A10:2021 | [Server-Side Request Forgery (SSRF)](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* A04:2021 | [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
