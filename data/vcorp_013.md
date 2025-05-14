# Path Traversal Vulnerability in .NET Core gRPC Service

# Vulnerability Case
During a routine security assessment of Acme Corp's microservices, we identified a potential path traversal vulnerability in a .NET Core gRPC service named *file-taint-grpc*. The service accepts a file name via a gRPC call and directly concatenates it with an internal base directory without proper input validation or sanitization, allowing attackers to manipulate the file path. During testing, abnormal access patterns were observed as crafted file names containing relative path specifiers (e.g., `"..\\"`) were able to traverse directories and access sensitive files. This indicates that an adversary could manipulate the service to **read** critical files, leading to a serious breach of confidentiality.  

```csharp
// In the file-taint-grpc service implemented with .NET Core and gRPC  
public override Task<ReadFileResponse> ReadFile(  
    ReadFileRequest request, ServerCallContext context)  
{  
    // Base directory for file access, assumed to be securely restricted  
    string basePath = @"C:\\AppData\\Files\\";  
      
    // Vulnerable: Directly combines untrusted user input with the base path  
    string filePath = Path.Combine(basePath, request.FileName);  
      
    // No sanitization: User input like `"..\\config\\appsettings.json"` can lead to  
    // path traversal, allowing access to sensitive system files.  
    if (!File.Exists(filePath))  
    {  
        throw new FileNotFoundException("File not found.");  
    }  
      
    string fileContent = File.ReadAllText(filePath);  
    return Task.FromResult(new ReadFileResponse { Content = fileContent });  
}  
```  

The vulnerability arises from the improper handling of the `request.FileName` parameter; by not sanitizing this input, attackers can include directory traversal sequences (e.g., `..\`) to navigate outside the intended file directory. Exploitation methods include crafting malicious gRPC requests to **read** sensitive configuration files or user data. The business impact is significant: unauthorized data disclosure could lead to compromised credentials, regulatory violations, and reputational damage for Acme Corp. This assessment was performed on a real-world .NET Core gRPC stack, highlighting the need for robust input validation in file access operations.  

context: csharp.dotnet-core.path-traversal.file-taint-grpc.file-taint-grpc The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files.

# Vulnerability Breakdown
This vulnerability involves a classic path traversal issue in Acme Corp's .NET Core gRPC service where untrusted user input is directly incorporated into file paths without proper validation.

1. **Key vulnerability elements**:
   - Direct combination of user-supplied file name with a base directory path
   - No input validation or sanitization of the file name parameter
   - Use of Path.Combine() without subsequent path validation
   - Implementation in a microservice architecture with gRPC communication

2. **Potential attack vectors**:
   - Submitting file names containing "..\\" sequences to traverse upward in directory hierarchy
   - Accessing sensitive configuration files (e.g., "..\\config\\appsettings.json")
   - Reading system files outside the intended directory structure
   - Potentially overwriting files if write operations are implemented

3. **Severity assessment**:
   - High confidentiality impact from unauthorized file access
   - Adjacent attack vector requiring access to the internal network
   - Low complexity to exploit once access is obtained
   - Potentially critical data exposure (configuration files, credentials)

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Adjacent (A) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): Low (L) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): None (N) 
   - Availability (A): None (N) 

CVSS Vector: CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N

# Description
A path traversal vulnerability exists in Acme Corp's microservice named "file-taint-grpc" implemented with .NET Core and gRPC. The vulnerability occurs in the `ReadFile` method which accepts a file name via gRPC call and directly concatenates it to a base directory path without proper validation or sanitization.

```csharp
public override Task<ReadFileResponse> ReadFile(
    ReadFileRequest request, ServerCallContext context)
{
    // Base directory for file access, assumed to be securely restricted
    string basePath = @"C:\AppData\Files\";
    
    // Vulnerable: Directly combines untrusted user input with the base path
    string filePath = Path.Combine(basePath, request.FileName);
    
    // No sanitization: User input like "..\config\appsettings.json" can lead to 
    // path traversal, allowing access to sensitive system files.
    if (!File.Exists(filePath))
    {
        throw new FileNotFoundException("File not found.");
    }
    
    string fileContent = File.ReadAllText(filePath);
    return Task.FromResult(new ReadFileResponse { Content = fileContent });
}

```

By manipulating the `request.FileName` parameter with directory traversal sequences (e.g., "..\\" or "../"), attackers can navigate outside the intended directory structure and access files in parent directories or elsewhere on the filesystem. This could lead to unauthorized access to sensitive configuration files, credentials, and other confidential data stored on the server.

# CVSS
**Score**: 5.7 \
**Vector**: CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N \
**Severity**: Medium

The Medium severity rating (5.7) is based on the following factors:

- **Adjacent Attack Vector (AV:A)**: The vulnerability is in a gRPC service which typically requires some level of network access to the internal service infrastructure. An attacker would need access to the network where the service is deployed.

- **Low Attack Complexity (AC:L)**: Exploitation is straightforward, requiring only the ability to craft a gRPC request with path traversal sequences in the file name parameter.

- **Low Privileges Required (PR:L)**: Some basic level of access to the gRPC service is required, implying at least low-level privileges within the network environment.

- **No User Interaction (UI:N)**: The vulnerability can be exploited without any action from a legitimate user.

- **Unchanged Scope (S:U)**: The vulnerability affects only the vulnerable component and doesn't inherently allow access to other components.

- **High Confidentiality Impact (C:H)**: The vulnerability allows unauthorized access to files outside the intended directory, potentially including sensitive configuration files that might contain credentials.

- **No Integrity Impact (I:N)**: Based on the provided code, the vulnerability only involves file reading operations, not writing.

- **No Availability Impact (A:N)**: The vulnerability doesn't directly impact the availability of the service.

While the attack vector is limited to local network access, the potential exposure of highly sensitive information warrants the Medium severity rating.

# Exploitation Scenarios
**Scenario 1: Configuration File Access**
An attacker with access to the gRPC service sends a request with the filename parameter set to "..\\..\\config\\appsettings.json". The vulnerable code combines this with the base path and reads the configuration file, which typically contains sensitive information such as database connection strings, API keys, and service account credentials. The attacker receives the file content in the gRPC response, giving them valuable insights into the system's infrastructure and potentially credentials for other services.

**Scenario 2: Application Secrets Exposure**
The attacker targets secrets stored outside the base directory by specifying "..\\..\\secrets\\api_keys.json" as the file name. This could expose OAuth tokens, encryption keys, or other sensitive credentials that the application uses for secure operations. With these secrets, the attacker could impersonate the application when communicating with other services in the microservice architecture.

**Scenario 3: Access to User Data Files**
If the service runs with elevated permissions, an attacker could traverse to user data storage locations with a request like "..\\..\\Users\\Data\\customer_database.mdf". Although binary database files may not be directly readable through simple file access, text-based data stores or export files could reveal personally identifiable information (PII), leading to privacy violations and potential regulatory consequences.

**Scenario 4: System Information Gathering**
An attacker uses the vulnerability to access system logs and configuration files by traversing to locations like "..\\..\\Windows\\System32\\drivers\\etc\\hosts" or "..\\..\\ProgramData\\logs\\". This information gathering phase provides valuable intelligence about the system's architecture, potentially revealing additional attack vectors or vulnerabilities to exploit.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive configuration data including database connection strings, API keys, and service credentials
- Potential exposure of customer and user personal information, leading to privacy violations
- Regulatory compliance issues if personally identifiable information (PII) or protected data is exposed
- Legal liability and financial penalties under frameworks like GDPR, CCPA, or industry-specific regulations
- Reputational damage and loss of customer trust if a data breach occurs
- Financial impact from incident response, forensic investigation, and remediation activities

**Technical Impact:**
- Exposure of internal system architecture, file paths, and configuration details
- Compromised secrets and credentials that could be used to access other systems or services
- Potential for lateral movement within the microservice architecture if configuration files reveal internal service endpoints and credentials
- Information disclosure that facilitates more sophisticated attacks targeting specific vulnerabilities
- Potential integrity issues if write access is implemented in similar vulnerable methods
- Compromise of the security principle of least privilege, allowing access to files that should be restricted

# Technical Details
The vulnerability is a classic path traversal issue in the file-taint-grpc .NET Core gRPC service. The root cause is in the `ReadFile` method implementation which directly incorporates user input into a file path without proper validation or sanitization.

```csharp
public override Task<ReadFileResponse> ReadFile(
    ReadFileRequest request, ServerCallContext context)
{
    // Base directory for file access, assumed to be securely restricted
    string basePath = @"C:\AppData\Files\";
    
    // Vulnerable: Directly combines untrusted user input with the base path
    string filePath = Path.Combine(basePath, request.FileName);
    
    // No sanitization: User input like "..\config\appsettings.json" can lead to 
    // path traversal, allowing access to sensitive system files.
    if (!File.Exists(filePath))
    {
        throw new FileNotFoundException("File not found.");
    }
    
    string fileContent = File.ReadAllText(filePath);
    return Task.FromResult(new ReadFileResponse { Content = fileContent });
}

```

The specific issues in this code are:

1. **Unsafe Path Construction**: The code uses `Path.Combine()` to join the base directory with user input. While `Path.Combine()` is generally a recommended approach for building paths, it doesn't protect against path traversal attacks when the input contains relative path components.

2. **Missing Input Validation**: There's no validation of the `request.FileName` parameter to check for potentially dangerous sequences like "..\\" or "/".

3. **No Path Canonicalization**: The code doesn't normalize or canonicalize the constructed path to ensure it remains within the intended directory.

4. **Lack of Access Control**: The implementation assumes that restricting to a base directory is sufficient for security, but doesn't enforce this restriction after path construction.

When an attacker provides input containing directory traversal sequences, such as "..\\..\\config\\appsettings.json", the `Path.Combine()` function will incorporate these sequences into the final path. The resulting path might look like:

```
C:\AppData\Files\..\..\config\appsettings.json

```

When this path is resolved by the filesystem APIs used in `File.Exists()` and `File.ReadAllText()`, it effectively navigates up two directory levels from the base directory and then accesses the config directory, resulting in:

```
C:\config\appsettings.json

```

This allows the attacker to read files outside the intended `C:\AppData\Files\` directory, violating the application's security boundaries.

# Remediation Steps
## Implement Path Validation and Canonicalization

**Priority**: P0

Modify the ReadFile method to validate and canonicalize the file path before accessing files:

```csharp
public override Task<ReadFileResponse> ReadFile(
    ReadFileRequest request, ServerCallContext context)
{
    // Base directory for file access
    string basePath = @"C:\AppData\Files\";
    
    // Input validation: Check for invalid characters or patterns
    if (string.IsNullOrEmpty(request.FileName) || 
        request.FileName.Contains("..") || 
        request.FileName.Contains("/") || 
        request.FileName.Contains("\\") || 
        Path.GetInvalidPathChars().Any(c => request.FileName.Contains(c)))
    {
        throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid file name"));
    }
    
    // Safe path construction
    string filePath = Path.Combine(basePath, request.FileName);
    
    // Canonicalize the path and verify it's within the base directory
    string canonicalPath = Path.GetFullPath(filePath);
    if (!canonicalPath.StartsWith(Path.GetFullPath(basePath), StringComparison.OrdinalIgnoreCase))
    {
        throw new RpcException(new Status(StatusCode.PermissionDenied, "Access denied"));
    }
    
    // Check file existence
    if (!File.Exists(canonicalPath))
    {
        throw new FileNotFoundException("File not found.");
    }
    
    // Safe file access
    string fileContent = File.ReadAllText(canonicalPath);
    return Task.FromResult(new ReadFileResponse { Content = fileContent });
}

```

This implementation includes several security measures:
1. Input validation to reject file names containing directory traversal sequences or other dangerous characters
2. Path canonicalization using `Path.GetFullPath()` to resolve any relative path components
3. Verification that the canonicalized path remains within the base directory
4. Consistent error messages that don't reveal system information
## Implement Whitelisting of Allowed Files

**Priority**: P1

For enhanced security, implement a whitelist approach that only allows access to specific pre-approved files:

```csharp
public override Task<ReadFileResponse> ReadFile(
    ReadFileRequest request, ServerCallContext context)
{
    // Define a whitelist of allowed file names
    HashSet<string> allowedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "report1.txt",
        "document2.pdf",
        "data3.json"
        // Add other allowed files
    };
    
    // Validate against the whitelist
    if (!allowedFiles.Contains(request.FileName))
    {
        throw new RpcException(new Status(StatusCode.NotFound, "File not found"));
    }
    
    // Base directory for file access
    string basePath = @"C:\AppData\Files\";
    
    // Safe path construction (even though we've validated against whitelist)
    string filePath = Path.Combine(basePath, request.FileName);
    
    // Additional safeguard: Canonicalize the path and verify it's within the base directory
    string canonicalPath = Path.GetFullPath(filePath);
    if (!canonicalPath.StartsWith(Path.GetFullPath(basePath), StringComparison.OrdinalIgnoreCase))
    {
        throw new RpcException(new Status(StatusCode.PermissionDenied, "Access denied"));
    }
    
    // Check file existence
    if (!File.Exists(canonicalPath))
    {
        throw new FileNotFoundException("File not found.");
    }
    
    // Safe file access
    string fileContent = File.ReadAllText(canonicalPath);
    return Task.FromResult(new ReadFileResponse { Content = fileContent });
}

```

This whitelist approach provides defense-in-depth by:
1. Explicitly defining which files can be accessed, eliminating path traversal concerns
2. Still performing path validation and canonicalization as an additional security layer
3. Applying the principle of least privilege by restricting access to only necessary files

For production scenarios with many files, consider implementing a more scalable approach such as storing allowed files in a database or configuration file, potentially with user-specific access controls.


# References
* CWE-22 | [Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A01:2021 | [Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
* CWE-73 | [External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
* CWE-434 | [Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
