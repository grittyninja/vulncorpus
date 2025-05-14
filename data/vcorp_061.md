# Path Traversal due to Improper Filepath Sanitization

# Vulnerability Case
During the code review of Acme Corp's Golang-based file server, we discovered that the application incorrectly uses Go’s `filepath.Clean` function to sanitize file path inputs from HTTP requests. Although `Clean` is designed to consolidate path elements into the shortest equivalent form, it does not filter out directory traversal patterns, leaving the server susceptible to unauthorized file access. The flaw was identified when mapping request URLs to filesystem paths in the file-serving endpoint, where malicious input such as `../../etc/passwd` could be normalized but still traverse directories. This vulnerability was found in a real-world stack using Go’s standard libraries (`net/http`, `filepath`, and `strings`), a common pattern in microservice architectures.

```go
package main

import (
	"net/http"
	"path/filepath"
	"strings"
)

func fileHandler(w http.ResponseWriter, req *http.Request) {
	// Vulnerable path construction using filepath.Clean
	cleanPath := filepath.Clean("/" + strings.Trim(req.URL.Path, "/"))
	// Files are served from the "./static directory
	http.ServeFile(w, req, "./static"+cleanPath)
}

func main() {
	http.HandleFunc("/", fileHandler)
	http.ListenAndServe(":8080", nil)
}
```

The vulnerability arises because `filepath.Clean` is used under the assumption that it sanitizes the path against directory traversal, whereas it merely normalizes the path by eliminating redundant separators and resolving relative components. This means an attacker could craft inputs with traversal sequences such as `../../` that `Clean` will simplify without enforcing directory boundaries. Exploiting this weakness, an adversary could request files outside the intended `./static` directory, potentially accessing sensitive system files or configuration data. The business impact includes exposure of confidential information, increased risk of further intrusion, and potential compliance and reputational damage.


context: go.lang.security.filepath-clean-misuse.filepath-clean-misuse `Clean` is not intended to sanitize against path traversal attacks. This function is for finding the shortest path name equivalent to the given input. Using `Clean` to sanitize file reads may expose this application to path traversal attacks, where an attacker could access arbitrary files on the server. To fix this easily, write this: `filepath.FromSlash(path.Clean("/"+strings.Trim(req.URL.Path, "/")))` However, a better solution is using the `SecureJoin` function in the package `filepath-securejoin`. See https://pkg.go.dev/github.com/cyphar/filepath-securejoin#section-readme.

# Vulnerability Breakdown
This vulnerability involves incorrect usage of Go's `filepath.Clean` function which fails to prevent directory traversal attacks in a file server application.

1. **Key vulnerability elements**:
   - Using `filepath.Clean` to sanitize user-controlled URL paths
   - Incorrectly assuming `Clean` prevents directory traversal (it merely normalizes paths)
   - Direct concatenation of the "cleaned" path with the base directory
   - No validation to ensure the final path remains within the intended directory

2. **Potential attack vectors**:
   - Crafting URLs containing path traversal sequences like `../../`
   - Accessing sensitive system files outside the intended directory
   - Reading configuration files potentially containing credentials
   - Obtaining source code to discover further vulnerabilities

3. **Severity assessment**:
   - Network-accessible attack vector requiring no special privileges
   - Low complexity exploitation requiring minimal technical knowledge
   - High confidentiality impact as any file on the system could potentially be read
   - No direct integrity or availability impact as the vulnerability allows read-only access

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): None (N) 
   - Availability (A): None (N) 

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

# Description
A path traversal vulnerability exists in Acme Corp's Golang-based file server due to improper sanitization of file paths from HTTP requests. The application incorrectly relies on `filepath.Clean` to secure file paths, but this function only normalizes paths without preventing directory traversal attacks.

```go
// Vulnerable code
cleanPath := filepath.Clean("/" + strings.Trim(req.URL.Path, "/"))
http.ServeFile(w, req, "./static"+cleanPath)

```

This allows attackers to craft URLs with directory traversal sequences (e.g., `../../etc/passwd`) to access files outside the intended `./static` directory. The `filepath.Clean` function merely simplifies these paths but doesn't restrict them to the intended directory, enabling unauthorized access to sensitive system files, configuration data, or other protected resources.

# CVSS
**Score**: 7.5 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N \
**Severity**: High

The High severity rating (7.5) is justified by the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability is exploitable remotely by anyone who can send HTTP requests to the server
- **Low Attack Complexity (AC:L)**: Exploitation requires no special conditions or circumstances; an attacker simply needs to craft a URL with directory traversal sequences
- **No Privileges Required (PR:N)**: The attacker doesn't need any authentication or special privileges to exploit the vulnerability
- **No User Interaction (UI:N)**: The vulnerability can be exploited without any action from legitimate users
- **Unchanged Scope (S:U)**: The vulnerability affects only the vulnerable component itself, without impacting other components
- **High Confidentiality Impact (C:H)**: The vulnerability allows complete disclosure of all file data on the system, potentially including sensitive configuration files, credentials, or personal data
- **No Integrity Impact (I:N)**: The vulnerability only allows reading files, not modifying them
- **No Availability Impact (A:N)**: The vulnerability doesn't cause denial of service or other availability issues

The severity is High rather than Critical because the scope remains unchanged and there's no impact on integrity or availability. However, the potential for full system file access with no authentication required makes this a serious security issue requiring immediate attention.

# Exploitation Scenarios
**Scenario 1: System File Access**
An attacker discovers the vulnerable file server and sends a request to `http://server:8080/../../../etc/passwd`. The server processes this as follows:
1. Extracts the path `/../../../etc/passwd`
2. Trims leading slashes: `../../../etc/passwd`
3. Adds a leading slash: `/../../../etc/passwd`
4. Applies `filepath.Clean()` which normalizes to `/etc/passwd`
5. Appends to `./static` becoming `./static/etc/passwd`
6. Serves the system's password file to the attacker

**Scenario 2: Configuration File Disclosure**
The attacker targets configuration files that might contain sensitive information:
1. Sends a request to `http://server:8080/../../app/config.json`
2. The path is normalized to `/app/config.json`
3. The server reads from `./static/app/config.json` which resolves to the actual application config
4. The attacker obtains database credentials, API keys, or other secrets

**Scenario 3: Source Code Exfiltration**
To find further vulnerabilities, the attacker accesses the application's source code:
1. Sends requests like `http://server:8080/../../main.go`
2. Examines returned source code for security issues, hardcoded credentials, or logic flaws
3. Uses this information to craft more sophisticated attacks against the application

**Scenario 4: Lateral Movement**
The attacker leverages the file disclosure to access SSH keys or other authentication material:
1. Requests `http://server:8080/../../../home/user/.ssh/id_rsa`
2. Uses the obtained private key to authenticate to other systems
3. Expands their foothold within the infrastructure

# Impact Analysis
**Business Impact:**
- Unauthorized access to confidential information including potential intellectual property
- Regulatory violations and potential penalties if sensitive user data is exposed (GDPR, CCPA, etc.)
- Reputational damage if a breach is disclosed or discovered by customers
- Loss of customer trust when security incidents become public
- Direct financial costs associated with incident response, forensics, and remediation
- Potential legal liability if sensitive information is used for fraudulent purposes

**Technical Impact:**
- Exposure of system information that could facilitate more sophisticated attacks
- Disclosure of configuration files potentially containing credentials, API keys, or other secrets
- Access to internal application logic through source code exfiltration
- Information about the system's users, services, and infrastructure through log files
- Potential for credential harvesting from configuration or user files
- Compromise of cryptographic materials (private keys, certificates) that could enable further attacks
- Detailed knowledge of application architecture that helps attackers identify additional vulnerabilities

# Technical Details
The vulnerability stems from a fundamental misunderstanding of Go's `filepath.Clean` function. This function is designed only to normalize file paths by removing redundant elements (like `./`) and resolving relative path components. It does not perform security validation or constraint enforcement.

```go
func fileHandler(w http.ResponseWriter, req *http.Request) {
    // Vulnerable path construction using filepath.Clean
    cleanPath := filepath.Clean("/" + strings.Trim(req.URL.Path, "/"))
    // Files are served from the "./static directory
    http.ServeFile(w, req, "./static"+cleanPath)
}

```

**How `filepath.Clean` processes paths:**

1. If a path contains `../` sequences, `Clean` resolves them by removing the previous path element
2. However, it doesn't prevent traversal beyond the intended root directory
3. For example, `filepath.Clean("/../../../etc/passwd")` returns `/etc/passwd`

**Exploitation mechanics:**

1. When a request for `http://server:8080/../../../etc/passwd` arrives:
   - `req.URL.Path` contains `/../../../etc/passwd`
   - After trimming, it becomes `../../../etc/passwd`
   - Adding the leading slash: `/../../../etc/passwd`
   - `filepath.Clean` normalizes to `/etc/passwd`

2. The final path constructed is `./static/etc/passwd`

3. When resolved by the operating system:
   - `./static` is the intended directory
   - `/etc/passwd` is treated as an absolute path or traverses upward
   - The file `/etc/passwd` is accessed instead of something within `./static`

**Key security principle violated:**

The code fails to implement proper path canonicalization and validation. It normalizes the path but doesn't enforce the constraint that the resulting path must remain within the intended base directory.

Unlike some other languages/frameworks that automatically prevent directory traversal (like PHP's `open_basedir` or Python's `os.path.realpath` with comparisons), Go requires explicit validation to ensure a path remains within intended boundaries.

# Remediation Steps
## Use SecureJoin for Safe Path Resolution

**Priority**: P0

Replace the vulnerable code with the `SecureJoin` function from the `github.com/cyphar/filepath-securejoin` package, which is specifically designed to prevent path traversal attacks:

```go
import (
    "net/http"
    "strings"
    "github.com/cyphar/filepath-securejoin"
)

func fileHandler(w http.ResponseWriter, req *http.Request) {
    // Extract the requested path
    requestPath := strings.Trim(req.URL.Path, "/")
    
    // Use SecureJoin to safely resolve the path
    safePath, err := securejoin.SecureJoin("./static", requestPath)
    if err != nil {
        http.Error(w, "Invalid path", http.StatusBadRequest)
        return
    }
    
    // Serve the file from the safely resolved path
    http.ServeFile(w, req, safePath)
}

```

The `SecureJoin` function ensures that the resolved path always remains within the specified base directory, regardless of how many `../` sequences are in the input. This effectively prevents path traversal attacks while still allowing legitimate subdirectory access.
## Implement Path Validation and Boundary Checking

**Priority**: P1

Add comprehensive path validation including explicit boundary checks to ensure the final path remains within the intended directory:

```go
import (
    "net/http"
    "path/filepath"
    "strings"
)

func fileHandler(w http.ResponseWriter, req *http.Request) {
    // Extract the requested path
    requestPath := strings.Trim(req.URL.Path, "/")
    
    // Reject paths containing suspicious patterns
    if strings.Contains(requestPath, "../") {
        http.Error(w, "Invalid path", http.StatusBadRequest)
        return
    }
    
    // Construct the file path
    filePath := filepath.Join("./static", requestPath)
    
    // Convert both paths to absolute paths for comparison
    staticDir, err := filepath.Abs("./static")
    if err != nil {
        http.Error(w, "Server error", http.StatusInternalServerError)
        return
    }
    
    absFilePath, err := filepath.Abs(filePath)
    if err != nil {
        http.Error(w, "Invalid path", http.StatusBadRequest)
        return
    }
    
    // Ensure the resolved path is within the static directory
    if !strings.HasPrefix(absFilePath, staticDir) {
        http.Error(w, "Access denied", http.StatusForbidden)
        return
    }
    
    // Serve the file
    http.ServeFile(w, req, filePath)
}

```

This implementation provides multiple layers of protection:
1. Early rejection of suspicious path patterns ("../")
2. Use of `filepath.Join` for proper path construction
3. Conversion to absolute paths to eliminate relative path ambiguities
4. Explicit boundary check to ensure the final path remains within the static directory


# References
* CWE-22 | [Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A01:2021 | [Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* filepath-securejoin | [Safe filepath joining that prevents directory traversal attacks](https://pkg.go.dev/github.com/cyphar/filepath-securejoin)
