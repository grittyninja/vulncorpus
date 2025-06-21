# Path Traversal in Go-Gin API Endpoint

# Vulnerability Case
During a comprehensive review of Acme Corp's Go-based microservices deployed via the Gin framework, our team identified a path traversal vulnerability in an API endpoint that constructs file paths from unsanitized user input. The endpoint accepts a filename via a query parameter and utilizes Go's native `filepath.Clean` function without ensuring that the resultant path remains confined to the designated directory. During dynamic testing, crafted input containing directory traversal sequences enabled access to files outside the expected file storage area. The issue was confirmed through taint analysis, where user-controlled data flowed directly into sensitive file operations. This vulnerability exposes the system to unauthorized file disclosure, directly impacting data confidentiality.

```go
package main

import (
        "io/ioutil"
        "net/http"
        "path/filepath"

        "github.com/gin-gonic/gin"
)

func main() {
        router := gin.Default()

        router.GET("/file", func(c *gin.Context) {
                // Retrieve user-supplied file name parameter
                filename := c.Query("name")
                // Construct file path from untrusted input with minimal sanitization.
                // Note: filepath.Clean does not enforce directory boundaries.
                filePath := filepath.Join("/var/app/files", filepath.Clean(filename))
                data, err := ioutil.ReadFile(filePath)
                if err != nil {
                        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
                        return
                }
                c.Data(http.StatusOK, "text/plain", data)
        })

        router.Run(":8080")
}
```

An attacker can exploit this vulnerability by manipulating the query parameter (e.g., using sequences like `../`) to traverse directories and access files that lie outside the intended base directory. Although the use of `filepath.Clean` normalizes the path, it does not enforce a strict boundary check against the designated directory, leaving the application prone to unauthorized file read operations. Successful exploitation might allow an adversary to access confidential configuration files or sensitive user data stored on the server. In a production environment relying on Go and the Gin framework on Linux, the resulting breach can have significant business implications, including data leakage, regulatory compliance violations, and reputational damage that may incur consequential financial losses.

context: go.gin.path-traversal.gin-path-traversal-taint.gin-path-traversal-taint The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files. In Go, it is possible to sanitize user input and mitigate path traversal by using the built-in `filepath.Clean` function.

# Vulnerability Breakdown
This vulnerability involves a path traversal weakness in Acme Corp's Go-based microservice API built using the Gin framework. The code constructs file paths using unsanitized user input, which can lead to unauthorized file access.

1. **Key vulnerability elements**:
   - Direct use of user-controlled filename parameter in file path construction
   - Improper reliance on filepath.Clean() which normalizes paths but doesn't enforce directory boundaries
   - Failure to validate that final path stays within intended directory
   - Exposure of sensitive system files and directories

2. **Potential attack vectors**:
   - Crafting query parameters with directory traversal sequences (e.g., `../`)
   - Requesting system files such as `/var/app/files/../../../etc/passwd`
   - Exploiting network-accessible endpoint requiring no authentication
   - Potential chaining with other vulnerabilities for system compromise

3. **Severity assessment**:
   - High confidentiality impact due to arbitrary file read capability
   - No integrity impact as the code only demonstrates read operations
   - No direct availability impact identified
   - Network attack vector allowing remote exploitation
   - Low complexity attack requiring minimal skills

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): None (N) 
   - Availability (A): None (N) 

# Description
A path traversal vulnerability has been identified in Acme Corp's Go-based microservice API built using the Gin framework. The vulnerable endpoint (`/file`) accepts a filename via a query parameter and uses it to construct a file path without proper validation. Although the code attempts to sanitize the input using `filepath.Clean()`, this function only normalizes paths and does not prevent directory traversal attacks.

```go
filePath := filepath.Join("/var/app/files", filepath.Clean(filename))
data, err := ioutil.ReadFile(filePath)

```

With this implementation, an attacker can supply input containing directory traversal sequences (e.g., `../`) to access files outside the intended directory. For example, a request to `/file?name=../../../etc/passwd` would allow the attacker to read the server's password file, potentially exposing sensitive system information. The vulnerability affects the confidentiality of data on the server, allowing unauthorized access to files that should be restricted.

# CVSS
**Score**: 7.5 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N \
**Severity**: High

The High severity rating (7.5) is justified by the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability is exploitable remotely through HTTP requests to the API endpoint, making it accessible to any network attacker.

- **Low Attack Complexity (AC:L)**: Exploiting this vulnerability is straightforward and requires minimal specialized knowledge. An attacker simply needs to craft a URL with directory traversal sequences.

- **No Privileges Required (PR:N)**: The vulnerable endpoint doesn't require authentication, allowing anonymous attackers to exploit it.

- **No User Interaction (UI:N)**: Exploitation is completely automated and doesn't require any user interaction.

- **Unchanged Scope (S:U)**: The vulnerability affects resources managed by the same security authority as the vulnerable component.

- **High Confidentiality Impact (C:H)**: Successful exploitation allows reading arbitrary files accessible to the application's user context, potentially including configuration files, credentials, and sensitive business data.

- **No Integrity Impact (I:N)**: The vulnerable code only demonstrates file read operations (ioutil.ReadFile) and does not show capability for modifying or deleting files.

- **No Availability Impact (A:N)**: There's no direct impact on system availability; the service continues to function normally.

# Exploitation Scenarios
**Scenario 1: Sensitive Configuration Exposure**
An attacker discovers the vulnerable API endpoint and crafts a request to access sensitive configuration files: `GET /file?name=../../etc/app-config.json`. The application constructs the path `/var/app/files/../../etc/app-config.json`, which resolves to `/etc/app-config.json`. This file contains database credentials, API keys, and other sensitive information, allowing the attacker to gain access to additional systems.

**Scenario 2: User Data Theft**
An attacker explores the system by using incremental path traversal attacks: `GET /file?name=../users/user1_data.json`. The application returns user data files containing personal information, payment details, or other sensitive data stored in a parallel directory to the intended files directory.

**Scenario 3: Source Code Access**
The attacker retrieves the application's source code by traversing to its location: `GET /file?name=../../../opt/app/main.go`. By analyzing the source code, the attacker discovers additional vulnerabilities, hardcoded credentials, and internal API details that can be exploited for further attacks.

**Scenario 4: Log File Analysis**
An attacker accesses system logs via: `GET /file?name=../../../../var/log/auth.log`. By examining authentication logs, the attacker identifies usernames, login patterns, and potentially debugging information that aids in crafting more targeted attacks against the system.

# Impact Analysis
**Business Impact:**
- Potential exposure of sensitive customer data, leading to privacy violations and breach notification requirements
- Risk of compliance violations with regulations like GDPR, CCPA, or industry-specific standards
- Reputational damage if vulnerability is exploited and publicly disclosed
- Financial impact from breach remediation costs, regulatory fines, and potential litigation
- Loss of competitive advantage if proprietary information or intellectual property is exposed

**Technical Impact:**
- Unauthorized access to sensitive configuration files potentially containing credentials and API keys
- Exposure of application source code, revealing additional security weaknesses and business logic
- Potential for lateral movement within the infrastructure if the exposed files contain credentials
- Security control bypass, as attackers can read restricted files outside the intended directory
- Information disclosure that could facilitate more targeted attacks against the system
- Compromise of the principle of least privilege, as attackers gain access to information beyond what the application should expose

# Technical Details
The vulnerability is a classic path traversal (also known as directory traversal) issue in the Go application's file handling logic. The root cause is improper sanitization of user-controlled file paths combined with unsafe file operations.

```go
func main() {
	router := gin.Default()
	router.GET("/file", func(c *gin.Context) {
		// Retrieve user-supplied file name parameter
		filename := c.Query("name")
		// Construct file path from untrusted input with minimal sanitization.
		// Note: filepath.Clean does not enforce directory boundaries.
		filePath := filepath.Join("/var/app/files", filepath.Clean(filename))
		data, err := ioutil.ReadFile(filePath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.Data(http.StatusOK, "text/plain", data)
	})
	router.Run(":8080")
}

```

**Key Technical Issues:**

1. **Misconception about `filepath.Clean()`**:
   The code uses `filepath.Clean()` which only normalizes a path by removing elements like extra slashes and resolving `.` and `..` references within the path string. However, it does not prevent path traversal attacks - it simply normalizes the traversal sequences. For example, `filepath.Clean("../../../etc/passwd")` returns `../../../etc/passwd` as a normalized but still traversing path.

2. **Path Construction with `filepath.Join()`**:
   The code uses `filepath.Join()` to combine the base directory and user input. While this function is appropriate for path construction, it doesn't provide any security guarantees against directory traversal. When `filepath.Join("/var/app/files", "../../../etc/passwd")` is executed, it correctly produces `/var/app/files/../../../etc/passwd`, which when resolved by the OS becomes `/etc/passwd`.

3. **Lack of Path Validation**:
   The application fails to verify that the final constructed path still resides within the intended base directory (`/var/app/files`). A proper implementation would check if the absolute path of the file starts with the absolute path of the base directory.

4. **Error Message Information Disclosure**:
   The error handling returns the raw error message to the client, which might contain sensitive information about the file system structure, further aiding attackers in their exploitation attempts.

**Exploitation Mechanics:**

1. An attacker crafts a request with a path traversal sequence: `GET /file?name=../../../etc/passwd`
2. The application processes this as:
   - `filename = "../../../etc/passwd"`
   - `filepath.Clean(filename)` returns `../../../etc/passwd` (still traversing)
   - `filepath.Join("/var/app/files", "../../../etc/passwd")` returns `/var/app/files/../../../etc/passwd`
3. The system resolves this path to `/etc/passwd` and reads the file
4. The contents are returned to the attacker

The vulnerability is particularly concerning because:
1. It requires no authentication
2. It's exploitable with a simple HTTP request
3. It potentially exposes any file readable by the application's user context

# Remediation Steps
## Implement Path Validation Using filepath.Abs and filepath.Rel

**Priority**: P0

Enhance the file path validation to ensure that the final resolved path remains within the intended base directory:

```go
func secureFilePath(baseDir, filename string) (string, error) {
	// Get the absolute path of the base directory
	baseAbs, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Construct the potential file path
	potentialPath := filepath.Join(baseAbs, filepath.Clean(filename))

	// Get the absolute path to resolve any symlinks or relative paths
	fileAbs, err := filepath.Abs(potentialPath)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Check if the file path is within the base directory
	rel, err := filepath.Rel(baseAbs, fileAbs)
	if err != nil || strings.HasPrefix(rel, "..") || strings.HasPrefix(rel, "/") {
		return "", fmt.Errorf("invalid file path: access denied")
	}

	return fileAbs, nil
}

// In your handler function:
router.GET("/file", func(c *gin.Context) {
	filename := c.Query("name")
	filePath, err := secureFilePath("/var/app/files", filename)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file request"})
		return
	}

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		// Don't expose raw error messages to clients
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file"})
		return
	}

	c.Data(http.StatusOK, "text/plain", data)
})

```

This solution:
1. Resolves both paths to absolute paths to handle any symlinks or relative references
2. Uses `filepath.Rel` to ensure the requested file is within the base directory
3. Rejects paths with `..` or absolute paths that escape the base directory
4. Provides generic error messages that don't reveal file system details
## Implement Allowlist-Based File Access

**Priority**: P1

Instead of allowing access to any file within a directory, implement an allowlist approach to restrict access to only specific pre-approved files:

```go
func main() {
	router := gin.Default()

	// Create a map of allowed files
	allowedFiles := map[string]string{
		"config": "/var/app/files/config.json",
		"readme": "/var/app/files/readme.txt",
		"users":  "/var/app/files/users/public.json",
		// Add other allowed files
	}

	router.GET("/file", func(c *gin.Context) {
		// Get the file identifier from the query
		fileID := c.Query("id")

		// Check if the requested file is in the allowlist
		filePath, exists := allowedFiles[fileID]
		if !exists {
			c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
			return
		}

		// Read the file (now guaranteed to be an allowed file)
		data, err := ioutil.ReadFile(filePath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file"})
			return
		}

		c.Data(http.StatusOK, "text/plain", data)
	})

	router.Run(":8080")
}

```

This approach:
1. Eliminates path traversal risk by not using user input in file path construction
2. Provides explicit control over which files can be accessed
3. Simplifies access control by using identifiers rather than file paths
4. Can be extended to include permission checks or other validations


# References
* CWE-22 | [Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* CWE-200 | [Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* A01:2021 | [Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
