# Path Traversal in Golang Web Application

# Vulnerability Case
During a routine security assessment of Acme Corp's web application—built using Golang with the Gorilla Mux router—we discovered a path traversal vulnerability in an API endpoint that serves file content. The endpoint constructs file paths by directly concatenating unsanitized user input, allowing attackers to manipulate the file path by injecting directory traversal sequences. During dynamic testing and code review, we observed that an HTTP request with crafted traversal patterns (e.g., `../../`) could lead to unauthorized access of sensitive files outside the designated directory. This vulnerability poses a significant risk of unauthorized data exposure, potentially compromising configuration or user data.  

```go
package main

import (
        "fmt"
        "io/ioutil"
        "net/http"

        "github.com/gorilla/mux"
)

func fileHandler(w http.ResponseWriter, r *http.Request) {
        vars := mux.Vars(r)
        // Vulnerable pattern: Directly using unsanitized filename from user input.
        fileName := vars["filename"]
        filePath := "/var/app/data/" + fileName

        // No sanitization or validation (e.g., filepath.Clean) applied
        data, err := ioutil.ReadFile(filePath)
        if err != nil {
                http.Error(w, "File not found", http.StatusNotFound)
                return
        }
        fmt.Fprintf(w, "File content: %s", data)
}

func main() {
        router := mux.NewRouter()
        router.HandleFunc("/files/{filename}", fileHandler)
        http.ListenAndServe(":8080", router)
}
```  

An attacker can exploit this vulnerability by crafting HTTP requests that insert directory traversal sequences (e.g., `../../filename`) into the `filename` parameter, thereby accessing files outside the intended `/var/app/data/` directory. The exploitation methodology involves sending malicious requests during active application runtime to read sensitive files. Given that the technology stack leverages common Golang libraries (including Gorilla Mux for routing and the standard I/O package), the impact can be broad-reaching across the enterprise environment, potentially leading to data breaches and significant business disruption.  

context: go.gorilla.path-traversal.gorilla-path-traversal.gorilla-path-traversal-taint The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files. In Go, it is possible to sanitize user input and mitigate path traversal by using the built-in `filepath.Clean` function.

# Vulnerability Breakdown
This vulnerability involves a path traversal issue in Acme Corp's Golang web application that uses Gorilla Mux router. The vulnerability allows attackers to access files outside the intended directory structure.

1. **Key vulnerability elements**:
   - Direct concatenation of unsanitized user input to form file paths
   - No path validation or sanitization using functions like `filepath.Clean`
   - Unrestricted file reading capability via `ioutil.ReadFile`
   - Exposure through a public API endpoint `/files/{filename}`
   - Implementation in Golang using Gorilla Mux router

2. **Potential attack vectors**:
   - Using directory traversal sequences (e.g., `../../`) to navigate outside intended directories
   - Accessing sensitive system files like `/etc/passwd`
   - Reading application configuration files that may contain credentials
   - Exposing internal application code and logic
   - Gathering information for further targeted attacks

3. **Severity assessment**:
   - The vulnerability presents a high confidentiality risk as it allows reading arbitrary files
   - Network-based attack vector enables remote exploitation
   - Low attack complexity as exploitation is straightforward
   - No authentication required to exploit the vulnerability
   - Impacts limited to the application's read access permissions

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
A path traversal vulnerability exists in Acme Corp's Golang web application using the Gorilla Mux router. The vulnerability is present in the `/files/{filename}` API endpoint, which constructs file paths by directly concatenating unsanitized user input to a base directory path without proper validation.

```go
func fileHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	// Vulnerable pattern: Directly using unsanitized filename from user input.
	fileName := vars["filename"]
	filePath := "/var/app/data/" + fileName

	// No sanitization or validation (e.g., filepath.Clean) applied
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	fmt.Fprintf(w, "File content: %s", data)
}

```

By manipulating the `filename` parameter with directory traversal sequences (such as `../../`), attackers can access files outside the intended `/var/app/data/` directory. This could lead to unauthorized access to sensitive system files, configuration files containing credentials, or private application data, potentially compromising the confidentiality of the entire system.

# CVSS
**Score**: 7.5 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N \
**Severity**: High

The High severity rating (7.5) is justified by the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability is exploitable remotely over the network through the exposed API endpoint, without requiring physical or adjacent network access.

- **Low Attack Complexity (AC:L)**: Exploitation is straightforward and doesn't require specialized conditions or reconnaissance. An attacker simply needs to insert directory traversal sequences in the filename parameter.

- **No Privileges Required (PR:N)**: The vulnerable endpoint doesn't require authentication or authorization, allowing any user to exploit it.

- **No User Interaction (UI:N)**: Exploitation is completely automated and doesn't require any action from a legitimate user.

- **Unchanged Scope (S:U)**: The vulnerability affects only resources managed by the same security authority (the web application itself), without impacting other components.

- **High Confidentiality Impact (C:H)**: The vulnerability allows unauthorized access to potentially any file the application has read permissions for, including sensitive configuration files, credentials, and user data.

- **No Integrity Impact (I:N)**: Based on the code provided, the vulnerability only allows reading files, not modifying them.

- **No Availability Impact (A:N)**: The vulnerability doesn't affect the availability of the application or system resources.

The high confidentiality impact combined with the easy remote exploitability without authentication requirements makes this a significant security risk that warrants immediate attention.

# Exploitation Scenarios
**Scenario 1: Sensitive Configuration File Access**
An attacker sends a request to `/files/../../../../etc/config.json` which translates to accessing `/etc/config.json`. This file might contain database credentials, API keys, or other sensitive application secrets. The attacker can use these credentials to access restricted systems or data, potentially leading to a broader compromise of the infrastructure.

**Scenario 2: System File Exposure**
The attacker requests `/files/../../../../etc/passwd` to retrieve the system's user account information. While modern systems don't store password hashes in this file, it still provides valuable reconnaissance information about system users and can be combined with other attacks. Similarly, accessing files like `/etc/shadow` (if permissions allow) could expose password hashes.

**Scenario 3: Application Source Code Disclosure**
By traversing to the application's source code directory with requests like `/files/../../../../var/www/app/main.go`, attackers can expose the application's source code. This reveals implementation details, security mechanisms, hidden API endpoints, and potentially hard-coded secrets, enabling more sophisticated attacks against the application.

**Scenario 4: User Data Harvesting**
If the application stores user data in files (like JSONs, CSVs, or SQLite databases), an attacker could access them with traversal paths like `/files/../../var/app/user_data.db`. This could lead to exposure of personal information, account details, or other sensitive user data, resulting in privacy violations and potential regulatory issues.

# Impact Analysis
**Business Impact:**
- Unauthorized exposure of sensitive customer data, potentially violating privacy regulations like GDPR, CCPA, or HIPAA
- Disclosure of intellectual property or business-sensitive information
- Compromised security credentials leading to broader system access
- Potential regulatory fines and legal consequences from data breaches
- Loss of customer trust and reputational damage if the breach becomes public
- Costs associated with incident response, forensic investigation, and remediation

**Technical Impact:**
- Exposure of sensitive configuration files containing database credentials, API keys, or encryption keys
- Disclosure of system information useful for further attacks (user lists, installed software, etc.)
- Access to internal logs that might contain sensitive data or security information
- Revelation of application source code, exposing additional vulnerabilities or security controls
- Information leakage that aids attackers in building more targeted exploits
- Potential for credential harvesting leading to authentication-based attacks on other systems
- Mapping of internal system architecture and file system layout

# Technical Details
The vulnerability stems from insecure path construction in the application's file handling logic. The core issue can be broken down into several technical components:

1. **Direct String Concatenation:** The application uses simple string concatenation to build file paths:

```go
filePath := "/var/app/data/" + fileName

```

This approach provides no protection against directory traversal sequences in the `fileName` variable.

2. **Missing Path Sanitization:** The application fails to use Go's built-in path handling functions like `filepath.Clean()` which would normalize paths and remove redundant elements:

```go
// Missing sanitization code like:
cleanPath := filepath.Clean(fileName)

```

3. **No Path Validation:** There's no validation to ensure the final path remains within the intended directory:

```go
// Missing validation code like:
if !strings.HasPrefix(filepath.Clean(filePath), "/var/app/data/") {
    // Reject the request
}

```

4. **Exploitation Mechanics:**

When an attacker provides a filename containing traversal sequences like `../../etc/passwd`, the application:
- Concatenates it to create `/var/app/data/../../etc/passwd`
- The OS resolves this path to `/etc/passwd`
- The file is read and its contents returned to the attacker

5. **Vulnerability in Context:**

The issue is particularly severe because:
- It exists in a web API endpoint accessible over the network
- No authentication is required to exploit it
- The Go application likely runs with service-level permissions
- The Gorilla Mux router extracts the user input without any built-in sanitization
- The vulnerable code uses `ioutil.ReadFile()` which follows symbolic links, potentially expanding the attack surface

The vulnerability provides a direct file read capability limited only by the operating system permissions of the user running the application.

# Remediation Steps
## Implement Path Sanitization and Validation

**Priority**: P0

Modify the file handler to properly sanitize and validate file paths to prevent traversal attacks:

```go
func fileHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileName := vars["filename"]
	
	// Step 1: Clean the path to normalize directory traversal sequences
	cleanFileName := filepath.Clean(fileName)
	
	// Step 2: Reject paths that try to navigate above the base directory
	if strings.HasPrefix(cleanFileName, "..") || strings.Contains(cleanFileName, "../") {
		http.Error(w, "Invalid file path", http.StatusBadRequest)
		return
	}
	
	// Step 3: Use filepath.Join to construct paths securely
	basePath := "/var/app/data"
	filePath := filepath.Join(basePath, cleanFileName)
	
	// Step 4: Verify the constructed path is still within the intended directory
	if !strings.HasPrefix(filePath, basePath+"/") {
		http.Error(w, "Invalid file path", http.StatusBadRequest)
		return
	}
	
	// Now it's safe to read the file
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	fmt.Fprintf(w, "File content: %s", data)
}

```

This implementation provides multiple layers of protection:
1. Path normalization to handle traverse sequences
2. Explicit rejection of suspicious path patterns
3. Proper path joining that handles separators correctly
4. Secondary validation to ensure the final path remains within the base directory
## Implement File Access Restrictions

**Priority**: P1

Add additional security controls to restrict which files can be accessed:

```go
func fileHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileName := vars["filename"]
	
	// Step 1: Validate file extension or filename patterns
	allowedExtensions := map[string]bool{".txt": true, ".json": true, ".csv": true}
	fileExt := filepath.Ext(fileName)
	if !allowedExtensions[fileExt] {
		http.Error(w, "File type not allowed", http.StatusForbidden)
		return
	}
	
	// Step 2: Use a whitelist approach to validate filenames
	// Only alphanumeric characters, underscores, hyphens, and periods
	if matched, _ := regexp.MatchString("^[a-zA-Z0-9_\\-\\.]+$", fileName); !matched {
		http.Error(w, "Invalid filename format", http.StatusBadRequest)
		return
	}
	
	// Step 3: Apply path sanitization and validation as in the first solution
	cleanFileName := filepath.Clean(fileName)
	if strings.HasPrefix(cleanFileName, "..") || strings.Contains(cleanFileName, "../") {
		http.Error(w, "Invalid file path", http.StatusBadRequest)
		return
	}
	
	// Step 4: Use filepath.Join and verify containment
	basePath := "/var/app/data"
	filePath := filepath.Join(basePath, cleanFileName)
	if !strings.HasPrefix(filePath, basePath+"/") {
		http.Error(w, "Invalid file path", http.StatusBadRequest)
		return
	}
	
	// Now it's safe to read the file
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	fmt.Fprintf(w, "File content: %s", data)
}

```

This enhanced solution adds:
1. File extension whitelisting to limit access to specific file types
2. Strict filename pattern validation using regular expressions
3. Multiple layers of validation for defense in depth

Additionally, consider implementing system-level controls such as running the application with restricted OS permissions and using filesystem isolation techniques like chroot environments.


# References
* CWE-22 | [Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* CWE-23 | [Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)
* A01:2021 | [Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
