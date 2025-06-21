# Path Traversal Vulnerability in Internal Go Web Application

# Vulnerability Case
During our recent security assessment of Acme Corp's web application built in Go, we discovered a critical path traversal vulnerability in an HTTP file retrieval endpoint. The vulnerability was identified while reviewing the source code, where the application concatenates a user-supplied query parameter directly to a base directory path without proper sanitization. This design flaw allows an attacker to inject directory traversal sequences (e.g., `../`) to access sensitive files, such as configuration files or private data stored on the filesystem. The vulnerable component leverages Go's standard net/http package and file I/O functions without the mitigation provided by the built-in `filepath.Clean` function. Exploiting this flaw could result in unauthorized file disclosure, potential file modifications, and significant operational and reputational impacts for the business.

```go
package main

import (
  "io/ioutil"
  "net/http"
)

func fileHandler(w http.ResponseWriter, r *http.Request) {
  // Vulnerable pattern: directly using unsanitized user input to build file path
  file := r.URL.Query().Get("file")
  content, err := ioutil.ReadFile("/var/app/data/" + file)
  if err != nil {
    http.Error(w, "File not found", http.StatusNotFound)
    return
  }
  w.Write(content)
}

func main() {
  http.HandleFunc("/read", fileHandler)
  http.ListenAndServe(":8080", nil)
}
```

In this scenario, exploitation is achieved by sending a crafted HTTP request to the /read endpoint with a parameter value such as `../../../../etc/passwd`, allowing the attacker to traverse directories and read sensitive files. This can expose critical system configurations and private data, potentially leading to regulatory non-compliance, data breaches, and severe business disruption.


context: go.net.path-traversal.net-http-path-traversal-taint.net-http-path-traversal-taint The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files. In Go, it is possible to sanitize user input and mitigate path traversal by using the built-in `filepath.Clean` function.

# Vulnerability Breakdown
This vulnerability involves a path traversal flaw in Acme Corp's internal Go web application that allows authenticated users to access files outside of the intended directory.

1. **Key vulnerability elements**:
   - Direct concatenation of user input to a file path without sanitization
   - Use of `ioutil.ReadFile` without path validation
   - Missing implementation of Go's built-in `filepath.Clean` function
   - Internal web application requiring authentication
   - No validation of user-supplied file parameter

2. **Potential attack vectors**:
   - Authenticated users sending HTTP requests with directory traversal sequences (e.g., `../`)
   - Insider threats accessing sensitive system files like `/etc/passwd`
   - Reading application configuration files containing credentials
   - Exposing internal application data not intended for the user's access level

3. **Severity assessment**:
   - High confidentiality impact due to unauthorized file access
   - Adjacent attack vector limited to internal network
   - Low privileges required (authentication needed)
   - Low complexity to exploit requiring only simple HTTP requests

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Adjacent (A) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): Low (L) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): None (N) 
   - Availability (A): None (N) 

# Description
A path traversal vulnerability has been identified in Acme Corp's internal Go web application, specifically in the file retrieval endpoint `/read`. The vulnerability exists because the application directly concatenates user-supplied input from the URL query parameter `file` to a base directory path without proper validation or sanitization.

```go
// Vulnerable code
file := r.URL.Query().Get("file")
content, err := ioutil.ReadFile("/var/app/data/" + file)

```

This insecure implementation allows authenticated users on the internal network to use directory traversal sequences (such as `../`) to navigate outside the intended directory and access arbitrary files on the server's filesystem. For example, a request to `/read?file=../../../../etc/passwd` could expose sensitive system user information.

The application fails to implement proper path sanitization using Go's built-in mechanisms like `filepath.Clean`, making it susceptible to this well-known vulnerability pattern despite being limited to authenticated internal users.

# CVSS
**Score**: 5.7 \
**Vector**: CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N \
**Severity**: Medium

The Medium severity rating (5.7) is justified by the following factors:

- **Adjacent attack vector (AV:A)**: The vulnerability is only exploitable from the internal network, not from the internet, which reduces the potential attack surface significantly.

- **Low attack complexity (AC:L)**: Exploiting this vulnerability remains straightforward and requires no special conditions or preparation. An attacker simply needs to craft a URL with the appropriate directory traversal sequences.

- **Low privileges required (PR:L)**: The vulnerable endpoint requires basic authentication, meaning an attacker must have valid credentials to exploit it. This significantly reduces the pool of potential attackers.

- **No user interaction (UI:N)**: The attack can be executed directly without requiring any actions from other users or administrators.

- **Unchanged scope (S:U)**: The vulnerability affects only resources managed by the same security authority (the web application and its accessible files).

- **High confidentiality impact (C:H)**: Successful exploitation allows authenticated attackers to read arbitrary files accessible to the application process, potentially including configuration files with credentials, private application data, and system files.

- **No integrity impact (I:N)**: Based on the code provided, the vulnerability appears to only allow reading files, not modifying them.

- **No availability impact (A:N)**: The vulnerability does not directly impact system availability or cause denial of service.

The severity is reduced from High to Medium primarily because of the Adjacent attack vector and Low privileges required, which substantially limit who can exploit this vulnerability.

# Exploitation Scenarios
**Scenario 1: Insider Threat Access to Sensitive Configurations**
An authenticated employee with basic access to the internal application sends a request to `/read?file=../../config/database.yml` to access the application's database configuration file, which contains database credentials with higher privileges than they should have. The employee uses these credentials to directly access the database and view sensitive HR data they shouldn't be able to see.

**Scenario 2: Lateral Movement by Malicious Insider**
An authenticated contractor with limited access to the internal network uses the path traversal vulnerability to access system files by sending requests like `/read?file=../../../../etc/passwd`. This provides information about system users which helps them identify potential targets for further attacks. They then use this information for social engineering or to attempt password guessing against internal systems.

**Scenario 3: Privilege Escalation via SSH Keys**
A malicious authenticated user exploits the vulnerability to read SSH private keys stored on the server by requesting `/read?file=../../../../home/admin/.ssh/id_rsa`. With this private key, they can authenticate to other internal systems as the admin user, effectively escalating their privileges across the network.

**Scenario 4: Intellectual Property Theft**
A disgruntled employee with basic authentication to the internal application uses path traversal to navigate the server directory structure and locate source code repositories. Using requests like `/read?file=../../../../var/www/src/proprietary-algorithm.go`, they exfiltrate valuable intellectual property to take to a competitor.

# Impact Analysis
**Business Impact:**
- Potential exposure of intellectual property to insider threats
- Regulatory violations if authenticated users can access personal data beyond their authorization level
- Internal security policy violations regarding least privilege principles
- Breach of segregation of duties if users can access information across departments
- Trust erosion among employees if the vulnerability is discovered and exploited internally
- Potential for internal sabotage or espionage if sensitive configurations are exposed

**Technical Impact:**
- Unauthorized access to sensitive configuration files containing internal credentials and API keys
- Exposure of system information that could facilitate lateral movement within the internal network
- Compromise of user data confidentiality beyond intended access levels
- Privilege escalation potential if authentication credentials are exposed
- Unauthorized access to logs that may contain sensitive information
- Circumvention of internal access controls and security boundaries
- Cross-department data exposure where strict separation should be maintained

# Technical Details
The vulnerability is a path traversal (also known as directory traversal) flaw in an internal Go web application accessible only to authenticated users. The core issue exists in the `fileHandler` function that services the `/read` endpoint:

```go
func fileHandler(w http.ResponseWriter, r *http.Request) {
  // Vulnerable pattern: directly using unsanitized user input to build file path
  file := r.URL.Query().Get("file")
  content, err := ioutil.ReadFile("/var/app/data/" + file)
  if err != nil {
    http.Error(w, "File not found", http.StatusNotFound)
    return
  }
  w.Write(content)
}

```

**Vulnerability Mechanics:**

1. The handler extracts the `file` parameter from the URL query string using `r.URL.Query().Get("file")`
2. This value is directly concatenated to the base directory path (`/var/app/data/`) without any validation or sanitization
3. The application then uses `ioutil.ReadFile()` to read the file at the constructed path
4. The contents of the file are written directly to the HTTP response

**Exploitation Process:**

1. An authenticated user on the internal network crafts a specially formatted URL with directory traversal sequences, for example:
   `http://internal-app/read?file=../../../../etc/passwd`
2. The application constructs the file path: `/var/app/data/../../../../etc/passwd`
3. When the OS resolves this path, the `../` sequences navigate up the directory tree, resulting in the path `/etc/passwd`
4. The application reads and returns the contents of this sensitive system file

**Technical Factors Enabling the Vulnerability:**

1. **Missing Path Sanitization**: The application fails to sanitize or validate the user input before using it in a file operation
2. **Direct Path Concatenation**: Simply joining strings to form paths is unsafe without proper validation
3. **Failure to Use Security Features**: Go provides the `filepath.Clean` function specifically to address this issue, but it's not used
4. **No Path Containment Checks**: The application doesn't verify that the final path remains within the intended base directory
5. **Excessive Service Permissions**: Even with authentication requirements, the application process likely runs with permissions that allow it to read sensitive system files
6. **Assumption of Trust**: The authentication requirement may have led developers to assume that additional input validation was unnecessary

# Remediation Steps
## Implement Path Validation with filepath.Clean

**Priority**: P0

Use Go's built-in filepath package to sanitize and validate file paths before accessing files:

```go
package main

import (
  "io/ioutil"
  "net/http"
  "path/filepath"
  "strings"
)

func fileHandler(w http.ResponseWriter, r *http.Request) {
  // Get the user input
  fileName := r.URL.Query().Get("file")
  
  // Define the base directory
  baseDir := "/var/app/data"
  
  // Clean the path to remove any directory traversal sequences
  cleanFileName := filepath.Clean(fileName)
  
  // Ensure the file doesn't start with "../" after cleaning
  if strings.HasPrefix(cleanFileName, "../") || strings.HasPrefix(cleanFileName, "/") {
    http.Error(w, "Invalid file path", http.StatusBadRequest)
    return
  }
  
  // Construct the full path and ensure it stays within the base directory
  fullPath := filepath.Join(baseDir, cleanFileName)
  
  // Double-check that the path is within the base directory
  if !strings.HasPrefix(fullPath, baseDir) {
    http.Error(w, "Access denied", http.StatusForbidden)
    return
  }
  
  // Now it's safe to read the file
  content, err := ioutil.ReadFile(fullPath)
  if err != nil {
    http.Error(w, "File not found", http.StatusNotFound)
    return
  }
  
  w.Write(content)
}

```

This implementation:
1. Uses `filepath.Clean` to normalize the path and remove directory traversal sequences
2. Explicitly checks that the cleaned filename doesn't start with "../" or "/"
3. Uses `filepath.Join` for proper path construction rather than string concatenation
4. Performs a secondary check to ensure the final path stays within the base directory
## Implement Authorization Checks and File Access Controls

**Priority**: P1

Enhance security by adding user-specific authorization checks and strict file access controls:

```go
package main

import (
  "io/ioutil"
  "net/http"
  "path/filepath"
  "strings"
  "database/sql"
  "context"
)

// Assume we have an authenticated user from middleware
type User struct {
  ID       int
  Username string
  Role     string
}

// Check if a user has access to a specific file
func hasAccessToFile(db *sql.DB, user User, filePath string) bool {
  // Query the database to check if this user has access to this file
  var hasAccess bool
  err := db.QueryRowContext(
    context.Background(),
    "SELECT EXISTS(SELECT 1 FROM file_permissions WHERE user_id = ? AND file_path = ?)",
    user.ID, filePath,
  ).Scan(&hasAccess)
  
  if err != nil {
    // Log the error
    return false
  }
  
  // For admin users, allow broader access but still within base directory
  if user.Role == "admin" {
    return true
  }
  
  return hasAccess
}

func fileHandler(w http.ResponseWriter, r *http.Request) {
  // Get authenticated user from context (set by auth middleware)
  user, ok := r.Context().Value("user").(User)
  if !ok {
    http.Error(w, "Authentication required", http.StatusUnauthorized)
    return
  }
  
  // Get the requested file
  fileName := r.URL.Query().Get("file")
  baseDir := "/var/app/data"
  
  // Clean and validate the path
  cleanFileName := filepath.Clean(fileName)
  if strings.HasPrefix(cleanFileName, "../") || strings.HasPrefix(cleanFileName, "/") {
    http.Error(w, "Invalid file path", http.StatusBadRequest)
    return
  }
  
  // Construct the full path
  fullPath := filepath.Join(baseDir, cleanFileName)
  if !strings.HasPrefix(fullPath, baseDir) {
    http.Error(w, "Access denied", http.StatusForbidden)
    return
  }
  
  // Check if the user has access to this file
  db := r.Context().Value("database").(*sql.DB) // Get DB from context
  if !hasAccessToFile(db, user, fullPath) {
    http.Error(w, "Access denied", http.StatusForbidden)
    return
  }
  
  // Read the file only if all checks pass
  content, err := ioutil.ReadFile(fullPath)
  if err != nil {
    http.Error(w, "File not found", http.StatusNotFound)
    return
  }
  
  w.Write(content)
}

```

This enhanced implementation:
1. Validates the authenticated user from the request context
2. Implements path sanitization as in the previous solution
3. Adds a permission check against a database to enforce user-specific file access controls
4. Provides role-based access control with admin users having broader (but still contained) access
5. Maintains multiple layers of defense against path traversal even with authentication


# References
* CWE-22 | [Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* CWE-200 | [Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
