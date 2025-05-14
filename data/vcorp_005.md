# Path Traversal in C++ File Handling Component

# Vulnerability Case
During a review of Acme Corp's C++ file handling component, a potential path traversal vulnerability was discovered when analyzing the module responsible for constructing file paths. The application concatenates unsanitized user input directly to a base directory without proper canonicalization, leading to a potential bypass of intended file boundaries. This issue was identified during unit testing where anomalous log entries indicated access attempts beyond the designated directory, and subsequent manual code analysis confirmed that no input validation was in place.

```cpp
#include <iostream>
#include <fstream>
#include <string>

int main(int argc, char* argv[]) {
  std::string baseDirectory = "/var/app/data/";
  
  // Untrusted input concatenated directly into file path
  std::string userInput = (argc > 1) ? argv[1] : "";
  std::string filePath = baseDirectory + userInput;

  std::ifstream file(filePath);
  if (!file.is_open()) {
    std::cerr << "Error opening file: " << filePath << std::endl;
    return -1;
  }
  
  std::cout << "File accessed successfully: " << filePath << std::endl;
  return 0;
}
```

The vulnerability arises from directly concatenating user-supplied input into a file system path without normalization or sanitization, a common misstep in C++ applications. An attacker can exploit this by injecting relative directory traversal sequences (e.g., `../../secret/config.cfg`) to manipulate the file path, potentially accessing sensitive files outside the intended directory. On systems such as Ubuntu 20.04 compiled with g++ in a typical deployment stack, this could lead to unauthorized disclosure of configuration data or user information. The business impact includes potential data breaches and loss of confidentiality, thereby increasing the risk of regulatory penalties and damage to Acme Corp’s reputation.

context: cpp.lang.security.filesystem.path-manipulation.path-manipulation The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files.

# Vulnerability Breakdown
This vulnerability involves improper path handling in Acme Corp's C++ file handling component where user input is directly concatenated to a base directory path without validation or sanitization.

1. **Key vulnerability elements**:
   - User-controlled input is directly concatenated to form a file path
   - No path validation or canonicalization is performed
   - No checks to ensure the final path remains within the intended directory
   - Standard C++ file handling libraries used without security controls

2. **Potential attack vectors**:
   - Providing relative path sequences like `../../` to traverse directory structure
   - Accessing sensitive system files outside the intended directory
   - Reading configuration files containing credentials or other sensitive data
   - Potentially accessing or modifying user data files

3. **Severity assessment**:
   - The vulnerability allows reading files outside intended boundaries
   - Local attack vector limits exposure somewhat
   - Low complexity to exploit with simple directory traversal sequences
   - No special privileges required to exploit
   - High confidentiality impact as sensitive files could be accessed

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Local (L) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): None (N) 
   - Availability (A): None (N) 

CVSS Vector: CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

# Description
A path traversal vulnerability has been identified in Acme Corp's C++ file handling component. The vulnerability exists because the application directly concatenates unsanitized user input to a base directory path without proper validation or canonicalization, potentially allowing attackers to access files outside the intended directory.

The vulnerable code:

```cpp
std::string baseDirectory = "/var/app/data/";
std::string userInput = (argc > 1) ? argv[1] : "";
std::string filePath = baseDirectory + userInput;

std::ifstream file(filePath);

```

By providing path traversal sequences (e.g., `../../secret/config.cfg`), an attacker can manipulate the file path to access sensitive files outside the intended directory. This could lead to unauthorized access to configuration files, user data, or system files, depending on the application's permissions.

# CVSS
**Score**: 6.2 \
**Vector**: CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N \
**Severity**: Medium

The CVSS score of 6.2 (Medium) is justified by the following factors:

- **Attack Vector (AV): Local (L)** - The vulnerability requires local access to the system to provide input to the application. This limits the potential attack surface compared to remotely exploitable vulnerabilities.

- **Attack Complexity (AC): Low (L)** - Exploiting the vulnerability is straightforward and requires minimal effort. An attacker simply needs to provide path traversal sequences as input.

- **Privileges Required (PR): None (N)** - No authentication or special privileges are required to exploit the vulnerability beyond the ability to run the application with user input.

- **User Interaction (UI): None (N)** - The vulnerability can be exploited without requiring any action from users other than the attacker.

- **Scope (S): Unchanged (U)** - The vulnerability affects only resources managed by the same security authority.

- **Confidentiality (C): High (H)** - An attacker could potentially access any file on the system that the application has permission to read, including sensitive configuration files, credentials, or user data.

- **Integrity (I): None (N)** - Based on the code provided, this appears to be a read-only operation with no evidence of file modification capabilities.

- **Availability (A): None (N)** - The vulnerability does not impact system availability.

The overall Medium severity reflects the significant confidentiality impact balanced against the local attack vector requirement.

# Exploitation Scenarios
**Scenario 1: Accessing System Configuration Files**

An attacker provides the input `../../../../etc/passwd` to the vulnerable application. The application constructs the path `/var/app/data/../../../../etc/passwd`, which resolves to `/etc/passwd`. If the application has sufficient permissions, it reads and displays the system's password file, revealing usernames and other system account information.

**Scenario 2: Obtaining Application Secrets**

The attacker examines the application's behavior and directory structure, then provides the input `../../.env` or `../../config/database.ini`. This could allow access to configuration files containing database credentials, API keys, or other sensitive information stored outside the intended data directory but still accessible to the application.

**Scenario 3: Accessing User Data**

If the application is multi-user, an attacker might use path traversal to access another user's data. For example, providing `../../../home/other-user/.ssh/id_rsa` could potentially expose another user's SSH private key if file permissions allow it and the application runs with appropriate privileges.

# Impact Analysis
**Business Impact:**
- Potential exposure of sensitive configuration data including credentials
- Risk of unauthorized access to user data, potentially violating privacy regulations
- Possible regulatory penalties from data protection authorities if personal data is exposed
- Loss of customer trust if a breach occurs and is disclosed
- Potential intellectual property theft if proprietary data is accessible

**Technical Impact:**
- Unauthorized access to files outside the intended directory structure
- Potential exposure of system information that aids in further attacks
- Compromise of secrets (API keys, passwords) that could lead to secondary attacks
- Information disclosure that could help attackers map the application's environment
- Violation of the principle of least privilege if sensitive files become accessible

# Technical Details
The vulnerability is a classic path traversal issue (CWE-22) resulting from improper handling of user-supplied filenames. The core problem exists in the following code:

```cpp
std::string baseDirectory = "/var/app/data/";
  
// Untrusted input concatenated directly into file path
std::string userInput = (argc > 1) ? argv[1] : "";
std::string filePath = baseDirectory + userInput;

std::ifstream file(filePath);

```

The vulnerability arises from several key issues:

1. **Direct Path Concatenation**: The application simply appends user input to a base directory string without any validation or sanitization.

2. **No Path Canonicalization**: The code doesn't normalize the resulting path to identify and prevent directory traversal sequences.

3. **No Path Validation**: There are no checks to ensure the final path remains within the intended directory.

4. **Unrestricted File Access**: The `std::ifstream` will attempt to open any file that the application has permission to access.

When the operating system resolves the file path, directory traversal sequences (`../`) are processed naturally. For example, if an attacker provides `../../../../etc/passwd` as input, the constructed path `/var/app/data/../../../../etc/passwd` resolves to `/etc/passwd`.

This is particularly dangerous in the C++ context because:

1. The standard C++ library doesn't provide built-in protection against path traversal
2. C++17's `std::filesystem` includes tools to address this (like `canonical()` and `relative()`), but they must be explicitly used
3. The application might run with elevated privileges in some contexts, increasing the impact

The vulnerability was detected during unit testing through anomalous log entries and confirmed through manual code review, indicating that proper security testing procedures were followed, but the vulnerability wasn't caught during development.

# Remediation Steps
## Implement Path Canonicalization and Validation

**Priority**: P0

Use C++17's `std::filesystem` library to properly canonicalize and validate file paths:

```cpp
#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>

namespace fs = std::filesystem;

bool isPathSafe(const fs::path& base_dir, const fs::path& requested_path) {
    // Canonicalize both paths to resolve any .. or . segments
    fs::path canonical_base = fs::canonical(base_dir);
    
    // Get the absolute path but don't follow symlinks yet
    fs::path absolute_requested = fs::absolute(requested_path);
    
    // Check if the requested path exists and is a regular file
    if (!fs::exists(absolute_requested) || !fs::is_regular_file(absolute_requested)) {
        return false;
    }
    
    // Now get canonical path (this resolves symlinks too)
    fs::path canonical_requested;
    try {
        canonical_requested = fs::canonical(absolute_requested);
    } catch (const fs::filesystem_error&) {
        return false; // Path couldn't be canonicalized
    }
    
    // Check if the canonical requested path starts with the canonical base path
    auto requested_str = canonical_requested.string();
    auto base_str = canonical_base.string();
    
    return requested_str.compare(0, base_str.length(), base_str) == 0;
}

int main(int argc, char* argv[]) {
    fs::path baseDirectory = "/var/app/data/";
    
    // Create a proper path using the filesystem library
    std::string userInput = (argc > 1) ? argv[1] : "";
    fs::path requestedPath = baseDirectory / userInput;
    
    // Validate the path is safe
    if (!isPathSafe(baseDirectory, requestedPath)) {
        std::cerr << "Error: Invalid or unsafe file path requested" << std::endl;
        return -1;
    }
    
    // Open the file using the validated path
    std::ifstream file(requestedPath);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << requestedPath << std::endl;
        return -1;
    }
    
    std::cout << "File accessed successfully: " << requestedPath << std::endl;
    return 0;
}

```

This implementation:
1. Uses `std::filesystem::path` for proper path handling
2. Properly joins paths using the `/` operator instead of string concatenation
3. Canonicalizes paths to resolve `.` and `..` segments
4. Explicitly checks that the requested file's path starts with the base directory
5. Includes additional checks for file existence and type
## Implement Input Validation and Whitelisting

**Priority**: P1

Add strict input validation to reject suspicious file paths and implement a whitelist approach:

```cpp
#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <filesystem>

namespace fs = std::filesystem;

bool isValidFilename(const std::string& filename) {
    // Reject empty filenames
    if (filename.empty()) {
        return false;
    }
    
    // Check for directory traversal sequences
    if (filename.find("../") != std::string::npos || 
        filename.find("./") != std::string::npos || 
        filename.find("\\..\\") != std::string::npos) {
        return false;
    }
    
    // Only allow alphanumeric characters, underscore, hyphen, and period
    // You may need to adjust this pattern based on your specific requirements
    static const std::regex valid_pattern("^[a-zA-Z0-9_\-\.]+$");
    if (!std::regex_match(filename, valid_pattern)) {
        return false;
    }
    
    return true;
}

int main(int argc, char* argv[]) {
    fs::path baseDirectory = "/var/app/data/";
    
    // Validate and sanitize user input
    std::string userInput = (argc > 1) ? argv[1] : "";
    
    // Strip any path components, only use the filename
    fs::path inputPath(userInput);
    std::string filename = inputPath.filename().string();
    
    // Validate the filename
    if (!isValidFilename(filename)) {
        std::cerr << "Error: Invalid filename" << std::endl;
        return -1;
    }
    
    // Construct the full path with the validated filename
    fs::path filePath = baseDirectory / filename;
    
    // Open the file
    std::ifstream file(filePath);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filePath << std::endl;
        return -1;
    }
    
    std::cout << "File accessed successfully: " << filePath << std::endl;
    return 0;
}

```

This implementation:
1. Extracts only the filename component from user input, discarding any path information
2. Validates the filename against a whitelist of allowed characters
3. Explicitly checks for and rejects directory traversal sequences
4. Constructs the path using the filesystem path join operator
5. Provides clear error messages for security violations


# References
* CWE-22 | [Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A01:2021 | [Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
* CWE-99 | [Improper Control of Resource Identifiers ('Resource Injection')](https://cwe.mitre.org/data/definitions/99.html)
