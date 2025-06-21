# Remote Command Injection via Insecure Eval

# Vulnerability Case
During our routine vulnerability assessment of Acme Corp’s automated deployment scripts, we discovered a critical flaw in a bash script that directly evaluates data fetched from a configuration server via an unencrypted `curl` command. The vulnerable code invokes the `eval` function on the server’s response without proper integrity checks, enabling attackers to inject arbitrary commands through:  
1) Compromise of the configuration server,  
2) Man-in-the-Middle (MITM) attacks on the unsecured HTTP connection, or  
3) DNS spoofing to redirect requests to malicious servers.  

This discovery was made while auditing the CI/CD pipeline where deployment scripts are executed on a Linux environment utilizing Bash (v5.0) and Curl (v7.68.0). If exploited, this vulnerability could allow adversaries to execute commands with the script’s privileges (potentially elevated), leading to remote code execution, lateral movement, and full system compromise. Given the script’s integration with Acme Corp’s critical infrastructure and the adjacent-network attack vector (CVSSv3.1 AV:A), the risk to business operations is critical.  

```bash
#!/bin/bash
# Vulnerable script snippet from /usr/local/bin/update_config.sh
CONFIG_URL=http://config.acme.local/api/update  # Insecure HTTP protocol
eval "$(curl -s ${CONFIG_URL})"  # Direct eval of untrusted remote content
echo "Configuration updated"
```  

The vulnerability arises from:  
- Unvalidated execution of remote content via `eval`  
- Use of HTTP (vs HTTPS), enabling MITM attacks  
- No cryptographic integrity checks of fetched data  

Exploitation scenarios include:  
- Attackers intercepting unencrypted traffic to inject malicious payloads  
- DNS poisoning to redirect to attacker-controlled servers  
- Persistent backdoor installation via initial compromise  

**Business Impact:**  
- Critical infrastructure compromise (CVSSv3.1 S:C)  
- Data breaches (C:H), service disruption (A:H), and reputational damage  
- Regulatory penalties due to inadequate security controls  

Context: bash.curl.security.curl-eval  
Data fetched via unsecured `curl` is directly evaluated, allowing command injection not only through server compromise but also via network-level attacks. Always validate and encrypt remote content.

# Vulnerability Breakdown
This vulnerability involves the direct evaluation of untrusted content retrieved from a remote server, enabling arbitrary command execution.

1. **Key vulnerability elements**:
   - Direct use of `eval` on content fetched via `curl`
   - No validation or sanitization of the retrieved data
   - HTTP connection without TLS, potentially allowing MITM attacks
   - Execution with the script's privileges, which could be elevated

2. **Potential attack vectors**:
   - Compromise of the configuration server
   - Network-level MITM attack on unencrypted HTTP connection
   - DNS spoofing to redirect to malicious server
   - Internal network access enabling traffic interception

3. **Severity assessment**:
   - High confidentiality impact from potential data theft
   - High integrity impact from potential data modification
   - High availability impact from service disruption capability
   - Adjacent attack vector requiring network positioning
   - Low complexity exploitation requiring basic skill

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Adjacent (A) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Changed (C)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): High (H) 

# Description
A critical command injection vulnerability exists in Acme Corp's deployment script `/usr/local/bin/update_config.sh`. The script retrieves configuration data from an internal server using a non-secured HTTP connection and directly executes the retrieved content using `eval` without any validation or sanitization.

```bash
eval "$(curl -s ${CONFIG_URL})"

```

This practice allows an attacker who can control or intercept the response from the configuration server to execute arbitrary commands with the privileges of the script. Since this script is part of the CI/CD pipeline, it likely runs with elevated permissions, potentially giving attackers significant access to critical infrastructure and sensitive data.

# CVSS
**Score**: 9.6 \
**Vector**: CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H \
**Severity**: Critical

The Critical severity rating is justified by:

- **Adjacent (A) attack vector**: The attacker needs to be in a logically adjacent network or have ability to intercept traffic to the config server.
- **Low (L) attack complexity**: Once the attacker has the position to intercept or control the server response, exploitation is straightforward.
- **No privileges (N) required**: The attacker doesn't need any privileges on the target system to execute the attack.
- **No user interaction (N)**: The vulnerability can be exploited without any action from users.
- **Changed (C) scope**: The vulnerability in the deployment script affects the security of the entire system, changing the security scope.
- **High (H) impacts across confidentiality, integrity, and availability**: Successful exploitation gives the attacker complete control over the affected system, allowing them to access sensitive data, modify system files, and disrupt services.

# Exploitation Scenarios
**Scenario 1: Configuration Server Compromise**
An attacker gains access to the configuration server (config.acme.local) and modifies the response to include malicious commands. When the deployment script runs, it fetches the malicious payload and executes it, giving the attacker remote command execution.

**Scenario 2: Man-in-the-Middle Attack**
An attacker with access to the internal network positions themselves between the server running the deployment script and the configuration server. The attacker intercepts the HTTP request and responds with malicious commands that get executed on the target system.

**Scenario 3: DNS Poisoning**
An attacker compromises the internal DNS infrastructure and configures config.acme.local to resolve to their controlled server. When the deployment script makes a request, it connects to the attacker's server, which delivers a malicious payload.

**Scenario 4: Persistent Backdoor Installation**
An attacker exploits this vulnerability once to install a persistent backdoor, such as a malicious cron job, SSH key, or system service. This allows continued access even if the original vulnerability is patched.

# Impact Analysis
**Business Impact:**
- Compromise of critical infrastructure systems could lead to significant operational disruption
- Potential data breaches exposing sensitive company and customer information
- Financial losses from operational downtime, recovery costs, and potential ransom demands
- Reputational damage if security breach becomes public
- Potential regulatory penalties for inadequate security controls
- Intellectual property theft affecting competitive position

**Technical Impact:**
- Remote code execution with the privileges of the deployment pipeline (potentially root/admin)
- Access to sensitive configuration data, secrets, and credentials
- Ability to modify application code, introducing backdoors or logic bombs
- Lateral movement through the internal network using compromised credentials
- Persistent access through installation of backdoors and alternate access mechanisms
- Potential complete compromise of the production environment
- Loss of integrity for deployment and build systems

# Technical Details
The vulnerability stems from a fundamental insecure coding practice: the direct evaluation of untrusted data. In this case, the bash script uses `eval` to execute content retrieved from a remote server without any validation.

```bash
#!/bin/bash
# Vulnerable script snippet from /usr/local/bin/update_config.sh

CONFIG_URL=http://config.acme.local/api/update

# Insecure pattern: directly eval'ing the remotely-fetched content
eval "$(curl -s ${CONFIG_URL})"
echo "Configuration updated"

```

**Exploitation Mechanics:**

1. The script makes an HTTP request to the configuration server
2. The configuration server responds with data that should be shell commands
3. The script passes this data directly to `eval` without any validation
4. Any commands in the response are executed with the script's privileges

**Security Issues:**

1. **No Input Validation**: The script blindly trusts and executes whatever it receives
2. **No Integrity Checks**: There's no verification that the response is legitimate
3. **Insecure Protocol**: Using HTTP instead of HTTPS allows for MITM attacks
4. **Improper Use of Eval**: `eval` is extremely dangerous when used with untrusted input

**Attack Surface:**
The vulnerability exposes the system to anyone who can:
- Compromise the configuration server
- Intercept network traffic between the script and server
- Redirect DNS resolution for the configuration server
- Otherwise influence the content returned by the curl command

Given that this script is part of the CI/CD pipeline, it likely runs with elevated privileges, making successful exploitation particularly severe.

# Remediation Steps
## Remove Direct Evaluation of Remote Content

**Priority**: P0

Instead of directly evaluating the returned content, implement a secure parsing mechanism:

```bash
#!/bin/bash

CONFIG_URL=https://config.acme.local/api/update
CONFIG_FILE=$(mktemp)

# Fetch configuration to a temporary file
curl -s -o "${CONFIG_FILE}" "${CONFIG_URL}"

# Validate the configuration file structure and content
if grep -q "^[a-zA-Z0-9_]*=[a-zA-Z0-9_\-\.\"'/ ]*$" "${CONFIG_FILE}"; then
  # Source the file instead of eval'ing it
  source "${CONFIG_FILE}"
  echo "Configuration updated successfully"
else
  echo "ERROR: Invalid configuration format detected"
  exit 1
fi

# Clean up
rm -f "${CONFIG_FILE}"

```

This approach:
1. Uses a temporary file instead of directly piping to eval
2. Performs basic validation of the configuration format
3. Uses 'source' instead of 'eval' for a more controlled execution
4. Implements error handling for invalid configurations
5. Uses HTTPS instead of HTTP for secure transport
## Implement Integrity Verification

**Priority**: P1

Add cryptographic verification of the configuration before executing it:

```bash
#!/bin/bash

CONFIG_URL=https://config.acme.local/api/update
SIG_URL=https://config.acme.local/api/update.sig
PUBLIC_KEY=/etc/acme/config-verification.pub
CONFIG_FILE=$(mktemp)
SIG_FILE=$(mktemp)

# Fetch configuration and signature
curl -s -o "${CONFIG_FILE}" "${CONFIG_URL}"
curl -s -o "${SIG_FILE}" "${SIG_URL}"

# Verify signature
if openssl dgst -sha256 -verify "${PUBLIC_KEY}" -signature "${SIG_FILE}" "${CONFIG_FILE}"; then
  echo "Signature verification successful"
  
  # Process the verified configuration file
  # (implement secure parsing as in previous solution)
  source "${CONFIG_FILE}"
  echo "Configuration updated successfully"
else
  echo "ERROR: Configuration signature verification failed"
  exit 1
fi

# Clean up
rm -f "${CONFIG_FILE}" "${SIG_FILE}"

```

This solution:
1. Retrieves both the configuration file and a cryptographic signature
2. Verifies the signature using a public key stored securely on the system
3. Only processes the configuration if the signature is valid
4. Provides enhanced protection against tampering and MITM attacks
5. Establishes a chain of trust for configuration updates


# References
* CWE-78 | [Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
* CWE-77 | [Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)
* CWE-94 | [Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* CWE-494 | [Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)
