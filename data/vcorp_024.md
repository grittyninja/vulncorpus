# Path Traversal via NGINX Alias Directive Misconfiguration

# Vulnerability Case
During an audit of Acme Corp's public-facing NGINX server (running on Ubuntu 20.04 LTS with a PHP-FPM backend), a misconfiguration was identified in the server's static file handling. The `alias` directive in the `location` block was defined without a trailing slash, which inadvertently enables path traversal via URL manipulation. This finding was uncovered during manual configuration review and cross-referenced with abnormal access logs, where specially crafted HTTP requests exploited the vulnerability. Attackers could append encoded relative paths to legitimate endpoints, potentially accessing files outside the intended directory and exposing sensitive configuration or data.

```nginx
location /static {
    alias /var/www/app/static;
}
```

Exploitation is achieved by appending URL-encoded traversal sequences (e.g., `..%2F`) to the `/static` endpoint, causing NGINX to resolve file paths relative to the parent directory of `/var/www/app/static`. Such traversal can bypass directory restrictions and access sensitive files, including server configuration, log files, or application assets not meant for public exposure. The business impact includes potential data leakage, unauthorized access to internal resources, and increased risk of lateral movement within the network, thereby compromising overall system integrity.


context: generic.nginx.security.alias-path-traversal.alias-path-traversal The alias in this location block is subject to a path traversal because the location path does not end in a path separator (e.g., '/'). To fix, add a path separator to the end of the path.

# Vulnerability Breakdown
This vulnerability involves a path traversal issue in Acme Corp's NGINX server configuration due to the missing trailing slash in an alias directive.

1. **Key vulnerability elements**:
   - NGINX server running on Ubuntu 20.04 LTS with PHP-FPM backend
   - `alias` directive in `location` block defined without a trailing slash
   - Path traversal becomes possible via URL manipulation
   - Affects public-facing server, increasing exposure
   - Enables access to files outside the intended directory

2. **Potential attack vectors**:
   - Appending URL-encoded traversal sequences (e.g., `..%2F`) to the `/static` endpoint
   - Crafting requests that resolve to sensitive files outside the intended directory
   - Targeting configuration files, logs, or other sensitive data
   - Potential for information disclosure of server internals

3. **Severity assessment**:
   - Low confidentiality impact as there's no proof of PII or key data exposure
   - No direct integrity impact as files cannot be modified
   - No direct availability impact
   - Network attack vector (remotely exploitable)
   - Low complexity to exploit (straightforward URL manipulation)

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): Low (L) 
   - Integrity (I): None (N) 
   - Availability (A): None (N) 

# Description
A path traversal vulnerability exists in Acme Corp's public-facing NGINX server (running on Ubuntu 20.04 LTS with a PHP-FPM backend) due to a misconfiguration in the static file handling. The `alias` directive in the `location` block is defined without a trailing slash, which inadvertently enables directory traversal attacks:

```nginx
location /static {
    alias /var/www/app/static;
}

```

This misconfiguration allows attackers to append encoded relative paths to legitimate endpoints (e.g., using `..%2F` sequences), causing NGINX to resolve file paths relative to the parent directory of `/var/www/app/static`. By crafting specific URLs, an attacker could potentially access files outside the intended directory, including server configuration files, logs, or other sensitive data not meant for public exposure.

# CVSS
**Score**: 5.3 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N \
**Severity**: Medium

The Medium severity rating (5.3) is justified by the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability is exploitable remotely through the public-facing NGINX server, without requiring local network access or physical proximity.

- **Low Attack Complexity (AC:L)**: Exploitation is straightforward, requiring only basic knowledge of path traversal techniques and URL encoding. No special timing, conditions, or reconnaissance are needed.

- **No Privileges Required (PR:N)**: An attacker does not need any authentication or privileges to exploit this vulnerability, as the static file serving endpoint is publicly accessible.

- **No User Interaction (UI:N)**: Exploitation can be performed directly by the attacker without requiring actions from a legitimate user.

- **Unchanged Scope (S:U)**: The vulnerability affects only the resources managed by the NGINX server and does not allow the attacker to affect components beyond its security scope.

- **Low Confidentiality Impact (C:L)**: While the vulnerability allows access to files outside the intended directory, there is no concrete evidence that highly sensitive information like PII or cryptographic keys would be exposed. The impact is limited to potential disclosure of system information and non-critical configuration files.

- **No Integrity Impact (I:N)**: The vulnerability itself does not allow modification of files, only read access.

- **No Availability Impact (A:N)**: The vulnerability does not directly impact the availability of the server or service.

# Exploitation Scenarios
**Scenario 1: Accessing Configuration Files**
An attacker discovers the path traversal vulnerability in the `/static` location and crafts a request like `/static..%2F..%2F..%2Fetc%2Fnginx%2Fnginx.conf` (URL-encoded form of `/static../../etc/nginx/nginx.conf`). This causes the server to return the NGINX configuration file, which might contain sensitive information such as server names, upstream server details, or even authentication credentials for protected areas.

**Scenario 2: Obtaining PHP Application Source Code**
The attacker targets the PHP application's source code by accessing files outside the static directory. For example, a request like `/static..%2F..%2Findex.php` could reveal the source code of the main application file, potentially exposing database credentials, business logic, or security weaknesses in the application.

**Scenario 3: Accessing System Files**
An attacker attempts to access system files to gather intelligence about the server environment. Requests like `/static..%2F..%2F..%2F..%2Fetc%2Fpasswd` could reveal user accounts on the system, while `/static..%2F..%2F..%2F..%2Fvar%2Flog%2Fauth.log` might expose recent authentication attempts, potentially including usernames or other sensitive data.

**Scenario 4: Lateral Movement Reconnaissance**
After successfully accessing system files, the attacker looks for information that could aid in lateral movement within the network. Files like `/static..%2F..%2F..%2F..%2Fhome%2Fuser%2F.ssh%2Fid_rsa` (SSH private keys), environment files with API tokens, or configuration files containing internal network details could be targeted.

# Impact Analysis
**Business Impact:**
- Potential exposure of sensitive configuration data including passwords and access credentials
- Unauthorized access to proprietary code, potentially revealing trade secrets or intellectual property
- Compliance violations if personal data or regulated information is exposed (GDPR, PCI DSS, etc.)
- Reputational damage if the breach becomes public
- Loss of customer trust if personal information is compromised
- Legal liability for failure to implement proper security controls
- Costs associated with incident response, forensic investigation, and remediation

**Technical Impact:**
- Exposure of server configuration details that could aid further attacks
- Access to application source code, revealing logic flaws and security weaknesses
- Potential disclosure of database credentials or connection strings
- Exposure of internal file system structure and server organization
- Access to log files that might contain sensitive user data or internal system information
- Information gathering for lateral movement within the network
- Insight into security mechanisms that could be bypassed in future attacks

# Technical Details
The vulnerability stems from a specific NGINX configuration pattern where the `alias` directive is used in a `location` block without proper trailing slashes. The problematic configuration is:

```nginx
location /static {
    alias /var/www/app/static;
}

```

The issue occurs due to how NGINX processes URI-to-filesystem path mapping when using the `alias` directive. Here's the mechanism of the vulnerability:

1. When NGINX receives a request for `/static/file.txt`, it correctly maps this to `/var/www/app/static/file.txt`

2. However, when using `alias` without trailing slashes, NGINX doesn't properly handle the path normalization for URI paths that contain traversal sequences

3. If an attacker requests `/static../etc/passwd` (or URL-encoded as `/static..%2Fetc%2Fpasswd`), NGINX will:
   - Take the prefix `/static` from the location
   - Replace it with `/var/www/app/static` (the alias value)
   - Append the remaining path portion `../etc/passwd`
   - Resulting in the path `/var/www/app/static../etc/passwd`

4. When this path is normalized by the filesystem, it resolves to `/var/www/app/etc/passwd` or potentially even `/etc/passwd` depending on how many traversal sequences are used

This normalization issue occurs specifically because both the location pattern and alias value don't have trailing slashes. When trailing slashes are present, NGINX handles the path joining differently and prevents this type of traversal.

The vulnerability is exacerbated by several factors:

1. **Public accessibility**: Being on a public-facing server increases the attack surface

2. **No authentication required**: The static file location typically doesn't require authentication

3. **URL encoding**: Path traversal sequences can be URL-encoded (e.g., `..%2F` instead of `../`) to bypass simple pattern filtering

4. **PHP-FPM backend**: While not directly related to the path traversal, the presence of PHP increases the potential value of the target, as source code files may contain sensitive information like database credentials

# Remediation Steps
## Add Trailing Slashes to Alias Configuration

**Priority**: P0

The immediate fix is to ensure that both the location path and alias value end with trailing slashes:

```nginx
location /static/ {
    alias /var/www/app/static/;
}

```

This ensures that NGINX correctly joins the path components and prevents directory traversal attacks. When both the location and alias have trailing slashes, NGINX properly handles the URI-to-filesystem path mapping.

Alternatively, you can use the `root` directive instead of `alias` if appropriate for your setup:

```nginx
location /static/ {
    root /var/www/app;
}

```

With the `root` directive, NGINX appends the entire location match to the specified root, so `/static/file.txt` would map to `/var/www/app/static/file.txt`.
## Implement Additional Security Controls

**Priority**: P1

Beyond fixing the immediate vulnerability, implement these additional security measures:

1. **Add path normalization checks**:

```nginx
# Deny requests containing suspicious path sequences
location ~ \.\./ {
    deny all;
}

# Then configure your regular location
location /static/ {
    alias /var/www/app/static/;
}

```

2. **Restrict file types** that can be served from static directories:

```nginx
location /static/ {
    alias /var/www/app/static/;
    # Only allow specific file extensions
    location ~ \.(gif|jpg|jpeg|png|css|js|ico|svg|woff|woff2)$ {
        try_files $uri =404;
    }
    # Deny access to everything else
    return 403;
}

```

3. **Use a validated NGINX configuration** with automated security scanning as part of the deployment pipeline to catch similar issues before they reach production.


# References
* CWE-22 | [Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A01:2021 | [Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
* A05:2021 | [Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
