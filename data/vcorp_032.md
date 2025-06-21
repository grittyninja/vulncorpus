# Hardcoded JWT Secret in Configuration File

# Vulnerability Case
During our routine security assessment of Acme Corp's backend services, we discovered an embedded JWT token in the application's configuration file that had bypassed standard code reviews. The token, hard-coded for what was initially intended as internal testing, was inadvertently committed to the production repository. Automated secrets scanning integrated into the CI/CD pipeline flagged the exposed JWT string. Its presence poses a significant risk, as an adversary might capture and reuse the token in authentication flows to impersonate privileged users or escalate access. Acme Corp's web application leverages a Node.js/Express stack and utilizes JSON Web Tokens for managing user sessions.

```javascript
// config.js - Exposed configuration file
module.exports = {
  // Hard-coded JWT token inadvertently committed to the code repository.
  jwtSecret:
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  tokenExpiry: "1h"
};

// Example usage in the authentication module
const jwt = require("jsonwebtoken");
const config = require("./config");

function generateToken(user) {
  // Signs a token for the user using the static jwtSecret
  return jwt.sign({ id: user.id, role: user.role }, config.jwtSecret, {
    expiresIn: config.tokenExpiry
  });
}

module.exports = { generateToken };
```

The exposed JWT token can potentially be misused if intercepted by an attacker, allowing unauthorized API access or impersonation of a valid user session. Exploitation might occur through replay attacks or by injecting the token into unauthorized requests, thereby bypassing proper authentication mechanisms. Such a scenario could lead to significant business impact, including data exfiltration, unauthorized transactions, and elevated privileges that compromise critical systems within the Acme Corp infrastructure.


context: generic.secrets.security.detected-jwt-token.detected-jwt-token JWT token detected

# Vulnerability Breakdown
This vulnerability involves the exposure of a JWT (JSON Web Token) secret directly within an application configuration file that was committed to a production repository.

1. **Key vulnerability elements**:
   - JWT secret hardcoded in plain text in config.js
   - Secret committed to production code repository
   - No environment variable or secure secret storage utilization
   - Used for signing authentication tokens in a Node.js/Express application
   - Detected by automated secrets scanning in the CI/CD pipeline

2. **Potential attack vectors**:
   - Code repository access (legitimate or unauthorized)
   - Server filesystem access where configuration is deployed
   - Internal threat actors with codebase access
   - CI/CD pipeline compromise allowing secret interception

3. **Severity assessment**:
   - High confidentiality impact through potential authenticated access to sensitive data
   - High integrity impact through potential modification of data via forged authentication
   - Adjacent attack vector requiring codebase or configuration access
   - Low complexity exploitation requiring basic knowledge of JWT
   - Low privileges required as attacker needs access to code repository or configuration files

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Adjacent (A) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): Low (L) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): None (N) 

# Description
A hard-coded JWT secret was discovered in Acme Corp's Node.js/Express web application's configuration file. This secret was inadvertently committed to the production repository despite being initially intended for internal testing purposes. The secret is used to sign JSON Web Tokens for user authentication and session management.

```javascript
// config.js - Exposed configuration file
module.exports = {
  // Hard-coded JWT token secret inadvertently committed to the code repository
  jwtSecret: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  tokenExpiry: "1h"
};

```

This exposure presents a significant security risk as anyone with access to the codebase can extract this secret and use it to forge valid authentication tokens, potentially impersonating legitimate users including those with elevated privileges. The vulnerability was detected by automated secrets scanning integrated into the CI/CD pipeline.

# CVSS
**Score**: 7.3 \
**Vector**: CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N \
**Severity**: High

The High severity rating (CVSS score of 7.3) is justified by the following factors:

- **Adjacent (A) Attack Vector**: The vulnerability requires access to the application's codebase or configuration files, which is not directly accessible over the network but requires special access to the source code repository or deployed configuration.

- **Low (L) Attack Complexity**: Once the JWT secret is obtained, exploiting it requires only basic knowledge of how JWT works. Forging tokens is straightforward with the secret key in hand.

- **Low Privileges Required (PR:L)**: The attacker needs some level of privileged access - either to the code repository, deployed configuration files, or CI/CD pipeline - to obtain the JWT secret. This is more restricted than a vulnerability exploitable without any privileges.

- **No User Interaction (UI:N)**: The vulnerability can be exploited without requiring any action from a legitimate user.

- **Unchanged (U) Scope**: The impact is contained within the security scope of the affected component.

- **High (H) Confidentiality Impact**: With a forged JWT, an attacker could access sensitive data by impersonating users with high privileges.

- **High (H) Integrity Impact**: An attacker could modify data they shouldn't have access to by authenticating as privileged users.

- **None (N) Availability Impact**: There is no direct impact on system availability.

# Exploitation Scenarios
**Scenario 1: Internal Developer Exploitation**
A disgruntled developer with legitimate access to the codebase identifies the hardcoded JWT secret in config.js. Using this secret, they craft a JWT token with administrator privileges by setting the appropriate role claim. Even after leaving the company, they can continue accessing the system with these elevated privileges until the secret is rotated.

**Scenario 2: Repository Access Breach**
An attacker gains unauthorized access to Acme Corp's code repository through compromised developer credentials. Upon discovering the JWT secret in the configuration file, they analyze other parts of the codebase to understand the token structure and required claims. The attacker then generates tokens with various privilege levels to methodically extract sensitive data and perform unauthorized operations.

**Scenario 3: CI/CD Pipeline Compromise**
An attacker who has compromised a build server or deployment pipeline intercepts the configuration file during the build process. By extracting the JWT secret, they can forge authentication tokens that mimic legitimate users, targeting high-value accounts like financial administrators. The attacker establishes persistence by creating tokens with extended expiration times, maintaining access even if the initial breach is discovered.

**Scenario 4: Social Engineering Attack**
An attacker targets a system administrator through a phishing campaign. After gaining temporary access to the administrator's development environment, they quickly locate and exfiltrate the configuration files containing the JWT secret. Later, they use this secret to generate tokens that grant access to sensitive API endpoints, exfiltrating customer data gradually to avoid detection.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive customer data potentially triggering regulatory violations under GDPR, CCPA, or similar regulations
- Financial losses from fraudulent transactions if payment systems are accessible via API
- Intellectual property theft if protected by authentication controls
- Reputational damage if a breach is disclosed publicly
- Loss of customer trust resulting in reduced business
- Potential legal liability for failing to implement reasonable security measures
- Costs associated with incident response, forensic investigation, and remediation

**Technical Impact:**
- Complete bypass of authentication mechanisms for all JWT-protected resources
- Ability to impersonate any user, including administrators and privileged users
- Authorization controls rendered ineffective when predicated on trusted authentication
- Potential for persistent unauthorized access that's difficult to detect
- If tokens aren't properly monitored, malicious activity might appear legitimate
- Invalidation challenges as existing tokens may remain valid until expiration
- Session management compromised across the application

# Technical Details
The vulnerability exists in the Node.js/Express application's approach to JWT secret management. The JWT secret is hardcoded directly in the application's configuration file, which is stored in the version control system and deployed to production environments.

```javascript
// config.js - Exposed configuration file
module.exports = {
  // Hard-coded JWT token secret inadvertently committed to the code repository
  jwtSecret: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  tokenExpiry: "1h"
};

// Example usage in the authentication module
const jwt = require("jsonwebtoken");
const config = require("./config");
function generateToken(user) {
  // Signs a token for the user using the static jwtSecret
  return jwt.sign({ id: user.id, role: user.role }, config.jwtSecret, {
    expiresIn: config.tokenExpiry
  });
}
module.exports = { generateToken };

```

The fundamental issues are:

1. **Secret Exposure**: The JWT signing secret is in plaintext in a file that is committed to version control. Anyone with repository access can see this secret.

2. **JWT Implementation**: The application uses this secret to sign tokens containing user identity and role information. With the secret, anyone can:
   - Decode existing tokens to extract user information
   - Forge new tokens with arbitrary user IDs and roles
   - Bypass authentication entirely by creating valid tokens

3. **Token Structure**: The tokens include user ID and role claims, which form the basis of authorization decisions:
   ```javascript
   jwt.sign({ id: user.id, role: user.role }, config.jwtSecret, ...)
   
   ```

4. **Usage Pattern**: The authentication module exports a `generateToken` function that other parts of the application likely use to create tokens for authenticated users. This suggests the tokens are used throughout the application for maintaining session state and authorization.

5. **Lack of Secret Rotation**: The hardcoded nature of the secret makes it difficult to rotate regularly, as it would require code changes and redeployment.

This vulnerability exists because the application fails to follow secure development practices for handling secrets. Instead of storing sensitive values in environment variables or dedicated secret management systems, the secret is embedded directly in the source code.

# Remediation Steps
## Rotate JWT Secret and Implement Environment Variables

**Priority**: P0

Immediately replace the hardcoded JWT secret with a new one accessed via environment variables:

```javascript
// config.js - Updated secure version
module.exports = {
  // Using environment variable instead of hardcoded secret
  jwtSecret: process.env.JWT_SECRET || (function() {
    console.error('WARNING: JWT_SECRET environment variable not set!');
    if (process.env.NODE_ENV === 'production') {
      throw new Error('JWT_SECRET must be set in production environment');
    }
    return 'dev_only_secret_do_not_use_in_production';
  })(),
  tokenExpiry: process.env.TOKEN_EXPIRY || "1h"
};

```

During deployment:
1. Generate a cryptographically strong random value using a secure method:
   ```bash
   # On Linux/Mac
   openssl rand -base64 64
   
   # On Windows (PowerShell)
   [Convert]::ToBase64String((New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes(64))
   
```

2. Set this value as an environment variable on all environments:
   ```bash
   # For development
   export JWT_SECRET="generated_secure_value_here"
   
   # For production (set in deployment pipeline or container configuration)
   
```

3. Invalidate all existing tokens by implementing a token version or issuance timestamp check
4. Monitor for any unauthorized access attempts using the old secret
## Implement Secret Management System

**Priority**: P1

Integrate with a dedicated secrets management solution for more robust security:

```javascript
// config.js - Using a secrets manager
const secretsManager = require('./services/secrets-manager');

module.exports = {
  // Async secret retrieval
  getJwtSecret: async () => {
    return await secretsManager.getSecret('jwt/signing-key');
  },
  tokenExpiry: process.env.TOKEN_EXPIRY || "1h"
};

// auth.js - Updated authentication module
const jwt = require("jsonwebtoken");
const config = require("./config");

async function generateToken(user) {
  const secret = await config.getJwtSecret();
  return jwt.sign({ id: user.id, role: user.role }, secret, {
    expiresIn: config.tokenExpiry
  });
}

async function verifyToken(token) {
  const secret = await config.getJwtSecret();
  return jwt.verify(token, secret);
}

module.exports = { generateToken, verifyToken };

```

Implementation steps:
1. Set up a secrets management service like AWS Secrets Manager, HashiCorp Vault, or Azure Key Vault
2. Create a service module to interact with the secrets API
3. Implement caching to reduce API calls while still allowing rotation
4. Set up appropriate access controls and audit logging for the secrets service
5. Configure automatic rotation policies for the JWT secret
6. Update all token verification code to use the new async verification function
## Enhance Detection and Prevention Controls

**Priority**: P2

Implement guardrails to prevent recurrence of this vulnerability:

1. Pre-commit hooks:
```json
// .gitignore - Ensure configuration is not committed
config.*.js
.env
.env.*

```

2. Add a template configuration file for developers:
```javascript
// config.template.js - Template for local development
module.exports = {
  // IMPORTANT: Never hardcode secrets here - use environment variables
  jwtSecret: process.env.JWT_SECRET,
  tokenExpiry: process.env.TOKEN_EXPIRY || "1h"
};

```

3. Configure static code analysis tools specifically for secret detection:
```json
// .secretsignore - Configuration for secret scanning tools
{
  "patterns": [
    "jwt[^\n]{10,}",
    "secret[^\n]{10,}",
    "key[^\n]{10,}",
    "password[^\n]{8,}",
    "eyJ[a-zA-Z0-9_-]{10,}"
  ],
  "allowList": [
    "src/tests/fixtures/mock-data.js"
  ]
}

```

4. Document secure coding practices in the README.md:
```markdown
## Security Guidelines
- Never hardcode secrets, tokens, or credentials in the source code
- Always use environment variables or the secrets management service
- Run `npm run security-check` before committing code
- Follow the security review process for authentication changes

```

5. Set up automated security testing:
- Integrate secret scanning tools into CI/CD pipelines with breaking failures
- Add automated security tests that verify secrets are not exposed
- Set up scheduled scans of the codebase to catch any regression


# References
* CWE-798 | [Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
* CWE-522 | [Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
* CWE-312 | [Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
* A07:2021 | [Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
* A04:2021 | [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
