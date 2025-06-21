# Hardcoded JWT RSA Private Key in Version-Controlled Configuration File

# Vulnerability Case
During an in-depth static code analysis of Acme Corp's Node.js web application that utilizes Express and JWT for authentication, our security tooling uncovered a hardcoded RSA private key embedded within a configuration file. This sensitive credential was committed to the production Git repository, exposing it to potential unauthorized access. The detection was confirmed by automated secret scanning tools during routine security assessments, indicating a high-risk issue. The exposure of such a private key can allow attackers to generate valid JWTs, thus impersonating legitimate users or escalating privileges within the application.

```javascript
// config.js in Acme Corp's Node.js web application
module.exports = {
  jwtPrivateKey: `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQD3JrV1W6bE8Yuy3DazKj5AnlHfjh6OpIqwGRZ8wv67Zz9YxwTw
e7sR1+KxXCpKC1s5r0ZtyQyqXQ9L6yV7t8LzEhY8mBKdD6YJn1X6zR9bYlYk8+O9
rJ8fX3rWcYk27fuQq5kvXHn9tXh5ZJcQxE1TgLgsF0C1sFOVh8W5q1YzRwIDAQAB
AoGACM5yaP2f56zq5jLbgS3Zq9M4R5ImKce5dIUZ0FwnscW1KdPbFRG9ZBKPAkam
z3qR+zM4ksMeXYbRHZhXse2viZqJ9+9dpPkbpYB/iTqKzsxGxW1T7x5TXYrBPP+o
TjD5hJyF4Z7RgoTw25NKE0IynuDmrtpJ8S/zzQ5lN3jDsIECQQD1Nht9ZPKzxCnJ
JENd9pLJ7eOr8eX4A0iL5gQH6kK6EjPtR9TDzOi3YK8g5pCWzESpsV9rx6mFA59S
VKC0F4mPAkEA9FZ9TASYYkOz6n4+PtuTk2ouFOJzZLy8LHtKyIT1jp4tJKXWkxhi
wb4u3Zqye9lq3Wd2O9BFXqw7W5PzpEuztQJBAKycI+y+eXW4b5byY1JvSj7Z/JnH
aTg8Kx3RecWgbh9xsRn7daK4r4+V55QqiwSbPkXcSgNtqAqGz9Gw2hxO+1ECQAqR
UN8n7NlKwN9TRhIjjrTILbXP2yD/wEdNf9j+5aZyv1zP4Q7aS1mVJxl5TeEe3r9s
D8p11wZq9/8uZH4zq+UCQAKfZHLbSxRB+ZQ2LWy0EyaPZFG9m4NRZqhojRex91gL
HzT+RuNrzPZ+9Xw1e2W9vUdNdI9FMlRfRlUP3M2K9+o=
-----END RSA PRIVATE KEY-----`,
  // Additional application settings follow...
};
```

The presence of a hardcoded RSA private key in a source-controlled configuration file enables an adversary, upon gaining access to the repository, to fabricate or sign JWTs. Exploitation of this vulnerability may include impersonation of legitimate users, unauthorized access to protected resources, and privilege escalation within the application. Given that the application relies on these tokens for authentication and session management, the business impact could be severe—potentially resulting in a complete compromise of user data, loss of customer trust, and regulatory non-compliance.


context: generic.secrets.security.detected-private-key.detected-private-key Private Key detected. This is a sensitive credential and should not be hardcoded here. Instead, store this in a separate, private file.

# Vulnerability Breakdown
This vulnerability involves an RSA private key for JWT authentication being hardcoded directly in a configuration file within a Node.js web application. This sensitive credential has been committed to the production Git repository, creating a significant security risk.

1. **Key vulnerability elements**:
   - RSA private key embedded directly in source code (config.js)
   - Key committed to version control (Git repository)
   - Key used for JWT token signing, which authenticates users
   - No apparent key rotation or secure storage mechanism
   - Application uses Express and JWT for authentication

2. **Potential attack vectors**:
   - Repository access by unauthorized individuals (insider threats, compromised credentials)
   - Repository access via public exposure if misconfigured
   - Extraction of keys from deployment artifacts
   - JWT forgery to impersonate legitimate users or escalate privileges

3. **Severity assessment**:
   - High confidentiality impact: Any repository access enables complete authentication bypass
   - High integrity impact: Forged JWTs allow unauthorized actions as legitimate users
   - No direct availability impact
   - Unchanged scope: Vulnerability affects only the authentication system itself
   - Adjacent attack vector requiring repository access
   - Low complexity once key is obtained

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
A critical security vulnerability has been identified in Acme Corp's Node.js web application during static code analysis. An RSA private key used for JWT (JSON Web Token) authentication has been hardcoded directly in a configuration file (`config.js`) and committed to the production Git repository.

```javascript
// config.js in Acme Corp's Node.js web application
module.exports = {
  jwtPrivateKey: `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQD3JrV1W6bE8Yuy3DazKj5AnlHfjh6OpIqwGRZ8wv67Zz9YxwTw
e7sR1+KxXCpKC1s5r0ZtyQyqXQ9L6yV7t8LzEhY8mBKdD6YJn1X6zR9bYlYk8+O9
rJ8fX3rWcYk27fuQq5kvXHn9tXh5ZJcQxE1TgLgsF0C1sFOVh8W5q1YzRwIDAQAB
AoGACM5yaP2f56zq5jLbgS3Zq9M4R5ImKce5dIUZ0FwnscW1KdPbFRG9ZBKPAkam
z3qR+zM4ksMeXYbRHZhXse2viZqJ9+9dpPkbpYB/iTqKzsxGxW1T7x5TXYrBPP+o
TjD5hJyF4Z7RgoTw25NKE0IynuDmrtpJ8S/zzQ5lN3jDsIECQQD1Nht9ZPKzxCnJ
JENd9pLJ7eOr8eX4A0iL5gQH6kK6EjPtR9TDzOi3YK8g5pCWzESpsV9rx6mFA59S
VKC0F4mPAkEA9FZ9TASYYkOz6n4+PtuTk2ouFOJzZLy8LHtKyIT1jp4tJKXWkxhi
wb4u3Zqye9lq3Wd2O9BFXqw7W5PzpEuztQJBAKycI+y+eXW4b5byY1JvSj7Z/JnH
aTg8Kx3RecWgbh9xsRn7daK4r4+V55QqiwSbPkXcSgNtqAqGz9Gw2hxO+1ECQAqR
UN8n7NlKwN9TRhIjjrTILbXP2yD/wEdNf9j+5aZyv1zP4Q7aS1mVJxl5TeEe3r9s
D8p11wZq9/8uZH4zq+UCQAKfZHLbSxRB+ZQ2LWy0EyaPZFG9m4NRZqhojRex91gL
HzT+RuNrzPZ+9Xw1e2W9vUdNdI9FMlRfRlUP3M2K9+o=
-----END RSA PRIVATE KEY-----`,
  // Additional application settings follow...
};

```

This private key is used to sign JWTs, which serve as the authentication mechanism for the application. Anyone with access to the Git repository can obtain this key and use it to forge valid authentication tokens, allowing them to impersonate legitimate users or escalate privileges within the application. This represents a severe breach of security best practices and puts the entire application's authentication system at risk.

# CVSS
**Score**: 7.3 \
**Vector**: CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N \
**Severity**: High

The High severity rating (7.3) is justified by the following factors:

- **Adjacent Attack Vector (AV:A)**: The vulnerability requires access to the Git repository, which is not directly exploitable over the public internet but could be accessed through the internal network or by insiders.

- **Low Attack Complexity (AC:L)**: Once an attacker has obtained the private key, forging valid JWTs is straightforward using readily available tools and libraries.

- **Low Privileges Required (PR:L)**: Some level of access to the organization's codebase or repository is needed to exploit this vulnerability, typically requiring at least basic contributor or viewer permissions.

- **No User Interaction (UI:N)**: The vulnerability can be exploited without any action from legitimate users once the attacker has obtained the key.

- **Unchanged Scope (S:U)**: The vulnerability affects only the authentication system itself and doesn't directly cross security boundaries to impact other components.

- **High Confidentiality Impact (C:H)**: With forged JWTs, attackers can access sensitive information belonging to any user of the system, potentially including personal data, financial information, or business secrets.

- **High Integrity Impact (I:H)**: Attackers can perform unauthorized actions as any user, potentially modifying critical data or business logic.

- **No Availability Impact (A:N)**: The vulnerability does not directly affect system availability.

The calculated score of 7.3 places this in the High severity category, reflecting the serious nature of exposing cryptographic secrets that protect the authentication system.

# Exploitation Scenarios
**Scenario 1: Insider Threat Exploitation**
A disgruntled employee with access to the Git repository notices the hardcoded RSA private key in config.js. Using this key, they create a simple script to generate forged JWT tokens for administrative accounts or other high-privilege users. With these tokens, they can access restricted parts of the application after hours or even after leaving the company, exfiltrating sensitive data or making unauthorized changes to the system.

```javascript
// Example exploit script to forge JWT tokens
const jwt = require('jsonwebtoken');
const fs = require('fs');

// The private key copied from the repository
const privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQD3JrV1W6bE8Yuy3DazKj5AnlHfjh6OpIqwGRZ8wv67Zz9YxwTw
... [rest of key] ...
-----END RSA PRIVATE KEY-----`;

// Create a forged token for admin access
const forgedToken = jwt.sign(
  { 
    userId: 1,  // Assuming ID 1 is an admin
    role: 'admin',
    permissions: ['read', 'write', 'delete', 'admin'],
    exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 30) // 30 day expiration
  }, 
  privateKey, 
  { algorithm: 'RS256' }
);

console.log('Forged JWT:', forgedToken);
// This token can now be used in HTTP headers: Authorization: Bearer [token]

```

**Scenario 2: Supply Chain Attack**
An attacker gains access to the repository through a compromised developer account or a breach of the Git hosting service. They identify the private key and create a backdoor for persistent access. They generate JWTs for various user accounts and use them to gradually exfiltrate data, careful to avoid detection by spreading access across multiple accounts and keeping activity levels consistent with normal usage patterns.

**Scenario 3: Privilege Escalation**
A contractor with limited access to the codebase discovers the private key. Though their account only has basic permissions in the application, they forge a JWT with elevated privileges. They use this token to access administrative features, granting their regular account persistent higher permissions, or creating additional backdoor accounts with administrative rights that can be accessed even after their contract ends.

# Impact Analysis
**Business Impact:**
- Potential unauthorized access to all protected resources within the application
- Breach of user data confidentiality, potentially affecting all customers
- Violation of data protection regulations (GDPR, CCPA, etc.) leading to significant financial penalties
- Loss of customer trust and business reputation if a breach occurs and becomes public
- Potential financial losses from fraud if the application handles transactions or sensitive financial data
- Legal liability for failing to implement basic security controls
- Extended incident response costs if exploitation occurs, including forensic investigation, remediation, and possible compensation

**Technical Impact:**
- Complete bypass of authentication controls throughout the application
- Ability for attackers to impersonate any user, including administrators
- Undetectable access as forged tokens appear identical to legitimate ones in logs
- Difficulty in distinguishing between legitimate and malicious activity
- Persistence of the vulnerability even if discovered, as rotating keys requires application updates
- Inability to revoke specific tokens if no additional validation is implemented
- Potential for data theft, modification, or destruction across the entire application
- Difficulty in determining the extent of compromise if exploited

# Technical Details
The vulnerability exists in a Node.js web application that uses Express as the web framework and JWT (JSON Web Tokens) for authentication. The critical issue is the hardcoding of an RSA private key directly in a configuration file that is committed to version control.

```javascript
// config.js in Acme Corp's Node.js web application
module.exports = {
  jwtPrivateKey: `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQD3JrV1W6bE8Yuy3DazKj5AnlHfjh6OpIqwGRZ8wv67Zz9YxwTw
e7sR1+KxXCpKC1s5r0ZtyQyqXQ9L6yV7t8LzEhY8mBKdD6YJn1X6zR9bYlYk8+O9
rJ8fX3rWcYk27fuQq5kvXHn9tXh5ZJcQxE1TgLgsF0C1sFOVh8W5q1YzRwIDAQAB
AoGACM5yaP2f56zq5jLbgS3Zq9M4R5ImKce5dIUZ0FwnscW1KdPbFRG9ZBKPAkam
z3qR+zM4ksMeXYbRHZhXse2viZqJ9+9dpPkbpYB/iTqKzsxGxW1T7x5TXYrBPP+o
TjD5hJyF4Z7RgoTw25NKE0IynuDmrtpJ8S/zzQ5lN3jDsIECQQD1Nht9ZPKzxCnJ
JENd9pLJ7eOr8eX4A0iL5gQH6kK6EjPtR9TDzOi3YK8g5pCWzESpsV9rx6mFA59S
VKC0F4mPAkEA9FZ9TASYYkOz6n4+PtuTk2ouFOJzZLy8LHtKyIT1jp4tJKXWkxhi
wb4u3Zqye9lq3Wd2O9BFXqw7W5PzpEuztQJBAKycI+y+eXW4b5byY1JvSj7Z/JnH
aTg8Kx3RecWgbh9xsRn7daK4r4+V55QqiwSbPkXcSgNtqAqGz9Gw2hxO+1ECQAqR
UN8n7NlKwN9TRhIjjrTILbXP2yD/wEdNf9j+5aZyv1zP4Q7aS1mVJxl5TeEe3r9s
D8p11wZq9/8uZH4zq+UCQAKfZHLbSxRB+ZQ2LWy0EyaPZFG9m4NRZqhojRex91gL
HzT+RuNrzPZ+9Xw1e2W9vUdNdI9FMlRfRlUP3M2K9+o=
-----END RSA PRIVATE KEY-----`,
  // Additional application settings follow...
};

```

**JWT Authentication Flow:**

In a typical JWT implementation using this private key, the application would:

1. Receive user credentials (username/password)
2. Validate credentials against a database
3. On successful validation, create a JWT with user identity and permission claims
4. Sign this JWT using the RSA private key with RS256 algorithm
5. Return the signed token to the client
6. For subsequent requests, validate the JWT signature using the corresponding public key

**Technical Vulnerability Analysis:**

1. **Asymmetric Key Exposure**: The RSA private key should never be exposed. Only the public key should be distributed for token verification, while the private key must remain confidential as it can sign any arbitrary token.

2. **Git Repository Risks**: Once committed to a Git repository, the key exists in:
   - Working copies on developer machines
   - Git history (difficult to completely remove)
   - CI/CD servers with repository access
   - Backup systems
   - Deployment artifacts

3. **JWT Forgery Process**:
   With access to the private key, an attacker can:
   - Create a new JWT payload with arbitrary claims (user ID, roles, permissions)
   - Sign it with the exposed private key using standard libraries
   - Use the forged token to make authenticated requests

4. **Detection Challenges**:
   - Forged tokens are indistinguishable from legitimate ones
   - No revocation mechanism in standard JWT implementation
   - System logs would show activity as the impersonated user

5. **Compounding Factors**:
   - Lack of key rotation (single key for all tokens)
   - No additional validation beyond signature checking
   - No monitoring for suspicious JWT claims or usage patterns

# Remediation Steps
## Remove Private Key from Source Code and Implement Secure Storage

**Priority**: P0

Immediately remove the RSA private key from the config file and implement secure key storage:

```javascript
// Updated config.js
module.exports = {
  // Reference environment variable instead of hardcoding
  jwtPrivateKeyPath: process.env.JWT_PRIVATE_KEY_PATH || '/secure/path/to/keys/jwt.key',
  // Other configuration settings
};

// In your authentication service
const fs = require('fs');
const jwt = require('jsonwebtoken');
const config = require('./config');

function generateToken(userData) {
  // Read key from secure location, not from code
  const privateKey = fs.readFileSync(config.jwtPrivateKeyPath, 'utf8');
  
  // Generate token
  return jwt.sign(userData, privateKey, { 
    algorithm: 'RS256',
    expiresIn: '1h' // Short expiration as a security measure
  });
}

```

**Implementation steps:**

1. Generate a new RSA key pair to replace the compromised one
2. Store the private key in a secure location with restricted access:
   - Environment variables (for key paths, not the actual key)
   - Secure file system with appropriate permissions
   - Secret management service (AWS Secrets Manager, HashiCorp Vault, etc.)
3. Update the application to load the key from the secure location
4. Configure CI/CD systems to securely inject secrets during deployment
5. Add the key file paths to .gitignore to prevent future commits
6. Deploy the changes immediately
7. Invalidate all existing tokens and force users to re-authenticate
## Implement Proper Key Management and Rotation Procedures

**Priority**: P1

Establish robust key management practices for long-term security:

```javascript
// Enhanced JWT service with key rotation support
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');

class JwtService {
  constructor(keysDirectory) {
    this.keysDirectory = keysDirectory;
    this.currentKeyId = process.env.CURRENT_KEY_ID;
    this.keys = this.loadKeys();
  }
  
  loadKeys() {
    // Load all keys from the directory, supporting multiple keys for rotation
    const keys = {};
    const keyFiles = fs.readdirSync(this.keysDirectory);
    
    keyFiles.forEach(file => {
      if (file.endsWith('.key')) {
        const keyId = path.basename(file, '.key');
        keys[keyId] = fs.readFileSync(path.join(this.keysDirectory, file), 'utf8');
      }
    });
    
    return keys;
  }
  
  generateToken(userData) {
    // Sign with current key, including key ID in payload
    return jwt.sign(
      { ...userData, kid: this.currentKeyId },
      this.keys[this.currentKeyId],
      { algorithm: 'RS256', expiresIn: '1h' }
    );
  }
  
  verifyToken(token) {
    // Decode without verification to get the key ID
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || !decoded.header.kid) {
      throw new Error('Invalid token format');
    }
    
    const keyId = decoded.header.kid;
    if (!this.keys[keyId]) {
      throw new Error('Unknown key ID');
    }
    
    // Verify with the appropriate key
    return jwt.verify(token, this.keys[keyId]);
  }
}

module.exports = new JwtService(process.env.JWT_KEYS_DIRECTORY);

```

**Key management procedures:**

1. **Regular Key Rotation**:
   - Schedule regular key rotations (quarterly or monthly)
   - Generate new keys with unique identifiers
   - Include key ID (kid) in token header or payload
   - Support multiple valid keys during transition periods

2. **Access Controls**:
   - Limit access to key storage to authorized personnel
   - Implement audit logging for key access events
   - Use different keys for different environments (dev, staging, prod)

3. **Emergency Procedures**:
   - Define clear processes for emergency key rotation
   - Create an incident response plan for key compromises
   - Test rotation procedures regularly to ensure they work

4. **Monitoring and Alerts**:
   - Implement alerts for suspicious JWT usage patterns
   - Monitor for tokens with unusual claims or unexpected key IDs
   - Add logging for authentication events and token validations


# References
* CWE-798 | [Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
* CWE-321 | [Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
* CWE-522 | [Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
* A02:2021 | [Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
* A07:2021 | [Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
