# JWT Authentication Bypass via 'none' Algorithm

# Vulnerability Case
During the security assessment of Acme Corp's Java-based authentication service, we identified that the service was configured to use the insecure "none" algorithm for JWT validation. This implementation was discovered during a code review of the authentication module, which leverages the popular [java-jwt](https://github.com/auth0/java-jwt) library in a Spring Boot environment. The issue arises from directly initializing the JWT verification process with a non-validating algorithm, effectively bypassing signature checks. As a result, an attacker can craft a forged JWT—with arbitrary claims—that will be automatically accepted by the service. This vulnerability could lead to unauthorized access and privilege escalation within the application ecosystem.

```java
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

public class VulnerableJWTHandler {

  public DecodedJWT verifyToken(String token) {
    // Vulnerable: Explicit use of 'none' algorithm bypasses token signature verification
    Algorithm algorithm = Algorithm.none();
    JWTVerifier verifier = JWT.require(algorithm).build();
    return verifier.verify(token);
  }
}
```

By employing the "none" algorithm in the JWT verification process, the service accepts tokens without checking their cryptographic signature. An attacker with minimal effort can generate a token containing altered or malicious claims, potentially granting unauthorized access to sensitive endpoints or escalating privileges. This vulnerability risks compromise of secured resources and could lead to broader network exploitation, resulting in significant business impact in terms of data breaches and loss of customer trust.


context: java.java-jwt.security.jwt-none-alg.java-jwt-none-alg Detected use of the 'none' algorithm in a JWT token. The 'none' algorithm assumes the integrity of the token has already been verified. This would allow a malicious actor to forge a JWT token that will automatically be verified. Do not explicitly use the 'none' algorithm. Instead, use an algorithm such as 'HS256'.

# Vulnerability Breakdown
This vulnerability involves a critical authentication bypass in Acme Corp's Java-based authentication service due to the use of the insecure "none" algorithm for JWT validation.

1. **Key vulnerability elements**:
   - Explicit use of Algorithm.none() in JWT verification
   - Complete bypass of signature validation for tokens
   - Implementation in a widely-used Spring Boot authentication service
   - Affects all endpoints protected by this authentication mechanism
   - Allows arbitrary claim manipulation without detection

2. **Potential attack vectors**:
   - Forging JWT tokens with elevated privileges (e.g., admin rights)
   - Creating tokens with arbitrary user identities for impersonation
   - Bypassing authorization checks for protected resources
   - Modifying existing valid tokens to change claims

3. **Severity assessment**:
   - Critical severity due to complete authentication bypass
   - No technical barriers to exploitation
   - No special privileges required to perform the attack
   - Remote exploitation possible from anywhere
   - Potential for unauthorized access to all protected resources

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Changed (C)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): Low (L) 

# Description
A critical authentication vulnerability exists in Acme Corp's Java-based authentication service that allows complete bypass of JWT verification. The vulnerability stems from the explicit use of the "none" algorithm (`Algorithm.none()`) in the JWT verification process, which effectively disables signature validation.

```java
public DecodedJWT verifyToken(String token) {
  // Vulnerable: Explicit use of 'none' algorithm bypasses token signature verification
  Algorithm algorithm = Algorithm.none();
  JWTVerifier verifier = JWT.require(algorithm).build();
  return verifier.verify(token);
}

```

By configuring the system to accept tokens with the "none" algorithm, the application fails to verify the cryptographic signature that normally guarantees a token's authenticity and integrity. This allows attackers to forge tokens with arbitrary claims, including user identities and permission levels, that will be automatically accepted by the system. Since this vulnerability exists in a central authentication service, it potentially compromises all protected resources across the application ecosystem.

# CVSS
**Score**: 10.0 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L \
**Severity**: Critical

This vulnerability receives a Critical severity rating (CVSS score: 10.0) based on the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely without requiring proximity to the target system. Any attacker who can send HTTP requests to the application can exploit this issue.

- **Low Attack Complexity (AC:L)**: Exploiting this vulnerability is straightforward and reliable. Creating a forged JWT requires minimal technical knowledge, as attackers simply need to construct a JWT with the "none" algorithm and desired claims.

- **No Privileges Required (PR:N)**: An attacker doesn't need any prior authentication or access to exploit the vulnerability. They can create arbitrary tokens without having legitimate credentials.

- **No User Interaction (UI:N)**: Exploitation does not require any action from users of the system. The attacker directly submits forged tokens to the API endpoints.

- **Changed Scope (S:C)**: The vulnerability allows the attacker to impact resources beyond the vulnerable authentication component itself, affecting all protected services and data.

- **High Confidentiality Impact (C:H)**: Attackers can access sensitive information across the entire application by impersonating any user, including those with administrative privileges.

- **High Integrity Impact (I:H)**: Attackers can modify data across the application by gaining unauthorized write access to various system components.

- **Low Availability Impact (A:L)**: While the vulnerability primarily affects confidentiality and integrity, some availability impacts are possible through abuse of administrative functions.

This maximum possible CVSS score reflects the severity of completely bypassing authentication controls in a centralized authentication service.

# Exploitation Scenarios
**Scenario 1: Administrative Access**
An attacker who is familiar with JWT structure creates a completely forged token with administrative claims:

1. The attacker crafts a JWT with this header and payload:
   ```json
   // Header
   {
     "alg": "none",
     "typ": "JWT"
   }
   
   // Payload
   {
     "sub": "admin",
     "name": "System Administrator",
     "role": "ADMIN",
     "permissions": ["user:read", "user:write", "config:read", "config:write"],
     "iat": 1622505600,
     "exp": 1654041600
   }
   
```

2. The attacker encodes these sections in base64url format and joins them with periods, deliberately omitting the signature section.
3. The forged token is sent to the application API with an Authorization header.
4. The vulnerable service verifies the token using the "none" algorithm, which succeeds.
5. The attacker now has full administrative access to the system.

**Scenario 2: User Impersonation**
An attacker targets a specific high-value user to access their sensitive data:

1. The attacker knows or guesses a valid user ID (e.g., from public profiles or enumeration).
2. They create a forged JWT with the victim's identity but without a valid signature.
3. When submitted to the application, the token passes verification due to the "none" algorithm.
4. The attacker can now view and manipulate all data belonging to the victim.

**Scenario 3: Machine-to-Machine API Exploitation**
In a microservices architecture, service-to-service communication often uses JWTs for authentication:

1. An attacker identifies an internal API endpoint from error messages or documentation.
2. They create a forged service authentication token with elevated service permissions.
3. The vulnerable JWT verification accepts the token without signature validation.
4. The attacker can now access internal APIs and potentially extract sensitive business data or disrupt operations.

# Impact Analysis
**Business Impact:**
- Complete compromise of authentication and authorization systems
- Unauthorized access to sensitive customer data, potentially leading to privacy violations
- Regulatory compliance violations (GDPR, CCPA, HIPAA, etc.) with associated penalties
- Breach disclosure requirements if customer data is accessed
- Loss of customer trust and reputational damage
- Financial losses from potential legal action following a breach
- Business disruption if attackers modify critical configuration or data

**Technical Impact:**
- Total bypass of authentication controls
- Privilege escalation to any permission level in the system
- Access to all protected resources and endpoints
- Ability to impersonate any user in the system
- Potential to modify or delete sensitive data
- Tampering with audit logs or security monitoring (actions would be recorded under impersonated identities)
- Possibility of using the authentication service vulnerability as a stepping stone for deeper attacks
- Compromise of API keys, secrets, or other credentials stored in protected areas

# Technical Details
The vulnerability exists in Acme Corp's Java-based authentication service that uses the Auth0 java-jwt library in a Spring Boot environment. The root cause is the explicit configuration to use the "none" algorithm for JWT verification, which fundamentally breaks the security model of JWTs.

```java
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

public class VulnerableJWTHandler {

  public DecodedJWT verifyToken(String token) {
    // Vulnerable: Explicit use of 'none' algorithm bypasses token signature verification
    Algorithm algorithm = Algorithm.none();
    JWTVerifier verifier = JWT.require(algorithm).build();
    return verifier.verify(token);
  }
}

```

**JWT Security Model and the 'none' Algorithm:**

JWT security is based on three parts: header, payload, and signature. The signature cryptographically ensures that the token was created by a trusted party and hasn't been modified. When using the "none" algorithm:

1. The signature verification step is effectively skipped
2. Any JWT with `{"alg":"none"}` in its header will be accepted
3. Attackers can create arbitrary tokens with any claims

**Exploitation Mechanics:**

To exploit this vulnerability, an attacker would:

1. Create a JWT with desired claims (e.g., user identity, roles, permissions)
2. Set the algorithm to "none" in the header
3. Encode the header and payload in Base64Url format
4. Join them with periods (no signature needed)
5. Send the forged token in an Authorization header

Example of a forged token structure:
```
[Base64Url-encoded header].[Base64Url-encoded payload].

```

Note the trailing period with nothing after it, as no signature is provided.

**Attack Constraints:**

This vulnerability has virtually no constraints. It does not require:
- Access to legitimate credentials
- Knowledge of cryptographic keys
- Advanced technical skills
- Special tools beyond basic knowledge of JWT structure

The only information an attacker needs is the general format of the JWT payload used by the application, which can often be inferred or discovered through documentation, error messages, or experimentation.

# Remediation Steps
## Replace 'none' Algorithm with Secure JWT Validation

**Priority**: P0

Immediately remove the use of the 'none' algorithm and implement proper cryptographic verification:

```java
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

public class SecureJWTHandler {
  private final Algorithm algorithm;
  
  public SecureJWTHandler(String secretKey) {
    // Use a secure algorithm like HMAC-SHA256 with a strong secret key
    this.algorithm = Algorithm.HMAC256(secretKey);
  }
  
  public DecodedJWT verifyToken(String token) {
    JWTVerifier verifier = JWT.require(algorithm)
        .withIssuer("acme-auth")       // Validate token issuer
        .acceptLeeway(1)               // 1 sec for clock skew
        .build();
    return verifier.verify(token);
  }
}

```

Key security improvements:
1. Uses cryptographically secure algorithm (HMAC-SHA256) instead of 'none'
2. Requires a secret key that must be kept secure
3. Adds issuer validation to ensure tokens come from a trusted source
4. Implements a small leeway for clock skew without compromising security

For production environments, consider using asymmetric algorithms like RSA or ECDSA if tokens need to be verified across multiple services.
## Implement Explicit Rejection of 'none' Algorithm

**Priority**: P1

Add an additional layer of protection that explicitly rejects any token using the 'none' algorithm, even if library defaults change:

```java
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

public class EnhancedSecureJWTHandler {
  private final Algorithm algorithm;
  
  public EnhancedSecureJWTHandler(String secretKey) {
    this.algorithm = Algorithm.HMAC256(secretKey);
  }
  
  public DecodedJWT verifyToken(String token) throws JWTVerificationException {
    // First decode the token without verification to check its algorithm
    DecodedJWT unverifiedJwt = JWT.decode(token);
    String tokenAlg = unverifiedJwt.getAlgorithm();
    
    // Reject tokens using 'none' algorithm or with missing algorithm
    if (tokenAlg == null || tokenAlg.equalsIgnoreCase("none")) {
      throw new JWTVerificationException("Insecure algorithm detected: Tokens using 'none' algorithm are explicitly rejected");
    }
    
    // Proceed with regular verification using secure algorithm
    JWTVerifier verifier = JWT.require(algorithm)
        .withIssuer("acme-auth")
        .acceptLeeway(1)
        .build();
        
    return verifier.verify(token);
  }
}

```

This implementation provides defense-in-depth by:
1. Performing a preliminary check to reject any token using the 'none' algorithm
2. Adding explicit verification even if the underlying library behavior changes
3. Providing clear error messages for security monitoring
4. Maintaining all the security benefits of the primary fix


# References
* CWE-327 | [Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
* CWE-287 | [Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
* CWE-347 | [Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
* A02:2021 | [Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
* A07:2021 | [Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
