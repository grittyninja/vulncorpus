# JWT Token Verification Bypass

# Vulnerability Case
During the security assessment of Acme Corp's Java authentication module built on Spring Boot and the Auth0 java-jwt library, we identified a critical vulnerability where JWT tokens are decoded without performing the mandatory signature verification step. During code review and dynamic testing, it became evident that the token’s integrity was not being validated before use, enabling attackers to forge tokens with arbitrary claims. The omission of the call to the `.verify()` method allows potentially malicious tokens to bypass authentication checks, posing a significant risk of privilege escalation and unauthorized access.

```java
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import javax.servlet.http.HttpServletRequest;

public class JwtProcessor {
  public String processToken(HttpServletRequest request) {
    // Retrieve the token from the HTTP header
    String token = request.getHeader("Authorization");
    
    // Vulnerable pattern: Decoding the JWT without verifying its signature
    DecodedJWT decodedJwt = JWT.decode(token);
    
    // Extract a claim without ensuring token integrity
    String userRole = decodedJwt.getClaim("role").asString();
    return userRole;
  }
}
```

Exploitation of this vulnerability involves a malicious actor crafting a JWT token with arbitrary claims, such as assigning an administrative role, and bypassing the signature verification process since the `.verify()` method is never invoked. In environments running Spring Boot with the Auth0 java-jwt library, this exploit can lead to unauthorized system access, allowing attackers to impersonate valid users, escalate privileges, and potentially exfiltrate sensitive data. The business impact is severe, as compromised tokens could undermine the entire trust model, leading to data breaches and a significant loss of customer and stakeholder confidence.


context: java.java-jwt.security.audit.jwt-decode-without-verify.java-jwt-decode-without-verify Detected the decoding of a JWT token without a verify step. JWT tokens must be verified before use, otherwise the token's integrity is unknown. This means a malicious actor could forge a JWT token with any claims. Call '.verify()' before using the token.

# Vulnerability Breakdown
This critical vulnerability stems from improper implementation of JWT token validation in Acme Corp's Java authentication module. The essential signature verification step is completely omitted, allowing attackers to forge valid-looking tokens with arbitrary claims.

1. **Key vulnerability elements**:
   - JWT tokens are decoded using `JWT.decode()` without subsequent verification
   - Token's cryptographic signature is never validated
   - Claims extracted from unverified tokens are trusted for authorization decisions
   - Built using Auth0's java-jwt library and Spring Boot framework

2. **Potential attack vectors**:
   - Crafting unauthorized admin tokens with elevated privileges
   - Impersonating legitimate users by forging tokens with their identifiers
   - Bypassing role-based access controls by including arbitrary role claims
   - Manipulating other security-critical claims (groups, permissions, etc.)

3. **Severity assessment**:
   - Complete authentication bypass requiring no special privileges
   - Network-accessible vulnerability with minimal exploitation complexity
   - Full system compromise possible by assuming administrative privileges
   - No user interaction required for exploitation
   - Impacts scope beyond the authentication component to all protected resources

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Changed (C)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): High (H) 

# Description
A critical authentication vulnerability has been identified in Acme Corp's Java authentication module built on Spring Boot and the Auth0 java-jwt library. The vulnerability stems from the application decoding JWT tokens without performing signature verification, which is a mandatory security step.

In the vulnerable implementation, the application uses `JWT.decode(token)` to parse the token's content but never calls the essential `.verify()` method to validate the token's cryptographic signature. This critical oversight allows attackers to forge tokens with arbitrary claims (such as elevated roles or permissions) that the system will accept as valid, effectively bypassing the entire authentication mechanism.

```java
// Vulnerable code pattern
DecodedJWT decodedJwt = JWT.decode(token);
String userRole = decodedJwt.getClaim("role").asString();
// Role is used for authorization without verification

```

This implementation treats all structurally valid JWTs as trustworthy, regardless of whether they were actually signed by the trusted authority, completely undermining the security model of the JWT authentication system.

# CVSS
**Score**: 10.0 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H \
**Severity**: Critical

This vulnerability receives the highest possible CVSS score of 10.0 (Critical) due to several aggravating factors:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely by anyone who can send requests to the application
- **Low Attack Complexity (AC:L)**: Exploiting this vulnerability is straightforward - an attacker only needs to craft a JWT with desired claims and no cryptographic expertise is required
- **No Privileges Required (PR:N)**: The attacker doesn't need any prior access or privileges to exploit this vulnerability
- **No User Interaction (UI:N)**: Exploitation can occur without any action from legitimate users
- **Changed Scope (S:C)**: The vulnerability in the authentication component affects resources managed by other security authorities (all protected APIs and data)
- **High Confidentiality Impact (C:H)**: Attackers can access any protected data by forging tokens with appropriate claims
- **High Integrity Impact (I:H)**: Attackers can modify data across the system by assuming administrative privileges
- **High Availability Impact (A:H)**: By accessing admin functionality, attackers could potentially disable services or cause system disruption

The absence of signature verification fundamentally breaks the JWT security model, effectively eliminating authentication controls entirely. This represents a worst-case scenario for authentication vulnerabilities.

# Exploitation Scenarios
**Scenario 1: Administrative Access**
An attacker analyzes the application's behavior and determines it uses JWT tokens with a "role" claim for authorization. The attacker creates a forged token with a payload containing `{"sub":"attacker","role":"ADMIN"}` and signs it with an arbitrary key. When this token is submitted in the Authorization header, the vulnerable application decodes it, extracts the "ADMIN" role, and grants full administrative access without verifying the signature. The attacker now has complete control over the system.

**Scenario 2: User Impersonation**
After observing a legitimate JWT token format, an attacker notices user identifiers are stored in the "sub" claim. The attacker creates a forged token with another user's identifier (e.g., `{"sub":"victim@acmecorp.com"}`) without knowing the victim's password. The application accepts this token without signature verification, allowing the attacker to impersonate the victim and access their personal data, make transactions on their behalf, or perform other unauthorized actions.

**Scenario 3: Multi-tenant Data Access**
In a SaaS application with multiple organization tenants, tenant identification is managed via a "tenant_id" claim in the JWT. An attacker who is a legitimate user of Tenant A creates a forged token with a claim for Tenant B. Due to missing verification, the system accepts this token, allowing the attacker to access, modify, or exfiltrate Tenant B's confidential business data.

# Impact Analysis
**Business Impact:**
- Complete compromise of authentication system, potentially leading to unauthorized access to all protected resources
- Data breaches involving customer information, intellectual property, or other sensitive data
- Potential regulatory violations and associated penalties (GDPR, HIPAA, etc.)
- Significant reputation damage and loss of customer trust if exploitation becomes public
- Legal liability for failing to implement basic security controls
- Financial losses from remediation costs, incident response, and potential lawsuits

**Technical Impact:**
- Unauthorized access to any protected API endpoint or resource
- Ability to perform privileged operations by assuming administrative roles
- Potential for complete system compromise including database access
- Bypass of role-based access controls and permission systems
- User impersonation without knowledge of credentials
- Cross-tenant data access in multi-tenant environments
- No reliable audit trail of legitimate vs. fraudulent access
- Potential ability to create persistent backdoor access by modifying system settings

# Technical Details
The vulnerability exists in the JwtProcessor class where JWT tokens are processed incorrectly. The fundamental issue is that the application uses the `JWT.decode()` method from Auth0's java-jwt library, which only parses the token structure without verifying its cryptographic signature:

```java
public class JwtProcessor {
  public String processToken(HttpServletRequest request) {
    // Retrieve the token from the HTTP header
    String token = request.getHeader("Authorization");
    
    // Vulnerable pattern: Decoding the JWT without verifying its signature
    DecodedJWT decodedJwt = JWT.decode(token);
    
    // Extract a claim without ensuring token integrity
    String userRole = decodedJwt.getClaim("role").asString();
    return userRole;
  }
}

```

**Technical Explanation:**

JWT tokens consist of three parts separated by dots: header.payload.signature

1. **Header**: Typically contains the token type and signing algorithm
2. **Payload**: Contains the claims (data) such as user ID, roles, and expiration
3. **Signature**: Cryptographically ensures the token hasn't been modified

The `JWT.decode()` method only parses these segments without validating the signature. This is explicitly warned against in the Auth0 java-jwt documentation, which states that decode should only be used for reading the token when you already trust it.

**Exploitation Details:**

To exploit this vulnerability:

1. Attacker observes the structure of a legitimate JWT used by the application
2. Attacker creates a new JWT with modified claims (e.g., elevated role)
3. Attacker base64-encodes the header and modified payload
4. Attacker adds any arbitrary signature (which won't be checked)
5. The token is submitted to the vulnerable application
6. Application decodes the token using `JWT.decode()` without verification
7. Application trusts the unverified claims and grants elevated access

Example of a forged token:
```
Header: { "alg": "HS256", "typ": "JWT" }
Payload: { "sub": "attacker", "role": "ADMIN", "exp": 1713048450 }
Signature: [arbitrary invalid signature that will never be checked]

```

When encoded, this might look like:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJBRE1JTiIsImV4cCI6MTcxMzA0ODQ1MH0.invalid_signature_that_is_never_verified

```

This approach completely circumvents the authentication system, as the whole purpose of JWT's signature is to ensure the claims were issued by a trusted authority.

# Remediation Steps
## Implement Proper JWT Verification

**Priority**: P0

Replace the vulnerable token processing with proper verification:

```java
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import javax.servlet.http.HttpServletRequest;

public class JwtProcessor {
  private final JWTVerifier verifier;
  
  public JwtProcessor(String secret) {
    // Set up the verifier once with the proper secret and configuration
    this.verifier = JWT.require(Algorithm.HMAC256(secret))
        .withIssuer("acme-auth")  // Optional: validate issuer
        .build();
  }
  
  public String processToken(HttpServletRequest request) {
    // Extract token from Authorization header
    String authHeader = request.getHeader("Authorization");
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      throw new SecurityException("Missing or invalid Authorization header");
    }
    
    String token = authHeader.substring(7); // Remove "Bearer " prefix
    
    try {
      // Properly verify the token's signature and claims
      DecodedJWT verifiedJwt = verifier.verify(token);
      
      // Only extract claims after verification
      String userRole = verifiedJwt.getClaim("role").asString();
      return userRole;
    } catch (Exception e) {
      // Handle verification failures securely
      throw new SecurityException("Token validation failed", e);
    }
  }
}

```

This implementation:
1. Creates a JWT verifier with the correct algorithm and secret
2. Properly extracts the token from the Authorization header
3. Verifies the token's signature and claims before using them
4. Handles verification failures securely
5. Only extracts claims from verified tokens
## Implement Comprehensive JWT Security Controls

**Priority**: P1

Enhance JWT security by implementing additional best practices:

```java
public class EnhancedJwtProcessor {
  private final JWTVerifier verifier;
  
  public EnhancedJwtProcessor(String secret) {
    // Create a more secure verifier with comprehensive validation
    this.verifier = JWT.require(Algorithm.HMAC256(secret))
        .withIssuer("acme-auth")                // Validate token issuer
        .withAudience("acme-api")                // Validate intended audience
        .acceptLeeway(5)                         // Small leeway for clock skew (5 seconds)
        .withClaimPresence("sub")                // Ensure subject claim exists
        .withClaimPresence("exp")                // Ensure expiration claim exists
        .build();
  }
  
  public DecodedJWT processToken(HttpServletRequest request) {
    // Extract token from Authorization header
    String authHeader = request.getHeader("Authorization");
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      throw new SecurityException("Missing or invalid Authorization header");
    }
    
    String token = authHeader.substring(7); // Remove "Bearer " prefix
    
    try {
      // Verify the token with enhanced validation
      DecodedJWT verifiedJwt = verifier.verify(token);
      
      // Additional custom validations
      validateCustomClaims(verifiedJwt);
      checkTokenAgainstBlacklist(token);
      
      return verifiedJwt;
    } catch (TokenExpiredException e) {
      // Specific handling for expired tokens
      throw new SecurityException("Token has expired", e);
    } catch (JWTVerificationException e) {
      // Generic handling for all other verification issues
      throw new SecurityException("Token validation failed", e);
    }
  }
  
  private void validateCustomClaims(DecodedJWT jwt) {
    // Implement custom business validations
    String tenant = jwt.getClaim("tenant_id").asString();
    if (tenant == null || tenant.isEmpty()) {
      throw new SecurityException("Missing required tenant_id claim");
    }
    
    // Add other custom validations as needed
  }
  
  private void checkTokenAgainstBlacklist(String token) {
    // Check if the token has been revoked
    // Implementation depends on your token revocation strategy
    if (tokenBlacklistService.isBlacklisted(token)) {
      throw new SecurityException("Token has been revoked");
    }
  }
}

```

This enhanced implementation includes:
1. Validation of issuer and audience claims
2. Requirement for expiration claim to prevent long-lived tokens
3. Custom claim validation for business-specific requirements
4. Token blacklist/revocation checks
5. Specific error handling for different verification failures


# References
* CWE-347 | [Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
* CWE-287 | [Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
* CWE-288 | [Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html)
* A07:2021 | [Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
* A01:2021 | [Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
