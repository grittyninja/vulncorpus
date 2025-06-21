# Weak Random Number Generation for Session Tokens

# Vulnerability Case
During the security review of Acme Corp's Java-based authentication module, we identified the use of non-cryptographic random number generators where session tokens were created using `java.util.Random()`. The discovery was made during a static code analysis of the source code responsible for generating secret session identifiers on a Spring Boot application deployed in a Tomcat environment. The use of weak RNGs like `java.util.Random()` results in predictable token values, increasing the risk of token prediction attacks that could compromise user sessions and sensitive data. This issue is pertinent across several components of the Acme Corp technology stack, including RESTful APIs that depend on token-based authentication.

```java
// Vulnerable token generation using insecure RNG
import java.util.Random;

public class SessionTokenGenerator {

  public static String generateToken() {
    StringBuilder token = new StringBuilder();
    Random rand = new Random(); // Insecure random number generator

    for (int i = 0; i < 16; i++) {
      // Generates a hex character potentially predictable if the RNG state is known
      token.append(Integer.toHexString(rand.nextInt(16)));
    }
    return token.toString();
  }

  public static void main(String[] args) {
    System.out.println("Generated session token: " + generateToken());
  }
}
```

In the code snippet above, the use of `java.util.Random()` introduces predictability due to its deterministic algorithm if the seed value is known or can be inferred. An attacker with knowledge of the underlying RNG logic could systematically reconstruct the RNG state, thereby predicting future tokens generated in the application. This vulnerability could be exploited to perform session hijacking or unauthorized access to user accounts, posing a significant business impact by jeopardizing both data integrity and customer trust across Acme Corp's digital services.


context: java.lang.security.audit.crypto.weak-random.weak-random Detected use of the functions `Math.random()` or `java.util.Random()`. These are both not cryptographically strong random number generators (RNGs). If you are using these RNGs to create passwords or secret tokens, use `java.security.SecureRandom` instead.

# Vulnerability Breakdown
This vulnerability involves the use of non-cryptographic random number generators (`java.util.Random`) for creating session tokens in Acme Corp's Java-based authentication module.

1. **Key vulnerability elements**:
   - Use of `java.util.Random()` instead of `java.security.SecureRandom` for security-critical token generation
   - 16-character hex token provides only 64 bits of entropy (when implemented correctly)
   - Deterministic algorithm with predictable sequence if seed is discovered
   - Implementation in authentication module affecting Spring Boot application
   - Used for generating session identifiers that control access to user accounts

2. **Potential attack vectors**:
   - Statistical analysis of collected tokens to determine RNG state
   - Seed prediction through observation of token patterns
   - Brute force attacks against the limited token space
   - Session prediction leading to account takeover

3. **Severity assessment**:
   - High confidentiality impact through potential unauthorized access to user data
   - High integrity impact through ability to modify user data via hijacked sessions
   - Network accessible attack vector increases exposure
   - High attack complexity due to mathematical analysis required
   - No privileges or user interaction needed for exploitation

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): High (H) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): None (N) 

# Description
A significant security vulnerability has been identified in Acme Corp's Java-based authentication module where session tokens are generated using `java.util.Random()` instead of cryptographically secure alternatives. This implementation is found in the Spring Boot application deployed in a Tomcat environment.

```java
// Vulnerable code snippet from authentication module
public class SessionTokenGenerator {
  public static String generateToken() {
    StringBuilder token = new StringBuilder();
    Random rand = new Random(); // Insecure random number generator
    for (int i = 0; i < 16; i++) {
      token.append(Integer.toHexString(rand.nextInt(16)));
    }
    return token.toString();
  }
}

```

The vulnerability stems from `java.util.Random()` being a non-cryptographic pseudo-random number generator (PRNG) that produces deterministic and potentially predictable sequences. When used for security-critical functions like session token generation, it creates a significant risk of token prediction attacks. An attacker could potentially analyze collected tokens, determine the internal state of the random number generator, and predict future token values, ultimately leading to unauthorized access through session hijacking.

# CVSS
**Score**: 7.4 \
**Vector**: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N \
**Severity**: High

The High severity rating (7.4) is justified by the following factors:

- **Network (N) attack vector**: The vulnerability can be exploited remotely by any attacker who can interact with the application's authentication system

- **High (H) attack complexity**: While exploitation is possible, it requires advanced understanding of random number generation algorithms and statistical analysis to successfully predict tokens

- **No privileges (N) required**: An attacker doesn't need any authenticated access to begin collecting tokens and analyzing patterns

- **No user interaction (N) needed**: The attack can be carried out without requiring actions from legitimate users

- **Unchanged (U) scope**: The vulnerability impacts only the authentication component itself without crossing security boundaries

- **High (H) confidentiality impact**: Successful exploitation provides unauthorized access to user accounts and potentially sensitive personal information

- **High (H) integrity impact**: An attacker could modify user data through the compromised session

- **None (N) availability impact**: The vulnerability doesn't directly affect system availability

Though the attack complexity is high due to the mathematical analysis required, the potential for complete account compromise without requiring privileges or user interaction warrants the High severity rating.

# Exploitation Scenarios
**Scenario 1: Token Analysis and Prediction**
An attacker creates multiple accounts or sessions in the application, collecting a series of session tokens (e.g., 20-30 consecutive tokens). Using knowledge of how `java.util.Random()` works, the attacker analyzes these tokens to reverse-engineer the internal state of the random number generator. With this information, the attacker can predict the next tokens that will be generated by the system. When legitimate users create new sessions, the attacker can hijack these sessions by using the predicted token values, gaining unauthorized access to user accounts and sensitive information.

**Scenario 2: Time-Based Seed Attack**
If the `Random` object is instantiated without an explicit seed (as in the vulnerable code), Java uses the current system time as a seed. An attacker who can approximately determine when the application was last restarted can narrow down the possible seeds to a manageable range. By testing tokens generated from these potential seeds against actual session tokens, the attacker can determine the exact seed used by the application, completely compromising the token generation process and allowing prediction of all future tokens.

**Scenario 3: Targeted Administrative Account Compromise**
An attacker observes that administrative users typically log in at specific times (e.g., Monday mornings). By monitoring token generation patterns and timing, the attacker predicts the likely token that will be assigned to the next administrative user. The attacker then waits for the admin to log in and uses the predicted token to hijack the administrative session, gaining elevated privileges within the application and access to sensitive administrative functions.

# Impact Analysis
**Business Impact:**
- Unauthorized access to user accounts and their sensitive personal information
- Potential exposure of confidential customer data leading to privacy violations
- Loss of customer trust and significant reputational damage
- Regulatory non-compliance with data protection laws (GDPR, CCPA, etc.)
- Financial losses from breach notification, remediation, and potential legal penalties
- Business disruption during emergency fixes and potential system-wide session resets

**Technical Impact:**
- Complete compromise of the authentication and session management system
- Unauthorized access to protected API endpoints and sensitive user data
- Potential for privilege escalation if admin sessions are compromised
- Data integrity issues resulting from unauthorized modifications to user information
- Bypass of access controls protecting sensitive functionality
- Difficulty in detecting these attacks as they use legitimate-looking session tokens
- Potential for persistent unauthorized access across multiple user accounts

# Technical Details
The vulnerability centers on the improper use of `java.util.Random()` for generating session tokens, which creates a significant security risk in the authentication system.

```java
import java.util.Random;

public class SessionTokenGenerator {
  public static String generateToken() {
    StringBuilder token = new StringBuilder();
    Random rand = new Random(); // Insecure random number generator
    for (int i = 0; i < 16; i++) {
      // Generates a hex character (0-f) - note this only uses 4 bits per character
      token.append(Integer.toHexString(rand.nextInt(16)));
    }
    return token.toString();
  }
}

```

**Technical Issues:**

1. **Non-cryptographic PRNG**: `java.util.Random` is a Linear Congruential Generator (LCG) with the formula:
   ```
   next(n) = (seed * 0x5DEECE66DL + 0xBL) & ((1L << 48) - 1)
   
   ```
   This algorithm is deterministic and not designed for security purposes.

2. **Predictable sequence**: If an attacker can determine the internal state of the PRNG (which has only 2^48 possible states), they can predict all future outputs.

3. **Limited entropy**: The implementation generates 16 hex characters (0-f), each representing only 4 bits of entropy. This provides a maximum of 64 bits of entropy, which is below the recommended minimum of 128 bits for security tokens.

4. **Default time-based seeding**: When `Random` is instantiated without an explicit seed, it uses the current system time in milliseconds, further reducing entropy and making the seed potentially guessable.

5. **Static method**: The implementation uses a static method that creates a new `Random` instance for each token, potentially making the sequence even more predictable if tokens are generated in quick succession.

**Attack Methodology:**

1. **State Recovery**: Collect several consecutive tokens
2. **Analysis**: Use mathematical techniques to determine the internal state of the PRNG
3. **Prediction**: Once the state is known, predict all future tokens
4. **Exploitation**: Use predicted tokens to hijack user sessions

The Java standard library explicitly warns against using `Random` for security purposes in its documentation, stating that "Instances of `java.util.Random` are not cryptographically secure. Consider instead using `SecureRandom` to get a cryptographically secure pseudo-random number generator for use by security-sensitive applications."

# Remediation Steps
## Replace Random with SecureRandom

**Priority**: P0

Immediately replace the use of `java.util.Random` with `java.security.SecureRandom` for all security-sensitive token generation:

```java
import java.security.SecureRandom;
import java.util.Base64;

public class SecureSessionTokenGenerator {
  // Use a properly seeded instance of SecureRandom
  private static final SecureRandom secureRandom = new SecureRandom();
  
  public static String generateToken() {
    // Generate at least 16 bytes (128 bits) of random data
    byte[] randomBytes = new byte[16];
    secureRandom.nextBytes(randomBytes);
    
    // Use URL-safe Base64 encoding without padding
    return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
  }
}

```

This implementation:
1. Uses `SecureRandom` which is designed for cryptographic purposes
2. Generates 16 bytes (128 bits) of entropy, which is the minimum recommended for security tokens
3. Uses Base64 encoding to represent the full range of random bytes efficiently
4. Creates a single instance of `SecureRandom` to leverage proper seeding and initialization
5. Uses URL-safe encoding for compatibility in web applications
## Implement Token Security Best Practices

**Priority**: P1

Enhance the token generation implementation with additional security features:

```java
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class EnhancedTokenGenerator {
  private static final SecureRandom secureRandom = new SecureRandom();
  private static final String HMAC_ALGORITHM = "HmacSHA256";
  private static final byte[] SERVER_SECRET = getOrCreateServerSecret(); // Load from secure storage
  
  public static String generateToken(String userId) {
    try {
      // Generate random component
      byte[] randomBytes = new byte[16];
      secureRandom.nextBytes(randomBytes);
      
      // Add timestamp to prevent token reuse across server restarts
      long timestamp = Instant.now().getEpochSecond();
      
      // Create message to sign: userId + timestamp + randomBytes
      String message = userId + ":" + timestamp + ":" + Base64.getEncoder().encodeToString(randomBytes);
      
      // Sign the message with server secret
      Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
      hmac.init(new SecretKeySpec(SERVER_SECRET, HMAC_ALGORITHM));
      byte[] signature = hmac.doFinal(message.getBytes());
      
      // Final token: message + signature
      String token = message + ":" + Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
      return Base64.getUrlEncoder().encodeToString(token.getBytes());
    } catch (Exception e) {
      throw new RuntimeException("Token generation failed", e);
    }
  }
  
  // Validate token and extract userId if valid
  public static String validateToken(String token) {
    try {
      // Decode token
      String decodedToken = new String(Base64.getUrlDecoder().decode(token));
      String[] parts = decodedToken.split(":");
      if (parts.length != 4) return null;
      
      String userId = parts[0];
      long timestamp = Long.parseLong(parts[1]);
      String randomComponent = parts[2];
      String receivedSignature = parts[3];
      
      // Check if token is expired (optional)
      long currentTime = Instant.now().getEpochSecond();
      if (currentTime - timestamp > 86400) return null; // 24 hour expiry
      
      // Verify signature
      String message = userId + ":" + timestamp + ":" + randomComponent;
      Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
      hmac.init(new SecretKeySpec(SERVER_SECRET, HMAC_ALGORITHM));
      byte[] expectedSignature = hmac.doFinal(message.getBytes());
      String expectedSignatureStr = Base64.getUrlEncoder().withoutPadding().encodeToString(expectedSignature);
      
      if (expectedSignatureStr.equals(receivedSignature)) {
        return userId; // Token is valid
      }
      return null; // Invalid signature
    } catch (Exception e) {
      return null; // Invalid token format
    }
  }
  
  private static byte[] getOrCreateServerSecret() {
    // Load from secure configuration or key management system
    // For development only: generate a random key
    byte[] secret = new byte[32];
    new SecureRandom().nextBytes(secret);
    return secret;
  }
}

```

This enhanced implementation:
1. Uses cryptographic signing to prevent token tampering
2. Includes timestamp to mitigate token reuse
3. Incorporates user ID into the token for stronger binding
4. Implements token validation with proper error handling
5. Adds expiration/timeout capability
6. Uses a server secret that should be securely stored and managed


# References
* CWE-338 | [Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html)
* CWE-326 | [Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
* CWE-330 | [Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
* A02:2021 | [Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
* A07:2021 | [Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
