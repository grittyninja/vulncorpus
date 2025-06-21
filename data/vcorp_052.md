# Insecure Random Number Generator Used for Session Token Generation

# Vulnerability Case
During the recent security audit of Acme Corp's Golang-based microservices architecture, our team identified a critical weakness in the session token generation module. The vulnerability was discovered during a manual code review of the authentication service, where we observed that the service uses the standard library's `math/rand` package to create cryptographic tokens. In a production environment running on Kubernetes with a modern Go stack, this misuse of a non-cryptographic pseudo-random number generator potentially allows an attacker to predict session tokens, increasing the risk of session hijacking and unauthorized access. Given the predictable seeding based on the system clock, statistical analysis and repeated token observation could lead to an accurate approximation of the RNG state, thereby enabling malicious exploitation.

```go
// Vulnerable code snippet from the token generation module
package main

import (
    "fmt"
    "math/rand"
    "time"
)

func generateToken(n int) string {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    token := make([]byte, n)
    // Using time-based seed with math/rand, which is predictable
    rand.Seed(time.Now().UnixNano())
    for i := range token {
        token[i] = charset[rand.Intn(len(charset))]
    }
    return string(token)
}

func main() {
    fmt.Println("Generated token:", generateToken(16))
}
```

The exploitation of this vulnerability relies on the inherent determinism of `math/rand` when seeded predictably, allowing an adversary to reconstruct the internal generator state by observing multiple token outputs. By statistically modeling the token generation process, an attacker could potentially predict future tokens or reverse-engineer valid session identifiers, leading to unauthorized access to sensitive user data or critical system functions. This vulnerability, if exploited, could result in significant business impact by undermining user trust and exposing the organization to costly data breaches and compliance violations.


context: go.lang.security.audit.crypto.math_random.math-random-used Do not use `math/rand`. Use `crypto/rand` instead.

# Vulnerability Breakdown
This vulnerability involves the use of a non-cryptographic pseudo-random number generator for generating security-critical session tokens in a production microservices environment.

1. **Key vulnerability elements**:
   - Using `math/rand` instead of `crypto/rand` for generating session tokens
   - Predictable seeding based on system time (time.Now().UnixNano())
   - Resetting the PRNG seed on each token generation call
   - Implementation in Golang microservices running in Kubernetes

2. **Potential attack vectors**:
   - Statistical analysis of collected tokens to determine RNG state
   - Time-based inference attacks (knowing when tokens were created)
   - Session prediction and hijacking
   - Unauthorized access to user accounts and data

3. **Severity assessment**:
   - High impact on both confidentiality and integrity
   - Network-accessible attack vector
   - Requires sophisticated attacker with statistical analysis capability
   - No special privileges required to observe and analyze tokens
   - No user interaction required for exploitation

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
A critical vulnerability has been identified in Acme Corp's Golang-based microservices architecture, specifically in the session token generation functionality. The authentication service is using the standard library's `math/rand` package, which is a non-cryptographically secure pseudo-random number generator (PRNG), to generate security-critical session tokens.

The vulnerability exists in the `generateToken` function, which:

1. Uses `math/rand` instead of the appropriate `crypto/rand` package
2. Seeds the PRNG with the current timestamp (`time.Now().UnixNano()`)
3. Re-seeds the generator on each function call, making the state predictable

```go
func generateToken(n int) string {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    token := make([]byte, n)
    // Using time-based seed with math/rand, which is predictable
    rand.Seed(time.Now().UnixNano())
    for i := range token {
        token[i] = charset[rand.Intn(len(charset))]
    }
    return string(token)
}

```

This implementation makes session tokens predictable to attackers who can observe multiple tokens and analyze patterns. Since tokens are seeded with timestamps, an attacker who roughly knows when a token was generated can significantly narrow down the possible token values, potentially leading to session hijacking and unauthorized access to sensitive user data.

# CVSS
**Score**: 7.4 \
**Vector**: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N \
**Severity**: High

The High severity rating (CVSS score 7.4) is justified by the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely over the network by observing and analyzing token patterns.

- **High Attack Complexity (AC:H)**: Exploitation requires sophisticated statistical analysis of multiple tokens and understanding of PRNG behavior, which demands technical expertise and is not trivial to execute.

- **No Privileges Required (PR:N)**: An attacker doesn't need any privileges to observe tokens and perform the analysis needed for prediction.

- **No User Interaction (UI:N)**: Exploitation doesn't require any actions from legitimate users.

- **Unchanged Scope (S:U)**: The impact is contained within the vulnerable authentication component.

- **High Confidentiality Impact (C:H)**: Successful exploitation allows access to sensitive user data across the application through session hijacking.

- **High Integrity Impact (I:H)**: An attacker could modify data as if they were the legitimate user whose session was compromised.

- **No Availability Impact (A:N)**: The vulnerability doesn't directly impact system availability.

This vulnerability is particularly concerning because it undermines the fundamental security assumption that session tokens are unpredictable, potentially allowing attackers to impersonate legitimate users and access sensitive data without detection.

# Exploitation Scenarios
**Scenario 1: Token Prediction Attack**
An attacker monitors the network traffic to the application and collects multiple session tokens (e.g., from HTTP headers or cookies). They analyze these tokens to identify patterns and correlations with timestamps. Using statistical modeling and an understanding of how `math/rand` works, they develop an algorithm to predict valid session tokens. The attacker then uses these predicted tokens to hijack active user sessions, gaining unauthorized access to sensitive user data and functionality.

**Scenario 2: Time-Window Attack**
An attacker who knows approximately when a high-value target (like an administrator) logs into the system can narrow down the potential seed values used for token generation. Since the seed is based on `time.Now().UnixNano()`, the attacker generates all possible tokens that could have been created in a specific time window (e.g., within a few seconds or minutes of the known login time). They then try these tokens until finding a valid one, allowing them to hijack the administrator's session.

**Scenario 3: State Reconstruction Attack**
A sophisticated attacker with access to multiple sequential tokens can potentially reconstruct the internal state of the `math/rand` generator. The implementation of `math/rand` is known, and by observing enough outputs, the attacker can determine the generator's state and precisely predict all future tokens it will generate. This allows them to compromise any newly created user session systematically.

# Impact Analysis
**Business Impact:**
- Potential unauthorized access to customer accounts and sensitive personal data
- Risk of financial loss if attackers gain access to payment or financial information
- Regulatory compliance violations (GDPR, CCPA, etc.) if personal data is exposed
- Damage to company reputation and customer trust if a breach occurs
- Potential legal liability from affected users
- Costs associated with incident response, forensic investigation, and remediation

**Technical Impact:**
- Complete compromise of the authentication mechanism
- Ability for attackers to impersonate legitimate users
- Unauthorized access to sensitive user data across all microservices
- Potential privilege escalation if administrator sessions are compromised
- Bypassing of access controls and audit logs (actions appear to come from legitimate users)
- Difficulty detecting compromised sessions through normal monitoring
- Invalidation of security assumptions in dependent systems that trust the authentication service

# Technical Details
The vulnerability stems from two fundamental cryptographic mistakes in the session token generation implementation:

1. **Using a non-cryptographic PRNG for security-critical functionality**
   
   The code uses Go's `math/rand` package, which is explicitly documented as not being cryptographically secure. From the Go documentation: "Package rand implements pseudo-random number generators... This package's output may be predictable and should not be used for security-sensitive work."

   The `math/rand` package uses the Mersenne Twister algorithm, which is designed for statistical randomness and performance, not security. Its internal state can be reconstructed after observing a sufficient number of outputs.

2. **Predictable seeding based on system time**

   ```go
   // Reseeds on every call using time
   rand.Seed(time.Now().UnixNano())
   
```

   This compounds the problem in several ways:
   
   - Time is a predictable entropy source
   - The granularity of `UnixNano()` is known
   - Reseeding on every call means two tokens generated in the same nanosecond would be identical
   - An attacker who knows approximately when a token was generated can drastically reduce the search space

**Exploitation Mechanics:**

To exploit this vulnerability, an attacker would:

1. Collect multiple tokens through network monitoring or other means
2. Analyze the token patterns to identify the character set used (though this is visible in the source code)
3. Using knowledge of the `math/rand` algorithm, attempt to reconstruct the internal state or narrow down the possible seed values
4. Generate candidate tokens based on potential seed values within a relevant time window
5. Test these candidate tokens against the application to identify valid sessions

The code also has an additional design issue: it reseeds the PRNG on every call to `generateToken()`. This means that the global PRNG state is modified each time, which could cause issues with other parts of the application that might be using `math/rand`. It also means that tokens generated within the same nanosecond would be identical, increasing collision probability.

# Remediation Steps
## Replace math/rand with crypto/rand

**Priority**: P0

Immediately replace the non-cryptographic PRNG with Go's cryptographically secure random number generator:

```go
import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
)

func generateSecureToken(length int) (string, error) {
    // Create a byte slice to hold the random data
    b := make([]byte, length)
    
    // Fill with cryptographically secure random bytes
    _, err := rand.Read(b)
    if err != nil {
        return "", fmt.Errorf("error generating random bytes: %w", err)
    }
    
    // Encode as base64 to create a printable token
    // Use RawURLEncoding to avoid characters that might need escaping in URLs
    return base64.RawURLEncoding.EncodeToString(b), nil
}

// Usage example
func main() {
    token, err := generateSecureToken(16) // 16 bytes = 128 bits of entropy
    if err != nil {
        fmt.Println("Error:", err)
        return
    }
    fmt.Println("Secure token:", token)
}

```

Alternatively, if you need to maintain the same character set for compatibility reasons:

```go
import (
    "crypto/rand"
    "fmt"
    "io"
    "math/big"
)

func generateSecureToken(n int) (string, error) {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    token := make([]byte, n)
    charsetLength := big.NewInt(int64(len(charset)))
    
    for i := range token {
        // Secure random index within charset length
        randomIndex, err := rand.Int(rand.Reader, charsetLength)
        if err != nil {
            return "", fmt.Errorf("error generating random index: %w", err)
        }
        token[i] = charset[randomIndex.Int64()]
    }
    
    return string(token), nil
}

```

This implementation:
- Uses `crypto/rand` which is cryptographically secure
- Properly handles errors from the random number generator
- Doesn't rely on predictable seed values
- Provides sufficient entropy for session tokens
## Implement Additional Token Security Measures

**Priority**: P1

Enhance session token security beyond just improving the random number generation:

```go
package session

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "fmt"
    "time"
)

type SessionToken struct {
    Token     string    `json:"token"`
    ExpiresAt time.Time `json:"expires_at"`
    UserID    int64     `json:"user_id"`
}

func GenerateSessionToken(userID int64, ipAddress string, userAgent string) (*SessionToken, error) {
    // Create a sufficiently large random component (32 bytes = 256 bits)
    randomBytes := make([]byte, 32)
    if _, err := rand.Read(randomBytes); err != nil {
        return nil, fmt.Errorf("failed to generate random bytes: %w", err)
    }
    
    // Include contextual information in token generation
    now := time.Now()
    expiresAt := now.Add(24 * time.Hour) // Token valid for 24 hours
    
    // Combine random component with contextual information
    h := sha256.New()
    h.Write(randomBytes)
    h.Write([]byte(fmt.Sprintf("%d", userID)))
    h.Write([]byte(ipAddress))
    h.Write([]byte(userAgent))
    h.Write([]byte(now.Format(time.RFC3339Nano)))
    
    tokenBytes := h.Sum(nil)
    token := base64.RawURLEncoding.EncodeToString(tokenBytes)
    
    return &SessionToken{
        Token:     token,
        ExpiresAt: expiresAt,
        UserID:    userID,
    }, nil
}

func ValidateSessionToken(token string, userID int64, ipAddress string, userAgent string) bool {
    // Implement token validation logic
    // This could include verifying the token hasn't expired, checking for revocation,
    // and optionally binding the token to IP address/user agent
    return true // Replace with actual validation
}

```

This implementation adds several security enhancements:

1. Adds expiration timestamps to tokens
2. Incorporates user context (IP address, user agent) to bind tokens to specific clients
3. Uses a cryptographic hash to combine random data with contextual information
4. Provides a structure for tracking and validating tokens
5. Allows for additional validation checks during token verification

Consider additional measures:
- Implement token rotation (periodically issue new tokens)
- Create a token revocation mechanism
- Store token hashes rather than raw tokens in your database
- Add rate limiting for failed authentication attempts


# References
* CWE-338 | [Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html)
* CWE-330 | [Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
* CWE-327 | [Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
* A02:2021 | [Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
* A07:2021 | [Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
