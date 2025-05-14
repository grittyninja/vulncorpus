# JWT None Algorithm Vulnerability in Go API Services

# Vulnerability Case
During a security assessment of Acme Corp's Go-based API services, we discovered that the application’s JWT validation logic was inadvertently configured to accept tokens signed with the `none` algorithm. Our analysis revealed that the implementation leverages the `jwt-go` library without explicitly enforcing algorithm restrictions, allowing crafted tokens to bypass signature verification. Verification was achieved by constructing a JWT token with a header indicating `alg": "none"`, which the vulnerable service accepted as valid. This vulnerability, detected through both static analysis and dynamic testing, exposes the system to unauthorized access through forged tokens.

```go
package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
)

func main() {
	// Crafted JWT token with header {"alg": "none"}
	tokenString := "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."

	// Token parsing without enforcing expected algorithm
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// No explicit check for the signing method is performed here
		return []byte("secret"), nil
	})

	if err != nil {
		fmt.Println("Error parsing token:", err)
	} else if token.Valid {
		fmt.Println("Token is valid (vulnerable to 'none' algorithm)")
	}
}
```

The vulnerability stems from not validating the JWT's specified algorithm against an expected signing method, thereby allowing an attacker to forge a token with `alg": "none"`. Exploitation involves crafting a token that omits signature verification, granting an attacker the ability to impersonate users or escalate privileges. In a real-world deployment using Go and the jwt-go library, such an exploit could lead to unauthorized data access and control over critical business functionalities, significantly impacting overall security and potentially resulting in data breaches or regulatory non-compliance.


context: go.jwt-go.security.jwt-none-alg.jwt-go-none-algorithm Detected use of the 'none' algorithm in a JWT token. The 'none' algorithm assumes the integrity of the token has already been verified. This would allow a malicious actor to forge a JWT token that will automatically be verified. Do not explicitly use the 'none' algorithm. Instead, use an algorithm such as 'HS256'.

# Vulnerability Breakdown
This vulnerability involves a critical authentication bypass in Acme Corp's Go-based API services due to improper JWT validation configuration. The implementation accepts tokens signed with the 'none' algorithm, completely circumventing signature verification.

1. **Key vulnerability elements**:
   - JWT validation accepts tokens with 'alg: none' header
   - The jwt-go library is used without algorithm restrictions
   - No verification of the signing method in the token validation callback
   - Authentication can be completely bypassed with crafted tokens

2. **Potential attack vectors**:
   - Forging tokens with 'none' algorithm to impersonate any user
   - Escalating privileges by modifying payload claims
   - Bypassing authentication for any protected API endpoint
   - Gaining unauthorized access to sensitive data and operations

3. **Severity assessment**:
   - Network-accessible attack vector (remotely exploitable)
   - Straightforward exploitation requiring minimal skill
   - No privileges or user interaction required
   - High impact on confidentiality and integrity
   - Critical security primitive (authentication) is compromised

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): None (N) 

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

# Description
A critical authentication bypass vulnerability exists in Acme Corp's Go-based API services due to improper JWT validation. The application uses the `jwt-go` library but fails to verify the signing algorithm, allowing attackers to forge tokens with the `none` algorithm that bypass signature verification entirely.

The vulnerability is present in the token validation callback function, which doesn't include an explicit check for the expected signing method:

```go
token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    // No explicit check for the signing method is performed here
    return []byte("secret"), nil
})

```

By crafting a JWT with header `{"alg": "none"}`, an attacker can create tokens that will be accepted as valid without any cryptographic verification. This completely undermines the authentication system, allowing unauthorized access to protected resources and potentially enabling privilege escalation.

# CVSS
**Score**: 9.1 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N \
**Severity**: Critical

The Critical severity rating (9.1) is justified by the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely without requiring local access or adjacent network positioning. Any user who can send requests to the API service can attempt exploitation.

- **Low Attack Complexity (AC:L)**: Exploitation is straightforward and reliable. The attacker only needs to craft a JWT token with the "none" algorithm and a valid payload structure, requiring minimal technical knowledge.

- **No Privileges Required (PR:N)**: An attacker doesn't need any prior authentication or privileges to exploit this vulnerability. The issue exists in the authentication mechanism itself.

- **No User Interaction Required (UI:N)**: Exploitation can be performed directly without requiring any actions from legitimate users or administrators.

- **Unchanged Scope (S:U)**: The vulnerability impacts only the resources managed by the vulnerable API service, without directly affecting other components.

- **High Confidentiality Impact (C:H)**: Successful exploitation allows unauthorized access to all data protected by the JWT authentication mechanism, potentially exposing sensitive user information, business data, and system details.

- **High Integrity Impact (I:H)**: Attackers can forge tokens to impersonate any user, potentially including administrators, allowing them to modify data they shouldn't have access to and perform unauthorized operations.

- **No Availability Impact (A:N)**: The vulnerability doesn't directly impact the availability of the service.

The critical rating reflects how this vulnerability completely compromises the authentication system, which is a foundational security control. The ability to bypass authentication with minimal effort and no prerequisites makes this a severe security risk.

# Exploitation Scenarios
**Scenario 1: Administrator Impersonation**
An attacker creates a JWT token with the following components:
- Header: `{"alg": "none"}`
- Payload: `{"user": "admin", "role": "administrator"}`
- Signature: Empty (not required with "none" algorithm)

The full token would be: `eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW5pc3RyYXRvciJ9.` 

When the attacker sends a request to the API with this token in the Authorization header, the vulnerable JWT verification accepts it as valid. The system grants the attacker administrative privileges, allowing access to all administrative functions and sensitive data.

**Scenario 2: User Impersonation for Data Theft**
An attacker targets a specific user's data by crafting a token with:
- Header: `{"alg": "none"}`
- Payload: `{"user": "target_user", "sub": "user123"}`

The attacker sends API requests with this token to access the victim's personal information, transaction history, or other sensitive data. Because the token is accepted as valid, the system believes the attacker is the legitimate user and provides full access to the victim's data.

**Scenario 3: Service-to-Service Authentication Bypass**
In a microservice architecture where services authenticate to each other using JWT, an attacker can forge a token claiming to be a trusted internal service:
- Header: `{"alg": "none"}`
- Payload: `{"service": "billing-system", "permissions": ["read", "write", "admin"]}`

With this token, the attacker can access internal APIs that would normally only be available to authorized services, potentially gaining access to sensitive internal operations and data.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive customer information potentially leading to identity theft
- Financial losses from unauthorized operations or transactions
- Regulatory violations including GDPR, CCPA, PCI-DSS, or industry-specific compliance requirements
- Reputational damage and loss of customer trust if a breach becomes public
- Potential legal liabilities from affected customers or partners
- Costs associated with incident response, forensic investigation, and remediation

**Technical Impact:**
- Complete authentication bypass for all API endpoints protected by JWT verification
- Unauthorized access to protected resources with the same privileges as legitimate users
- Ability to perform unauthorized operations including reading, creating, updating, or deleting data
- Impersonation of any user in the system, including administrators or privileged users
- Unauthorized access to sensitive business logic and workflows
- Bypassing of all access controls dependent on user identity
- Potential for undetected malicious activity as actions would appear to come from legitimate users
- Difficulty in forensic analysis as logs would show activities under impersonated identities

# Technical Details
The vulnerability exists in the JWT validation implementation which fails to verify the signing algorithm used in the token. The problematic code is:

```go
token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    // No explicit check for the signing method is performed here
    return []byte("secret"), nil
})

```

The issue stems from two critical security flaws:

1. **Missing Algorithm Verification**:
   The JWT validation callback function doesn't check which signing algorithm is specified in the token header. The `jwt-go` library allows a token to specify any algorithm, including `none`, which indicates no signature verification should be performed.

2. **Acceptance of 'none' Algorithm**:
   Without explicit validation, the library will accept tokens with `{"alg": "none"}` in the header, treating them as valid regardless of the signature (or lack thereof).

**Technical Exploitation:**

A JWT token consists of three parts separated by dots: header.payload.signature

For example, a legitimate token might look like:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.gVAQI0q9m0P0jTP3myKhBPWVQl0iFEwNV4bT-3A5TTQ

```

To exploit the vulnerability, an attacker can create a token with the "none" algorithm:
1. Create a header: `{"alg": "none", "typ": "JWT"}`
2. Base64url-encode it: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0`
3. Create a payload with desired claims: `{"user": "admin"}`
4. Base64url-encode it: `eyJ1c2VyIjoiYWRtaW4ifQ`
5. Combine with an empty signature: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.`

When this token is submitted to the vulnerable API, the `jwt-go` library will:
1. Parse the header and identify the algorithm as "none"
2. Skip signature verification since the algorithm is "none"
3. Accept the token as valid
4. Process the claims in the payload as legitimate

In the `jwt-go` library, this vulnerability is especially problematic because the library defaults to accepting the "none" algorithm unless explicitly told otherwise in the validation callback.

# Remediation Steps
## Explicitly Verify Signing Algorithm

**Priority**: P0

Modify the JWT parsing code to explicitly check the signing algorithm against the expected method:

```go
token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    // Verify the signing method is what we expect (e.g., HMAC SHA-256)
    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
    }
    
    // Return the secret key for validation
    return []byte("secret"), nil
})

```

This validation ensures that the token must use the expected signing algorithm (in this case, HMAC) and will reject tokens using the "none" algorithm or any other unexpected algorithm. 

Alternatively, for more explicit algorithm checking, you can verify the exact algorithm used:

```go
token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    // Ensure the specific algorithm is the one expected
    if token.Method != jwt.SigningMethodHS256 {
        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
    }
    
    return []byte("secret"), nil
})

```
## Upgrade to a Modern JWT Library with Secure Defaults

**Priority**: P1

The original `dgrijalva/jwt-go` library has been deprecated and has known security issues. Migrate to the actively maintained fork with security improvements:

```go
// Replace
import "github.com/dgrijalva/jwt-go"

// With
import "github.com/golang-jwt/jwt/v4"

```

With the newer library, implement proper JWT validation:

```go
import (
    "fmt"
    "github.com/golang-jwt/jwt/v4"
)

func validateToken(tokenString string) (*jwt.Token, error) {
    // Define the expected claims structure
    type CustomClaims struct {
        User string `json:"user"`
        Role string `json:"role"`
        jwt.RegisteredClaims // Includes standard claims like exp, iat, iss
    }
    
    // Parse the token with explicit claims and algorithm validation
    token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
        // Verify the signing algorithm
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        
        // For HMAC algorithms, the key is the secret
        return []byte("your-secure-secret-key"), nil
    })
    
    if err != nil {
        return nil, fmt.Errorf("token validation failed: %v", err)
    }
    
    return token, nil
}

```

This implementation provides additional security through:
1. Type-safe claims through `ParseWithClaims`
2. Explicit algorithm verification
3. Support for standard claims like expiration
4. Better error handling


# References
* CWE-327 | [Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
* CWE-345 | [Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
* CWE-347 | [Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
* A02:2021 | [Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
* A07:2021 | [Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
