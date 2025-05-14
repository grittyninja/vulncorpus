# RSA Key Generation with Insufficient Bit Length

# Vulnerability Case
During a review of Acme Corp's Go-based microservices, I discovered that RSA keys were being generated using a 1024-bit modulus via the native `crypto/rsa` package, falling below the recommended minimum of 2048 bits. This vulnerability was identified during source code analysis of a secure API endpoint handling sensitive transactions in an AWS-hosted Docker/Kubernetes environment. The weak key parameter was inadvertently used due to legacy configuration defaults within the cryptographic initialization routine, which did not enforce proper key length validation. An attacker with access to substantial computational resources could feasibly factor these weak RSA keys, compromising digital signature integrity and enabling decryption of confidential communications.

```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

func main() {
	// Vulnerable RSA key generation: only 1024 bits used, below the 2048-bit recommendation.
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		fmt.Println("Error generating RSA key:", err)
		return
	}
	fmt.Printf("Generated RSA key with %d bits (vulnerable)\n", privateKey.N.BitLen())
}
```

Exploitation of this vulnerability involves an adversary leveraging factorization techniques on the weak 1024-bit modulus, potentially reconstructing the private key. With the private key compromised, an attacker could forge digital signatures, impersonate legitimate services, or decrypt intercepted encrypted traffic. This not only undermines the confidentiality and integrity of Acme Corp’s secure communications but may also result in unauthorized access to sensitive data, severely impacting the organization's trust and compliance posture.


context: go.lang.security.audit.crypto.use_of_weak_rsa_key.use-of-weak-rsa-key RSA keys should be at least 2048 bits

# Vulnerability Breakdown
This vulnerability involves the generation of RSA keys with insufficient key length (1024 bits) in a Go microservice, potentially compromising the cryptographic security of the application.

1. **Key vulnerability elements**:
   - RSA keys generated with 1024-bit modulus, below the recommended minimum of 2048 bits
   - Implementation in Go-based microservices using the native `crypto/rsa` package
   - Affects secure API endpoints handling sensitive transactions
   - Deployed in AWS-hosted Docker/Kubernetes environment
   - Legacy configuration defaults being used without validation

2. **Potential attack vectors**:
   - Factorization attacks against the weak 1024-bit modulus
   - Reconstruction of private keys from factored moduli
   - Decryption of intercepted encrypted communications
   - Forgery of digital signatures for service impersonation

3. **Severity assessment**:
   - High impact on confidentiality (potential decryption of sensitive data)
   - High impact on integrity (potential signature forgery)
   - Requires substantial computational resources to exploit
   - No direct availability impact
   - Network accessible vulnerability
   - Low privileges required to trigger transactions that use the vulnerable keys

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): High (H) 
   - Privileges Required (PR): Low (L) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): None (N) 

CVSS Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N

# Description
A cryptographic vulnerability has been identified in Acme Corp's Go-based microservices where RSA keys are being generated with insufficient bit length (1024 bits), falling below the industry-recommended minimum of 2048 bits. The vulnerable code uses the Go `crypto/rsa` package with a legacy configuration that doesn't enforce adequate key length validation.

```go
privateKey, err := rsa.GenerateKey(rand.Reader, 1024) // Vulnerable: using only 1024 bits

```

This weakness significantly reduces the cryptographic strength of the encryption. While 1024-bit RSA keys were once considered adequate, advances in computational power and factoring algorithms have rendered them vulnerable. Organizations including NIST and BSI have recommended a minimum of 2048 bits for RSA keys for several years.

The vulnerability affects secure API endpoints handling sensitive transactions in an AWS-hosted Docker/Kubernetes environment, potentially exposing confidential communications and enabling signature forgery.

# CVSS
**Score**: 6.8 \
**Vector**: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N \
**Severity**: Medium

The Medium severity (6.8) rating is justified by the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely, as the attacker only needs to obtain the public key and attempt to factor it. This is possible for any network-exposed service using these keys.

- **High Attack Complexity (AC:H)**: Successfully exploiting this vulnerability requires substantial computational resources to factor a 1024-bit RSA key. While feasible with sufficient resources, this is not trivial and represents a significant barrier to exploitation.

- **Low Privileges Required (PR:L)**: An attacker needs basic privileges to trigger transactions that use the vulnerable keys. This could involve authenticated API access or similar permissions to initiate operations that leverage the cryptographic functionality.

- **No User Interaction (UI:N)**: The vulnerability can be exploited without any user interaction, as it's purely a cryptographic weakness.

- **Unchanged Scope (S:U)**: The impact is limited to the vulnerable component itself, not affecting other services beyond what the key protects.

- **High Confidentiality Impact (C:H)**: If exploited, an attacker could decrypt sensitive information encrypted with the compromised key, potentially exposing financial transactions, authentication data, or other confidential information.

- **High Integrity Impact (I:H)**: With a compromised private key, an attacker could forge signatures, creating fraudulent transactions or communications that appear legitimate.

- **No Availability Impact (A:N)**: This cryptographic weakness doesn't directly impact system availability.

# Exploitation Scenarios
**Scenario 1: Passive Surveillance and Decryption**
A well-resourced adversary (such as a nation-state) intercepts and stores encrypted API communications from Acme Corp's microservices over an extended period. They allocate significant computing resources to factor the 1024-bit RSA key. Once successful, they can retrospectively decrypt all previously captured communications, potentially exposing sensitive transaction data, authentication credentials, and personally identifiable information.

**Scenario 2: Digital Signature Forgery**
After factoring the weak RSA key, an attacker crafts fraudulent requests with perfectly valid digital signatures. These forged signatures allow the attacker to impersonate legitimate users or services, authorizing transactions or accessing protected resources. Due to the mathematical validity of these signatures, detection becomes extremely difficult as they pass all cryptographic verification checks.

**Scenario 3: Man-in-the-Middle with Perfect Forward Secrecy Bypass**
An attacker positions themselves to intercept TLS handshakes between clients and Acme's services. By factoring the weak RSA key used for authentication, they can decrypt the session keys exchanged during these handshakes, even if Perfect Forward Secrecy is implemented. This allows them to decrypt the entire subsequent communication session, potentially compromising authentication tokens or session cookies that enable further attacks.

**Scenario 4: Cloud Key Management Service Compromise**
If the weak RSA keys are stored in a cloud key management service (AWS KMS, etc.), an attacker who successfully factors the key could potentially extract sensitive materials protected by these keys through the legitimate API. This could include database credentials, API tokens, or other secrets used throughout the microservice architecture.

# Impact Analysis
**Business Impact:**
- Potential violation of data protection regulations (GDPR, CCPA, etc.) if encrypted personal data is compromised
- Breach of contractual obligations with customers regarding data security
- Loss of customer trust and reputational damage if a breach occurs
- Legal liability from fraudulent transactions if signatures are forged
- Costs associated with incident response, forensic investigation, and remediation
- Potential regulatory fines for inadequate security measures
- Business disruption during emergency key rotation and recertification

**Technical Impact:**
- Complete compromise of confidentiality for data encrypted with the affected keys
- Loss of integrity guarantees for digitally signed content
- Invalidation of non-repudiation properties for transactions
- Potential for undetected backdoor access to systems if authentication relies on the compromised keys
- Requirement for comprehensive key rotation and recertification
- Need to re-encrypt any archived data that was protected with the weak keys
- Possible invalidation of security compliance certifications
- Technical debt from emergency fixes and rushed implementation changes

# Technical Details
The vulnerability stems from the use of insufficiently strong RSA keys in Acme Corp's Go-based microservices. The specific issue is the use of 1024-bit RSA keys instead of the recommended minimum of 2048 bits.

The vulnerable code generates RSA keys as follows:

```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

func main() {
	// Vulnerable RSA key generation: only 1024 bits used, below the 2048-bit recommendation.
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		fmt.Println("Error generating RSA key:", err)
		return
	}
	fmt.Printf("Generated RSA key with %d bits (vulnerable)\n", privateKey.N.BitLen())
}

```

**Technical Background:**

RSA security relies on the computational difficulty of factoring large numbers. The modulus (N) in an RSA key is the product of two large prime numbers (p and q). The private key components are derived from these primes. If an attacker can factor N into p and q, they can regenerate the entire private key.

As computational power increases and factoring algorithms improve, the bit length required for security increases. 1024-bit RSA keys were once considered secure but are now vulnerable to factorization by well-resourced attackers.

**Factorization Feasibility:**

In 2015, researchers estimated that factoring a 1024-bit RSA key would cost approximately $1 million using specialized hardware. With ongoing advances in computing power, this cost continues to decrease. For comparison:

- 512-bit RSA keys can be factored in hours on consumer hardware
- 768-bit RSA keys were factored publicly in 2009
- 1024-bit RSA keys are estimated to be within reach of well-resourced attackers
- 2048-bit RSA keys are currently considered secure against factorization attempts

**Technical Risk Factors:**

1. **Key Reuse**: If the same weak key is used across multiple services, the impact of compromise increases substantially

2. **Long-term Security**: Data encrypted today might need to remain secure for years. As factorization becomes easier, 1024-bit keys provide increasingly inadequate protection

3. **Legacy Compatibility**: The use of 1024-bit keys often stems from compatibility with legacy systems, creating a technical debt that increases security risk

4. **Distributed Factorization**: Modern computing clusters and cloud computing make distributed factorization increasingly feasible for sophisticated attackers

# Remediation Steps
## Increase RSA Key Size to Minimum 2048 Bits

**Priority**: P0

Immediately modify all RSA key generation code to use a minimum of 2048 bits:

```go
// Secure implementation using 2048 bits (minimum recommendation)
privateKey, err := rsa.GenerateKey(rand.Reader, 2048)

// OR for long-term security (recommended)
privateKey, err := rsa.GenerateKey(rand.Reader, 4096)

```

To prevent future occurrences, create a utility function that enforces minimum key size requirements:

```go
func generateSecureRSAKey(bits int) (*rsa.PrivateKey, error) {
    // Define minimum acceptable key size
    const MinRSAKeySize = 2048
    
    // Validate key size
    if bits < MinRSAKeySize {
        return nil, fmt.Errorf("insecure RSA key size: %d bits; minimum required: %d bits", 
                               bits, MinRSAKeySize)
    }
    
    // Generate key with validated size
    privateKey, err := rsa.GenerateKey(rand.Reader, bits)
    if err != nil {
        return nil, fmt.Errorf("failed to generate RSA key: %w", err)
    }
    
    return privateKey, nil
}

```

This function can be used throughout the codebase to ensure all RSA key generation follows security best practices.
## Implement Key Rotation and Management Policy

**Priority**: P1

Develop and implement a comprehensive key rotation strategy:

1. **Identify and Rotate Existing Keys**:

```go
func rotateWeakRSAKeys(oldKeyID string) (string, error) {
    // Generate new key with secure parameters
    newKey, err := generateSecureRSAKey(2048)
    if err != nil {
        return "", err
    }
    
    // Store new key in secure storage (e.g., AWS KMS, HashiCorp Vault)
    newKeyID, err := keyStore.StoreKey(newKey)
    if err != nil {
        return "", fmt.Errorf("failed to store new key: %w", err)
    }
    
    // Update key references and mark old key for deprecation
    err = keyStore.DeprecateKey(oldKeyID, newKeyID)
    if err != nil {
        return "", fmt.Errorf("failed to deprecate old key: %w", err)
    }
    
    return newKeyID, nil
}

```

2. **Establish Automated Key Management**:

```go
type KeyPolicy struct {
    KeyType      string
    MinBitLength int
    MaxAgeInDays int
}

var securityPolicies = map[string]KeyPolicy{
    "RSA": {
        KeyType:      "RSA",
        MinBitLength: 2048,  // Minimum recommendation
        MaxAgeInDays: 365,   // Annual rotation
    },
}

func enforceKeyPolicy() {
    keys, _ := keyStore.ListAllKeys()
    
    for _, key := range keys {
        policy, exists := securityPolicies[key.Type]
        if !exists {
            log.Warn("No policy defined for key type", key.Type)
            continue
        }
        
        // Check for violations
        if key.BitLength < policy.MinBitLength {
            log.Critical("Key %s has insufficient bit length (%d < %d)", 
                         key.ID, key.BitLength, policy.MinBitLength)
            // Trigger rotation process
        }
        
        // Check age
        keyAge := time.Since(key.CreatedAt)
        if keyAge > time.Duration(policy.MaxAgeInDays)*24*time.Hour {
            log.Warn("Key %s exceeds maximum age policy", key.ID)
            // Schedule rotation
        }
    }
}

```

3. **Document and enforce a cryptographic policy** that specifies minimum key lengths, approved algorithms, and rotation schedules across the organization.


# References
* CWE-326 | [Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
* CWE-310 | [Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html)
* A02:2021 | [Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
* SP 800-57 | [Recommendation for Key Management](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
* SP 800-131A | [Transitioning the Use of Cryptographic Algorithms and Key Lengths](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf)
