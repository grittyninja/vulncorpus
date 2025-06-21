# Hard-coded API Key in Production Node.js Application

# Vulnerability Case
During our assessment of Acme Corp's web application backend—built on Node.js with an Express framework and MongoDB—we discovered that a generic API key was hard-coded into the production configuration. The API key, originally intended as a fallback during integration testing, was inadvertently deployed in the live environment and exposed via public version control history. This vulnerability was identified using automated secrets scanning complemented by manual code review, which flagged the predictable key pattern. An attacker obtaining this key could bypass authentication mechanisms to access internal API endpoints, leading to unauthorized data retrieval and potential manipulation. The business impact includes significant risk of exposing sensitive customer data, financial losses, and reputational damage stemming from such unauthorized access.

```javascript
// app.js - Node.js backend using Express
const express = require("express");
const app = express();

// Hard-coded generic API key intended for integration tests
const GENERIC_API_KEY = "GENERIC_API_KEY_12345";

app.get("/api/sensitive-data", (req, res) => {
  const providedKey = req.headers["x-api-key"];
  if (providedKey && providedKey === GENERIC_API_KEY) {
    res.json({ sensitive: "data" });
  } else {
    res.status(403).json({ error: "Unauthorized" });
  }
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
```

The vulnerability arises from embedding a static, generic API key directly in the source code, making it susceptible to discovery through public repositories or automated scanning tools. An adversary who acquires this key can craft requests to internal API endpoints (as illustrated in the snippet) by including the key in the HTTP header (e.g., using the `x-api-key` field), thereby bypassing standard authentication. Exploitation may involve using scripting or API testing tools (such as Postman or curl) to automate bulk requests and enumerate accessible resources. The resulting unauthorized access can lead to sensitive data exfiltration, data manipulation, and potentially facilitate more extensive lateral movement within the network, posing a severe threat to business operations and customer trust.


context: generic.secrets.security.detected-generic-api-key.detected-generic-api-key Generic API Key detected

# Vulnerability Breakdown
This vulnerability involves embedding a static, generic API key directly in the application's source code that was later exposed through public version control history.

1. **Key vulnerability elements**:
   - Hard-coded string constant `GENERIC_API_KEY_12345` in source code
   - API key intended for testing deployed to production environment
   - Exposed via public version control history
   - Used for authentication to sensitive API endpoints
   - Discoverable through automated secrets scanning tools

2. **Potential attack vectors**:
   - Mining public repositories for secrets and credentials
   - Retrieving historical commits to find removed but still exposed secrets
   - Using automated tools like GitRob, TruffleHog, or Gitleaks to scan code repositories
   - Leveraging GitHub Search to directly find terms like "API_KEY" or "SECRET"
   - Using the exposed API key to bypass authentication
   - Crafting unauthorized requests to access sensitive data

3. **Severity assessment**:
   - High confidentiality impact due to potential sensitive data exposure
   - Low integrity impact as some data manipulation may be possible
   - Network-based attack vector allowing remote exploitation
   - Low complexity as the attacker only needs to use the key in requests
   - No privileges or user interaction required

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): Low (L) 
   - Availability (A): None (N) 

# Description
A critical security vulnerability was discovered in Acme Corp's Node.js backend application where a generic API key (`GENERIC_API_KEY_12345`) is hard-coded directly into the production source code. This API key, originally intended for integration testing, was inadvertently deployed to the production environment and subsequently exposed through public version control history.

The application uses this hard-coded key to authenticate requests to sensitive API endpoints such as `/api/sensitive-data`. Any request that includes this key in the `x-api-key` header is granted access to protected resources, bypassing proper authentication mechanisms.

```javascript
// Vulnerable code snippet from app.js
const GENERIC_API_KEY = "GENERIC_API_KEY_12345";
app.get("/api/sensitive-data", (req, res) => {
  const providedKey = req.headers["x-api-key"];
  if (providedKey && providedKey === GENERIC_API_KEY) {
    res.json({ sensitive: "data" });
  } else {
    res.status(403).json({ error: "Unauthorized" });
  }
});

```

This vulnerability represents a significant security risk as attackers who discover this key through code repository analysis or automated secrets scanning can craft requests to access restricted API endpoints, potentially leading to unauthorized data access and exfiltration. Even if the API key has been removed in current versions of the code, it remains accessible through version control history unless the repository has been completely purged.

# CVSS
**Score**: 8.1 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N \
**Severity**: High

The High severity rating (8.1) is based on several critical factors:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely over the internet, as the API key allows access to exposed API endpoints without requiring local network access.

- **Low Attack Complexity (AC:L)**: Exploitation is straightforward and requires minimal effort - once the attacker obtains the API key from version control history, they only need to include it in HTTP request headers.

- **No Privileges Required (PR:N)**: The vulnerability can be exploited without any authentication or authorization, as possessing the API key itself bypasses these mechanisms.

- **No User Interaction (UI:N)**: Exploitation doesn't require any action from legitimate users of the system.

- **Unchanged Scope (S:U)**: The impact is confined to the vulnerable API and its accessible resources, without escalating privileges to other components.

- **High Confidentiality Impact (C:H)**: An attacker can access sensitive data through API endpoints, potentially exposing customer information and other confidential data.

- **Low Integrity Impact (I:L)**: While the primary risk is unauthorized data access, there's potential for limited data manipulation depending on the API's functionality.

- **No Availability Impact (A:N)**: The vulnerability doesn't directly impact system availability or cause denial of service.

The combination of easy exploitation, no required privileges, and high confidentiality impact makes this a serious vulnerability warranting immediate remediation.

# Exploitation Scenarios
**Scenario 1: Repository Mining for API Key Extraction**
An attacker systematically hunts for sensitive credentials across public GitHub repositories using specialized tools like GitRob, TruffleHog, or Gitleaks. These tools are specifically designed to detect patterns that match API keys, passwords, and other secrets. The attacker targets Acme Corp's repositories and runs these scanners, which flag the `GENERIC_API_KEY_12345` value in historical commits. Even though developers may have removed this key in later commits, the attacker uses `git log -p` to view the entire commit history, revealing when the key was added and subsequently removed. With the extracted API key, the attacker crafts HTTP requests with the header `x-api-key: GENERIC_API_KEY_12345` to access the sensitive endpoint `/api/sensitive-data`, successfully bypassing authentication.

**Scenario 2: Direct GitHub Search Exploitation**
A more targeted approach involves an attacker using GitHub's code search functionality to look for specific patterns like "API_KEY", "SECRET", or specific key formats. The search turns up Acme Corp's repository where `GENERIC_API_KEY_12345` appears in previous commits. Even if the repository is now private, if it was ever public, search engine caches or sites like GitHub Archive may have indexed the code. The attacker extracts the key and tests it against Acme Corp's API endpoints, confirming it still works in production.

**Scenario 3: Systematic API Enumeration**
After discovering the API key through version control history, an attacker creates a script that systematically tests all possible API endpoints (using common naming conventions) with the same API key. Since the same key is used across multiple endpoints, the attacker maps out all accessible resources and extracts sensitive data in bulk. This allows them to discover endpoints not explicitly documented or referenced in the code they initially found.

**Scenario 4: Persistent Access**
The attacker discovers that the API key has remained unchanged for months due to it being hard-coded in the application. They establish a persistent connection to periodically extract new data using the compromised API key, maintaining access even as other security measures are implemented. Because the key is generic and used by legitimate systems, it becomes difficult to distinguish malicious traffic from normal operations.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive customer data potentially resulting in privacy violations
- Regulatory compliance failures (GDPR, CCPA, etc.) leading to significant financial penalties
- Legal liability from customer data exposure and potential class-action lawsuits
- Reputational damage when security incidents are disclosed, eroding customer trust
- Costs associated with incident response, forensic investigation, and remediation
- Possible business disruption during emergency security patching

**Technical Impact:**
- Compromise of API security boundaries, allowing unauthorized data access
- Potential for data exfiltration from internal databases through exposed API endpoints
- Invalidation of security controls that rely on API key authentication
- Need to revoke and rotate all API keys across the organization
- Security posture degradation as attackers gain insights into internal systems
- Possible exposure of other internal endpoints or services if the same key is reused
- Opportunity for attackers to map internal API structure and dependencies
- Challenges in distinguishing legitimate from malicious API usage during investigation

# Technical Details
The vulnerability stems from embedding a static API key directly in the application's source code, which was subsequently exposed through version control history. The affected code is in a Node.js application using the Express framework.

```javascript
// Vulnerable implementation in app.js
const express = require("express");
const app = express();

// Hard-coded generic API key intended for integration tests
const GENERIC_API_KEY = "GENERIC_API_KEY_12345";

app.get("/api/sensitive-data", (req, res) => {
  const providedKey = req.headers["x-api-key"];
  if (providedKey && providedKey === GENERIC_API_KEY) {
    res.json({ sensitive: "data" });
  } else {
    res.status(403).json({ error: "Unauthorized" });
  }
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});

```

**API Key Exposure Methods:**

1. **Git History Extraction**: Even if the API key is removed in current code, version control systems like Git preserve the entire history by default. Attackers can use commands like `git log -p` to view all changes, revealing when the key was added:
   ```bash
   git log -p --all -S "GENERIC_API_KEY"
   
   ```

2. **Automated Secret Detection Tools**: Attackers routinely use specialized tools to find secrets in repositories:
   - **GitRob**: Scans organizations for sensitive files
   - **TruffleHog**: Uses entropy analysis to find high-entropy strings likely to be secrets
   - **Gitleaks**: Pattern matches against known credential formats
   
3. **GitHub Search**: Simple queries like `"API_KEY"` in GitHub search can reveal hard-coded credentials:
   ```
   "const API_KEY" filename:*.js
   ```

**Technical issues:**

1. **Hard-coded Credentials**: The API key is directly embedded in the source code as a constant, making it visible to anyone with code access.

2. **Insufficient Secrets Management**: The application lacks proper secrets management, using a string literal instead of environment variables or a dedicated secrets service.

3. **Test Credential in Production**: A credential intended for testing was deployed to production, violating the principle of environment separation.

4. **Weak Authentication Mechanism**: The API relies solely on a single shared key for authentication without additional security layers.

5. **Exposure Vector**: The credential was exposed through version control history, which is difficult to completely remove once committed.

**Exploitation Method:**

To exploit this vulnerability, an attacker would:

1. Discover the API key through repository scanning or code analysis using the methods described above
2. Craft an HTTP request to the API endpoint with the appropriate header:

```
GET /api/sensitive-data HTTP/1.1
Host: api.acmecorp.com
x-api-key: GENERIC_API_KEY_12345

```

3. Receive sensitive data in the response:

```
HTTP/1.1 200 OK
Content-Type: application/json

{"sensitive": "data"}

```

The vulnerability persists as long as the hard-coded key remains valid and unchanged in the production environment, even if it has been removed from the current version of the code.

# Remediation Steps
## Remove Hard-coded API Key and Implement Environment-based Secrets

**Priority**: P0

Immediately remove the hard-coded API key from the source code and replace it with environment variables or a dedicated secrets management solution:

```javascript
// Revised implementation using environment variables
const express = require("express");
const app = express();

// API key loaded from environment variable
const API_KEY = process.env.API_KEY;

// Verify the API key is set
if (!API_KEY) {
  console.error("ERROR: API_KEY environment variable must be set");
  process.exit(1);
}

app.get("/api/sensitive-data", (req, res) => {
  const providedKey = req.headers["x-api-key"];
  if (providedKey && providedKey === API_KEY) {
    res.json({ sensitive: "data" });
  } else {
    res.status(403).json({ error: "Unauthorized" });
  }
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});

```

Implementation steps:
1. Set up environment variables in all environments (development, staging, production)
2. Generate unique, strong API keys for each environment
3. Update deployment pipelines to inject the appropriate environment variables
4. Verify the application exits safely if the key is not provided
5. Implement secure logging that doesn't expose the key
6. Rotate all existing API keys, assuming the current keys are compromised
7. Consider using Git history rewriting tools like BFG Repo Cleaner to purge sensitive data from repository history
## Implement Robust API Authentication and Authorization

**Priority**: P1

Replace the simple API key authentication with a more robust authentication and authorization framework:

```javascript
const express = require("express");
const jwt = require("jsonwebtoken");
const app = express();

// Secret key for JWT verification from environment variable
const JWT_SECRET = process.env.JWT_SECRET;

// Authentication middleware
const authenticate = (req, res, next) => {
  try {
    // Extract token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Authentication required" });
    }
    
    const token = authHeader.split(" ")[1];
    
    // Verify JWT token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Add user information to request object
    req.user = decoded;
    
    // Check if token is in revocation list (optional)
    // checkTokenRevocation(token);
    
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid authentication token" });
  }
};

// Protected route using the authentication middleware
app.get("/api/sensitive-data", authenticate, (req, res) => {
  // Additional authorization check if needed
  if (!req.user.permissions.includes("read:sensitive-data")) {
    return res.status(403).json({ error: "Insufficient permissions" });
  }
  
  res.json({ sensitive: "data" });
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});

```

This implementation:
1. Uses JWT-based authentication instead of a static API key
2. Includes permissions in the token for fine-grained authorization
3. Separates authentication and authorization concerns
4. Provides a foundation for more advanced features like token revocation


# References
* CWE-798 | [Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
* CWE-312 | [Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
* A02:2021 | [Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
* A04:2021 | [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
* A07:2021 | [Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
