# Hardcoded Database Credentials in Application Configuration

# Vulnerability Case
During a routine audit of Acme Corp’s code repositories and CI/CD pipeline, our automated secrets scanning tool flagged a generic high-entropy string pattern within a legacy configuration file of a Node.js application. The detected generic secret was found in a configuration file that managed database access credentials, indicating potential exposure of sensitive internal authentication data. This vulnerability was discovered after correlating scan alerts with repository commit histories during a scheduled vulnerability assessment. The presence of such hardcoded secrets in source code increases the risk of unauthorized access if the repository content is exposed or inadvertently shared. The finding underscores weaknesses in secret management practices within the development lifecycle.

```javascript
// config.js - Acme Corp Node.js Application Configuration
module.exports = {
  // Hardcoded credential mistakenly left in the legacy config
  dbPassword: "GENERIC_SECRET_EXPOSED", // Generic Secret detected
  apiEndpoint: "https://api.acmecorp.internal",
  port: 3000,
};
```

Attackers can leverage automated scanning tools to identify repositories containing hardcoded secrets like `GENERIC_SECRET_EXPOSED` and may attempt to use these credentials to gain unauthorized access to internal databases or other critical services hosted on Acme Corp’s infrastructure. Exploitation may involve lateral movement in network environments, data exfiltration, and privilege escalation, especially if other services are configured to trust the authenticated requests from the compromised secret. The business impact could be significant, resulting in data breaches, service disruption, financial losses, and damage to corporate reputation, in addition to potential regulatory and compliance repercussions.


context: generic.secrets.security.detected-generic-secret.detected-generic-secret Generic Secret detected

# Vulnerability Breakdown
This vulnerability involves hardcoded database credentials detected in a Node.js application configuration file, exposing sensitive authentication data.

1. **Key vulnerability elements**:
   - Database password directly embedded in source code (`"GENERIC_SECRET_EXPOSED"`) 
   - Stored in a version-controlled repository accessible to multiple developers
   - Part of a legacy configuration file that manages database access
   - No apparent protection or obfuscation of the secret
   - Node.js application configuration that might be deployed to multiple environments

2. **Potential attack vectors**:
   - Repository exposure (public repositories, breaches, or inadvertent sharing)
   - Access to deployment environments where configuration is readable
   - Insider threats with legitimate code access
   - Code deployed to non-production environments with lower security
   - Lateral movement if credentials provide access to production databases

3. **Severity assessment**:
   - High confidentiality impact due to potential unauthorized database access
   - High integrity impact from possible data modification capabilities
   - Some availability impact if database access could be abused
   - Local attack vector as it requires access to code or deployed application
   - Scope is changed as vulnerability in application affects database systems

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Local (L) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): Low (L) 
   - User Interaction (UI): None (N) 
   - Scope (S): Changed (C)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): Low (L) 

# Description
A critical security vulnerability has been identified in Acme Corp's Node.js application where database credentials are hardcoded directly in a legacy configuration file. During a routine audit, automated secrets scanning detected a high-entropy string pattern in a source code repository, specifically a plaintext database password stored in `config.js`.

```javascript
// config.js - Acme Corp Node.js Application Configuration
module.exports = {
  // Hardcoded credential mistakenly left in the legacy config
  dbPassword: "GENERIC_SECRET_EXPOSED", // Generic Secret detected
  apiEndpoint: "https://api.acmecorp.internal",
  port: 3000,
};

```

This insecure practice of embedding credentials directly in source code significantly increases the attack surface by:

1. Exposing sensitive authentication data to anyone with repository access
2. Creating persistence of credentials across multiple environments
3. Making credential rotation difficult as it requires code changes
4. Potentially exposing secrets if code is shared or the repository is compromised
5. Violating the principle of secure credential management

The exposed database password could grant unauthorized access to Acme Corp's database infrastructure, potentially leading to data breaches, unauthorized data access, or service disruption.

# CVSS
**Score**: 8.8 \
**Vector**: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L \
**Severity**: High

The High severity rating (8.8) reflects several critical factors:

- **Local Attack Vector (AV:L)**: The vulnerability requires access to either the source code repository or a deployed instance of the application, limiting the potential attack surface compared to a network-accessible vulnerability.

- **Low Attack Complexity (AC:L)**: Once the credential is obtained, exploiting it requires minimal technical effort - simply using the password to connect to the database.

- **Low Privileges Required (PR:L)**: Exploiting this vulnerability requires some level of initial access to the codebase or deployed application, such as repository access or file system access to a running instance.

- **No User Interaction (UI:N)**: No action from users is required to exploit the vulnerability once the credential is obtained.

- **Changed Scope (S:C)**: The vulnerability crosses security boundaries - a compromise in the application code allows access to a separate system (the database).

- **High Confidentiality Impact (C:H)**: An attacker could potentially access all data stored in the database, including sensitive business or customer information.

- **High Integrity Impact (I:H)**: With database access, an attacker could modify or delete data, potentially affecting business operations and data integrity.

- **Low Availability Impact (A:L)**: While the database itself would likely remain operational, targeted modifications or queries could potentially impact performance or specific functionality.

The severity is particularly high because database credentials typically provide broad access to sensitive data and could lead to significant data breaches if exploited.

# Exploitation Scenarios
**Scenario 1: Repository Compromise**
An attacker gains unauthorized access to Acme Corp's code repository (through a compromised developer account, misconfigured access controls, or a breach of the version control system). Using automated scanning tools similar to those used in the audit, they identify the hardcoded credential in config.js. With the database password in hand, they connect directly to the database server from an external location, bypassing application-level controls and exfiltrating sensitive data.

**Scenario 2: Deployment Environment Access**
A contractor with temporary access to a staging or testing environment examines the deployed Node.js application files. They discover the config.js file with the hardcoded database password. Even after their legitimate access is revoked, they retain knowledge of the credential, which remains unchanged in the configuration. Months later, they use this credential to access the production database, as the same password is used across environments.

**Scenario 3: Insider Threat Exploitation**
A disgruntled employee with repository access copies the database credentials before leaving the company. Since the credentials are hardcoded in the application rather than managed through a proper secrets management system, they aren't automatically rotated when the employee departs. The former employee later uses these credentials to access the company's database, stealing proprietary data or introducing malicious modifications.

**Scenario 4: Accidental Public Exposure**
A developer seeking help with a technical issue inadvertently shares a code snippet containing the config.js file on a public forum. Although they quickly delete the post, the exposed credential is indexed by search engines and archived by various services. Automated bots scanning for exposed credentials identify the database password, which is then exploited to access Acme Corp's database infrastructure.

# Impact Analysis
**Business Impact:**
- Potential unauthorized access to sensitive customer or business data stored in databases
- Risk of regulatory violations and associated penalties (GDPR, CCPA, etc.) if personal data is exposed
- Financial losses from incident response, forensic investigation, and mandatory breach notifications
- Reputational damage and loss of customer trust if a breach occurs and becomes public
- Costs associated with emergency credential rotation across all environments
- Potential business disruption during remediation activities
- Possible intellectual property theft if proprietary data is accessed

**Technical Impact:**
- Complete compromise of database integrity and confidentiality
- Potential for data theft, modification, or deletion without detection
- Risk of backdoor creation within database systems
- Challenges in determining historical unauthorized access (limited audit trail for credential use)
- Risk of lateral movement if the compromised database contains credentials for other systems
- Difficulty in revoking access without breaking application functionality
- Single point of failure created by shared credentials across environments
- Deployment complications if emergency code changes are needed to rotate credentials

# Technical Details
The vulnerability exists in a Node.js application that uses a JavaScript configuration file to store application settings, including a database password. The problematic implementation is in `config.js`:

```javascript
// config.js - Acme Corp Node.js Application Configuration
module.exports = {
  // Hardcoded credential mistakenly left in the legacy config
  dbPassword: "GENERIC_SECRET_EXPOSED", // Generic Secret detected
  apiEndpoint: "https://api.acmecorp.internal",
  port: 3000,
};

```

**Technical Security Issues:**

1. **Plaintext Storage**: The credential is stored in plaintext rather than encrypted or obtained from a secure store.

2. **Source Control Exposure**: Being part of the application code, this file is likely tracked in version control, creating multiple copies and access points.

3. **Static Configuration**: Hardcoded credentials can't be easily rotated without code changes and redeployment.

4. **Environment Inconsistency**: The same credential may be used across development, testing, and production environments.

5. **Access Control Limitations**: Anyone with read access to the codebase or deployed application files has access to the credential.

**How Applications Typically Use This Configuration:**

In a Node.js application, this configuration file would typically be imported at runtime:

```javascript
const config = require('./config');
const mysql = require('mysql');

// Database connection using the hardcoded credential
const connection = mysql.createConnection({
  host: 'database.acmecorp.internal',
  user: 'dbuser',
  password: config.dbPassword, // Using the exposed password
  database: 'acme_app'
});

connection.connect(function(err) {
  if (err) throw err;
  console.log("Connected to database!");
});

```

This pattern means the credential is loaded into memory whenever the application runs, potentially being logged, included in error reports, or visible in process inspection. It also means that the credential is a static value that doesn't change between deployments unless the code is updated.

# Remediation Steps
## Immediate Credential Rotation

**Priority**: P0

Immediately rotate the exposed database password to invalidate the compromised credential:

1. Generate a new strong password for the database user
2. Update the database user's password in the database system
3. Update all application instances to use the new password (as a temporary measure, using the method described in P1)
4. Monitor for any failed login attempts using the old credential, which might indicate unauthorized access attempts
5. Perform a thorough security review to determine if there was any unauthorized access using the exposed credential

This action should be taken immediately to minimize the window of exposure, even before implementing a proper secrets management solution.
## Implement Environment-Based Configuration

**Priority**: P1

Replace hardcoded credentials with environment variables or a proper secrets management solution:

```javascript
// config.js - Secure version using environment variables
module.exports = {
  // Database password loaded from environment variable
  dbPassword: process.env.DB_PASSWORD,
  apiEndpoint: process.env.API_ENDPOINT || "https://api.acmecorp.internal",
  port: parseInt(process.env.PORT || "3000"),
};

```

For deployment, set environment variables securely:

1. Development: Use `.env` files with `.gitignore` to prevent committing secrets
2. CI/CD: Use the pipeline's secure variables feature
3. Production: Use a secure secret management solution like:
   - AWS Secrets Manager or Parameter Store
   - Azure Key Vault
   - HashiCorp Vault
   - Google Secret Manager

Example using a secrets management service (AWS):

```javascript
// config.js - Using AWS Secrets Manager
const AWS = require('aws-sdk');
const secretsManager = new AWS.SecretsManager();

async function getDbPassword() {
  const data = await secretsManager.getSecretValue({ SecretId: 'acme-app/db-password' }).promise();
  return JSON.parse(data.SecretString).password;
}

module.exports = {
  getConfig: async () => {
    return {
      dbPassword: await getDbPassword(),
      apiEndpoint: process.env.API_ENDPOINT || "https://api.acmecorp.internal",
      port: parseInt(process.env.PORT || "3000"),
    };
  }
};

```

This ensures credentials are never stored in the codebase and can be rotated without code changes.
## Implement Secret Scanning in CI/CD

**Priority**: P2

Integrate automated secret scanning into the CI/CD pipeline to prevent similar issues in the future:

1. Implement pre-commit hooks using tools like `git-secrets` or `detect-secrets` to prevent committing secrets:

```bash
# Example pre-commit hook installation
npm install --save-dev husky
npm install --save-dev detect-secrets

```

Add to package.json:
```json
{
  "husky": {
    "hooks": {
      "pre-commit": "detect-secrets-hook --baseline .secrets.baseline"
    }
  }
}

```

2. Add secret scanning to CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
name: Secret Scanning
on: [push, pull_request]

jobs:
  detect-secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Detect secrets
        uses: reviewdog/action-detect-secrets@v0.5
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          reporter: github-pr-review

```

3. Regularly scan repositories for historical secrets using tools like TruffleHog or GitLeaks

4. Consider implementing server-side rejection of commits containing potential secrets

These automated controls create multiple layers of protection against secret exposure in code repositories.
## Develop Secure Coding Guidelines

**Priority**: P3

Create and enforce secure coding guidelines for credential management:

1. Document clear standards for handling sensitive credentials:
   - Never hardcode credentials in source code
   - Always use environment variables or secret management services
   - Document proper patterns for credential rotation
   - Establish secure practices for local development

2. Create templated code examples that demonstrate proper credential handling:

```javascript
// Example template for database connections
const { getSecret } = require('./secrets-manager');

async function createDatabaseConnection() {
  // Get credentials from secure storage at runtime
  const dbConfig = await getSecret('database/credentials');
  
  return mysql.createConnection({
    host: dbConfig.host,
    user: dbConfig.username,
    password: dbConfig.password,
    database: dbConfig.database
  });
}

```

3. Implement regular developer training on secure credential management

4. Create an incident response plan specifically for credential exposure

5. Establish a secure process for developers to access and use credentials during development

These guidelines should be integrated into the development team's standard practices, code reviews, and onboarding process to prevent future instances of hardcoded credentials.


# References
* CWE-798 | [Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
* CWE-259 | [Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)
* A07:2021 | [Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
* A04:2021 | [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
* 800-53r5 | [Security and Privacy Controls for Information Systems and Organizations](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
