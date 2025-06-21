# SQL Injection in AWS Lambda Go Function

# Vulnerability Case
During a comprehensive assessment of Acme Corp's AWS Lambda functions written in Go, we identified a potential SQL injection vulnerability in a function interfacing with an Amazon RDS instance. The function builds its SQL query by concatenating unsanitized input from the user-controlled (`$EVENT`) object instead of relying on parameterized queries or prepared statements (e.g., using `Prepare` or `PrepareContext`). Static code analysis followed by dynamic testing with fuzzed inputs confirmed that a malicious payload in the (`$EVENT`) parameter can manipulate the SQL query structure. This flaw could allow an attacker to perform unauthorized data retrieval or modification. The exploitation of this vulnerability poses significant risks to data confidentiality and integrity as well as potential disruption of business operations.

```go
package main

import (
        "context"
        "database/sql"
        "errors"
        "fmt"
)

// User represents a simplified user record from the database.
type User struct {
        Username string
        Email    string
}

// lambdaHandler is an AWS Lambda function handler vulnerable to SQL injection.
func lambdaHandler(ctx context.Context, event map[string]interface{}, db *sql.DB) ([]User, error) {
        // Extracting user-controlled input from the event object.
        userID, ok := event["userID"].(string)
        if !ok {
                return nil, errors.New("invalid user input")
        }

        // Vulnerable SQL query construction via direct string concatenation.
        query := "SELECT username, email FROM users WHERE id = '" + userID + "'"
        fmt.Println("Executing query:", query)

        rows, err := db.QueryContext(ctx, query)
        if err != nil {
                return nil, err
        }
        defer rows.Close()

        var users []User
        for rows.Next() {
                var user User
                if err := rows.Scan(&user.Username, &user.Email); err != nil {
                        return nil, err
                }
                users = append(users, user)
        }

        return users, nil
}

func main() {
        // Main function placeholder.
}
```

An attacker can exploit this vulnerability by supplying a malicious string—as part of the (`$EVENT`) payload—to alter the intended structure of the SQL query; for example, a value resembling `1'; DROP TABLE users;--` could be injected, potentially resulting in arbitrary SQL commands executing against the database. The use of Go on AWS Lambda in conjunction with an Amazon RDS backend magnifies the impact, as an attacker could retrieve or manipulate sensitive data, compromise database integrity, or even disrupt service availability. Such an exploit not only risks data leakage and loss of customer trust but can also lead to severe regulatory and financial consequences for the business.


context: go.aws-lambda.security.database-sqli.database-sqli Detected SQL statement that is tainted by `$EVENT` object. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. In order to prevent SQL injection, use parameterized queries or prepared statements instead. You can use prepared statements with the 'Prepare' and 'PrepareContext' calls.

# Vulnerability Breakdown
This vulnerability exists in Acme Corp's AWS Lambda function written in Go which interfaces with an Amazon RDS instance. The code directly concatenates user input from the event object into SQL queries without sanitization.

1. **Key vulnerability elements**:
   - Direct string concatenation of user input into SQL query
   - No use of parameterized queries or prepared statements
   - Lack of input validation for the `userID` parameter
   - AWS Lambda function with database access privileges
   - Potential for complete query manipulation

2. **Potential attack vectors**:
   - Injecting SQL commands via the `userID` parameter in Lambda event
   - Terminating the original query and appending malicious commands
   - Using UNION queries to extract data from other tables
   - Leveraging database-specific syntax for privilege escalation

3. **Severity assessment**:
   - High confidentiality impact due to potential unauthorized data access
   - High integrity impact from possible data manipulation
   - Low availability impact as service disruption is possible but not guaranteed
   - Network-accessible attack vector through AWS Lambda triggers
   - Low complexity exploitation requiring basic SQL injection knowledge

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): Low (L) 

# Description
A critical SQL injection vulnerability has been discovered in an Acme Corp AWS Lambda function written in Go. The function accepts user input from the event object and directly concatenates this input into a SQL query without proper sanitization or parameterization.

```go
// Vulnerable code snippet
userID, ok := event["userID"].(string)
if !ok {
        return nil, errors.New("invalid user input")
}

// Direct string concatenation creates SQL injection vulnerability
query := "SELECT username, email FROM users WHERE id = '" + userID + "'"
rows, err := db.QueryContext(ctx, query)

```

This vulnerability allows attackers to manipulate the SQL query structure by injecting malicious SQL commands through the `userID` parameter. For example, an attacker could submit `1' OR '1'='1` as the userID to bypass authentication restrictions, or use more sophisticated techniques to extract data, modify database contents, or potentially disrupt service.

Given that this Lambda function has access to an Amazon RDS instance, the potential impact includes unauthorized access to sensitive data, data manipulation, and possible service disruption. The combination of AWS Lambda's scalability and the direct database access magnifies the potential damage of exploitation.

# CVSS
**Score**: 9.4 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L \
**Severity**: Critical

This vulnerability receives a Critical severity rating (CVSS score 9.4) based on the following factors:

- **Attack Vector (Network)**: The vulnerability is exploitable remotely through AWS Lambda triggers, which can be invoked over networks without requiring direct server access.

- **Attack Complexity (Low)**: Exploitation requires minimal specialized knowledge or conditions; basic SQL injection techniques are sufficient to exploit the vulnerability.

- **Privileges Required (None)**: No authentication or special privileges are needed to execute the attack, as anyone who can trigger the Lambda function can exploit the vulnerability.

- **User Interaction (None)**: The vulnerability can be exploited without requiring any action from legitimate users.

- **Scope (Unchanged)**: While serious, the vulnerability only affects the database the Lambda function interacts with, not changing security scope boundaries.

- **Confidentiality (High)**: A successful exploit could result in complete disclosure of all data stored in the database, including potentially sensitive user information.

- **Integrity (High)**: Attackers could insert, modify, or delete data in the database, potentially affecting all database contents.

- **Availability (Low)**: The vulnerability could cause some disruption of access to the database or Lambda function, but is unlikely to result in a complete system outage.

The Critical rating is appropriate given that this vulnerability allows unauthenticated remote attackers to access and modify sensitive data with minimal effort, potentially leading to severe business impacts including data breaches and regulatory violations.

# Exploitation Scenarios
**Scenario 1: Data Exfiltration**
An attacker triggers the Lambda function with a specially crafted payload containing a UNION-based SQL injection:

```
"userID": "0' UNION SELECT username, password FROM users--"

```

This causes the Lambda to execute:

```sql
SELECT username, email FROM users WHERE id = '0' UNION SELECT username, password FROM users--'

```

The attack bypasses the original query's constraints and returns all usernames and password hashes from the users table, potentially compromising all user accounts in the system.

**Scenario 2: Data Manipulation**
An attacker injects a payload with multiple SQL statements:

```
"userID": "1'; UPDATE users SET is_admin = true WHERE username = 'attacker';--"
```

If the database driver supports multiple statements, this would execute:

```sql
SELECT username, email FROM users WHERE id = '1'; UPDATE users SET is_admin = true WHERE username = 'attacker';--'
```

The attack grants administrative privileges to the attacker's account, enabling further system compromise.

**Scenario 3: Database Structure Enumeration**
An attacker uses error-based techniques to map the database:

```
"userID": "' AND (SELECT 1 FROM information_schema.tables WHERE table_schema=database() LIMIT 1)='2"
```

This causes a type conversion error that reveals database information in error messages. By iterating through similar queries, the attacker builds a complete map of the database schema, tables, and columns to plan more targeted attacks.

# Impact Analysis
**Business Impact:**
- Potential exposure of sensitive customer data leading to privacy violations
- Regulatory non-compliance with data protection laws (GDPR, CCPA, HIPAA)
- Financial penalties from regulatory bodies for data breaches
- Remediation costs including security assessments, fixes, and potential database rebuilds
- Loss of customer trust and reputational damage
- Business disruption if critical data is modified or deleted
- Legal liability from affected customers or partners

**Technical Impact:**
- Unauthorized access to all database tables and records accessible by the Lambda function
- Data integrity compromise through unauthorized modifications
- Potential for vertical and horizontal privilege escalation within the application
- Database corruption risk from malicious SQL commands
- Sensitive information disclosure including potential credentials or configuration details
- Possible denial of service through resource-intensive queries
- Potential for secondary attacks using extracted information
- Compromise of AWS IAM credentials if stored in the accessed database

# Technical Details
The vulnerability is a classic SQL injection resulting from directly concatenating user input into SQL queries instead of using parameterized statements. In the Lambda function code:

```go
// Extracting user-controlled input from the event object.
userID, ok := event["userID"].(string)
if !ok {
        return nil, errors.New("invalid user input")
}

// Vulnerable SQL query construction via direct string concatenation.
query := "SELECT username, email FROM users WHERE id = '" + userID + "'"
fmt.Println("Executing query:", query)

rows, err := db.QueryContext(ctx, query)

```

The issue occurs because:

1. The `userID` parameter is extracted from the event object as a string without validation
2. This string is directly concatenated into the SQL query
3. No escaping or sanitization is performed before query execution
4. Parameterized queries are not used despite Go's `database/sql` package supporting them

**Exploitation Mechanics:**

The vulnerability allows an attacker to break out of the intended SQL string context by providing specially crafted input. For example:

1. Normal execution with `userID = "123"` produces:
   ```sql
   SELECT username, email FROM users WHERE id = '123'

   ```

2. Malicious input with `userID = "1' OR '1'='1"` produces:
   ```sql
   SELECT username, email FROM users WHERE id = '1' OR '1'='1'

   ```
   This would return all users rather than just the one with id=1.

3. Data extraction with `userID = "1' UNION SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'public';--"` produces:
   ```sql
   SELECT username, email FROM users WHERE id = '1' UNION SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'public';--'
   
   ```
   This returns database metadata, revealing the schema structure.

The Go runtime environment exacerbates this vulnerability because:

1. The standard `database/sql` package executes the raw query as provided
2. Go's error handling may expose detailed database errors to the attacker
3. AWS Lambda's stateless nature means each invocation could be used for different injection techniques
4. The RDS database connection likely has broad permissions for the application to function

# Remediation Steps
## Implement Parameterized Queries

**Priority**: P0

Replace the string concatenation with parameterized queries using Go's `database/sql` package placeholders:

```go
// Extracting user-controlled input from the event object.
userID, ok := event["userID"].(string)
if !ok {
        return nil, errors.New("invalid user input")
}

// Use parameterized query with placeholders
query := "SELECT username, email FROM users WHERE id = ?"
fmt.Println("Executing parameterized query")

// The database driver will safely handle the parameter
rows, err := db.QueryContext(ctx, query, userID)
if err != nil {
        return nil, err
}
defer rows.Close()

```

This approach ensures that the database treats the `userID` value as data rather than executable SQL code, effectively preventing SQL injection attacks. The database driver automatically handles proper escaping and type handling for the parameter.
## Implement Input Validation

**Priority**: P1

Add strict input validation to ensure the `userID` parameter conforms to expected patterns:

```go
// Extracting user-controlled input from the event object.
userID, ok := event["userID"].(string)
if !ok {
        return nil, errors.New("invalid user input")
}

// Validate userID format (assuming it should be numeric)
if matched, err := regexp.MatchString("^[0-9]+$", userID); err != nil || !matched {
        return nil, errors.New("invalid userID format: must be numeric")
}

// Use parameterized query with placeholders
query := "SELECT username, email FROM users WHERE id = ?"
rows, err := db.QueryContext(ctx, query, userID)

```

This provides defense-in-depth by rejecting potentially malicious inputs before they reach the database query. Customize the validation pattern according to your specific userID format requirements (UUID, numeric, etc.).
## Implement Prepared Statements

**Priority**: P2

Use prepared statements for better security and performance, especially if the query is executed multiple times:

```go
// Prepare the statement once
stmt, err := db.PrepareContext(ctx, "SELECT username, email FROM users WHERE id = ?")
if err != nil {
        return nil, fmt.Errorf("failed to prepare statement: %w", err)
}
defer stmt.Close()

// Execute with the parameter
rows, err := stmt.QueryContext(ctx, userID)
if err != nil {
        return nil, err
}
defer rows.Close()

```

Prepared statements offer the same SQL injection protection as parameterized queries, with the added benefit of query plan caching if the same query is executed multiple times with different parameters. For Lambda functions that handle multiple events in the same instance, this can provide performance improvements.


# References
* CWE-89 | [Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A04:2021 | [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
* A05:2021 | [Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
