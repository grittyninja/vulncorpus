# SQL Injection in C++ Authentication Service

# Vulnerability Case
During our assessment of Acme Corp's legacy C++ authentication service interfacing with a MySQL backend, we identified that untrusted user input was directly concatenated into SQL queries without sanitization. The vulnerability was discovered during dynamic testing and log analysis when anomalous database queries were observed containing injected SQL control characters. This coding pattern, which bypasses parameterized query best practices, enables an attacker to manipulate the query structure and execute arbitrary SQL commands.

```cpp
#include <iostream>
#include <mysql/mysql.h>
#include <string>

void lookupUser(MYSQL* conn, const std::string& userInput) {
  // Vulnerable pattern: direct concatenation of untrusted user input
  std::string query = "SELECT * FROM users WHERE username = '" + userInput + "'";
  if (mysql_query(conn, query.c_str())) {
    std::cerr << "Query failed: " << mysql_error(conn) << std::endl;
    return;
  }
  MYSQL_RES* result = mysql_store_result(conn);
  // Process results...
}
```

The technical implications of this SQL injection vulnerability are significant: an attacker can craft inputs such as `' OR '1'='1` to manipulate the SQL query logic and bypass authentication or exfiltrate sensitive data. Exploitation methods may also allow modification or deletion of critical records, potentially leading to unauthorized system access and severe business disruptions, including data breaches and regulatory non-compliance. The vulnerability is particularly severe as the MySQL connection is configured to allow multiple statements, enabling attacks like `'; DROP TABLE users;--`. Real-world stacks like C++ with the MySQL C API underscore the risk when established libraries are misused by not employing prepared statements or ORM frameworks.

context: cpp.lang.security.sql.sql-injection.sql-injection Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data or modify/delete data. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions.

# Vulnerability Breakdown
This vulnerability involves direct string concatenation of untrusted user input into SQL queries within a C++ authentication service using the MySQL C API.

1. **Key vulnerability elements**:
   - User input is directly concatenated into SQL queries without sanitization
   - No use of parameterized queries or prepared statements
   - Implementation in C++ using MySQL C API, which offers prepared statement functionality that wasn't utilized
   - Located in authentication service, which is a particularly sensitive system component
   - Direct string concatenation pattern using the `+` operator in C++

2. **Potential attack vectors**:
   - Authentication bypass using crafted inputs like `' OR '1'='1`
   - Data exfiltration through UNION queries (e.g., `' UNION SELECT password,username FROM users--`)
   - Database schema enumeration via error messages
   - Potential for destructive operations using DELETE or DROP statements
   - Possible stored procedures execution if appropriate permissions exist

3. **Severity assessment**:
   - Critical impact on confidentiality (entire database potentially readable)
   - Critical impact on integrity (data may be altered or deleted)
   - High impact on availability (potential database corruption)
   - Low attack complexity (well-documented attack patterns)
   - No user interaction needed for exploitation
   - Network attack vector as this is likely an authentication API

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Changed (C)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): High (H) 

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

# Description
A critical SQL injection vulnerability exists in Acme Corp's legacy C++ authentication service that interfaces with a MySQL backend database. The vulnerability occurs when untrusted user input is directly concatenated into SQL query strings without proper sanitization or parameterization.

```cpp
#include <iostream>
#include <mysql/mysql.h>
#include <string>

void lookupUser(MYSQL* conn, const std::string& userInput) {
  // Vulnerable pattern: direct concatenation of untrusted user input
  std::string query = "SELECT * FROM users WHERE username = '" + userInput + "'";
  if (mysql_query(conn, query.c_str())) {
    std::cerr << "Query failed: " << mysql_error(conn) << std::endl;
    return;
  }
  MYSQL_RES* result = mysql_store_result(conn);
  // Process results...
}

```

This vulnerability allows attackers to inject malicious SQL commands by crafting input containing SQL control characters and commands. For example, an attacker could bypass authentication with input like `' OR '1'='1` or exfiltrate sensitive data using UNION-based attacks. The issue is particularly severe as it affects an authentication service, potentially compromising the security of the entire system.

# CVSS
**Score**: 10.0 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H \
**Severity**: Critical

This SQL injection vulnerability receives a Critical severity rating (CVSS score 10.0) due to several factors:

- **Network Attack Vector (AV:N)**: The vulnerability is in an authentication service which is likely accessible remotely over a network.

- **Low Attack Complexity (AC:L)**: Exploiting SQL injection is straightforward using well-documented techniques and requires no special conditions or timing.

- **No Privileges Required (PR:N)**: An attacker doesn't need any prior access or privileges to exploit this vulnerability, as it exists in the authentication mechanism itself.

- **No User Interaction (UI:N)**: Exploitation can be fully automated and requires no action from legitimate users.

- **Changed Scope (S:C)**: A successful attack on the authentication service can affect other system components that rely on authentication decisions.

- **High Confidentiality Impact (C:H)**: Attackers can access sensitive data stored in the database, potentially including credentials, personal information, or business-critical data.

- **High Integrity Impact (I:H)**: Attackers can modify database contents, potentially altering user permissions, creating unauthorized accounts, or tampering with application data.

- **High Availability Impact (A:H)**: Through destructive SQL commands, attackers could delete data or otherwise disrupt the availability of the system.

The combination of these factors results in the maximum possible CVSS score, reflecting the serious nature of SQL injection vulnerabilities, especially in authentication contexts.

# Exploitation Scenarios
**Scenario 1: Authentication Bypass**
An attacker attempts to log in to the application but instead of entering a valid username, they input: `' OR '1'='1' --`. The application constructs the following query:

```sql
SELECT * FROM users WHERE username = '' OR '1'='1' --'

```

Everything after the `--` is treated as a comment, effectively changing the query to select all users where either the username is empty OR 1=1 (which is always true). This returns the first user in the database (often an administrator), allowing the attacker to bypass authentication entirely.

**Scenario 2: Data Exfiltration**
An attacker uses a UNION-based injection to extract sensitive information from other tables in the database. They might input:

```
' UNION SELECT username, password FROM users--

```

This transforms the query to:

```sql
SELECT * FROM users WHERE username = '' UNION SELECT username, password FROM users--'

```

The application would then return username and password hash combinations from the users table, allowing the attacker to attempt offline password cracking.

**Scenario 3: Database Manipulation**
An attacker could execute destructive operations using inputs like:

```
'; DROP TABLE users;--

```

This would construct:

```sql
SELECT * FROM users WHERE username = ''; DROP TABLE users;--'

```

If the MySQL server is configured to allow multiple statements (through multi-query), this would delete the entire users table, causing significant disruption to the application's functionality.

**Scenario 4: Blind SQL Injection**
Even without seeing direct query results, attackers can extract data using boolean-based inference. For example:

```
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--

```

By observing differences in application behavior based on whether the condition is true or false, attackers can gradually extract sensitive data character by character.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive systems and data through authentication bypass
- Potential full data breach if attackers can exfiltrate entire database contents
- Possible data theft including personally identifiable information (PII) or intellectual property
- Regulatory compliance violations (GDPR, CCPA, etc.) with associated financial penalties
- Mandatory breach notifications to affected users and regulatory authorities
- Loss of customer trust and reputational damage
- Business disruption if attackers damage database integrity
- Legal liability from affected parties
- Costs associated with forensic investigation, remediation, and monitoring

**Technical Impact:**
- Complete compromise of database confidentiality
- Authentication system bypass leading to unauthorized system access
- Data integrity violations through unauthorized modification of database records
- Potential creation of unauthorized administrator accounts for persistent access
- Database schema exposure revealing application structure
- Possible lateral movement to other connected systems
- Service disruption through database corruption or deletion
- Potential for complete application compromise
- Manipulation of transaction records or audit logs to hide malicious activity

# Technical Details
The vulnerability stems from a fundamental secure coding failure: directly concatenating user-controlled input into SQL queries without any form of sanitization or parameterization. In the vulnerable code:

```cpp
void lookupUser(MYSQL* conn, const std::string& userInput) {
  std::string query = "SELECT * FROM users WHERE username = '" + userInput + "'";
  if (mysql_query(conn, query.c_str())) {
    std::cerr << "Query failed: " << mysql_error(conn) << std::endl;
    return;
  }
  MYSQL_RES* result = mysql_store_result(conn);
  // Process results...
}

```

The technical issues with this implementation include:

1. **String Concatenation**: The code directly inserts the `userInput` parameter into the SQL query string using the C++ `+` operator, without any validation or escaping.

2. **No SQL Character Escaping**: Special characters like single quotes (`'`), which are used to delimit strings in SQL, are not escaped. This allows an attacker to break out of the string context and inject arbitrary SQL commands.

3. **No Input Validation**: The code doesn't validate that the input contains only expected characters or patterns for a username.

4. **Use of Raw Query Execution**: The vulnerable code uses `mysql_query()` to execute raw SQL strings instead of using prepared statements.

5. **No Error Handling Security**: While there is error logging, error messages might be exposed to users, potentially revealing database structure information that aids attackers.

**Exploitation Mechanics:**

SQL injection attacks work by manipulating the structure of the query rather than just the data within it. For example, with input `' OR '1'='1`, the query becomes:

```sql
SELECT * FROM users WHERE username = '' OR '1'='1'

```

This transforms the query's logic to select all records where either the username is an empty string OR where 1=1 (which is always true), effectively returning all users from the database.

More sophisticated attacks can use:

- UNION statements to combine the original query with attacker-specified queries
- Subqueries to extract data from other tables
- Multiple statements to execute additional SQL commands
- Time-based techniques to extract data when results aren't directly visible

The MySQL C API provides several alternatives to prevent this vulnerability:

1. Prepared statements via `mysql_stmt_prepare()` and related functions
2. Parameter binding via `mysql_stmt_bind_param()`
3. Character escaping via `mysql_real_escape_string()`

However, none of these protective measures are used in the vulnerable code.

# Remediation Steps
## Use Prepared Statements

**Priority**: P0

Replace direct string concatenation with prepared statements using the MySQL C API:

```cpp
void lookupUser(MYSQL* conn, const std::string& userInput) {
  // Prepare statement
  MYSQL_STMT* stmt = mysql_stmt_init(conn);
  if (!stmt) {
    std::cerr << "Failed to initialize statement: " << mysql_error(conn) << std::endl;
    return;
  }
  
  // Define parameterized query with placeholder
  const char* query = "SELECT * FROM users WHERE username = ?";
  
  // Prepare the statement
  if (mysql_stmt_prepare(stmt, query, strlen(query))) {
    std::cerr << "Failed to prepare statement: " << mysql_stmt_error(stmt) << std::endl;
    mysql_stmt_close(stmt);
    return;
  }
  
  // Bind parameters
  MYSQL_BIND bind[1];
  memset(bind, 0, sizeof(bind));
  
  // Set up parameter binding
  bind[0].buffer_type = MYSQL_TYPE_STRING;
  bind[0].buffer = (void*)userInput.c_str();
  bind[0].buffer_length = userInput.length();
  
  // Bind parameters to statement
  if (mysql_stmt_bind_param(stmt, bind)) {
    std::cerr << "Failed to bind parameters: " << mysql_stmt_error(stmt) << std::endl;
    mysql_stmt_close(stmt);
    return;
  }
  
  // Execute statement
  if (mysql_stmt_execute(stmt)) {
    std::cerr << "Failed to execute statement: " << mysql_stmt_error(stmt) << std::endl;
    mysql_stmt_close(stmt);
    return;
  }
  
  // Process results (would need to bind result columns too)
  // ...
  
  // Clean up
  mysql_stmt_close(stmt);
}

```

This approach ensures that user input is treated strictly as data and cannot alter the structure of the SQL query. The MySQL API handles proper escaping and type handling automatically when using prepared statements with parameter binding.
## Implement Input Validation

**Priority**: P1

In addition to using prepared statements, add input validation to ensure that only expected characters are accepted:

```cpp
#include <iostream>
#include <mysql/mysql.h>
#include <string>
#include <regex>

bool isValidUsername(const std::string& username) {
  // Define regex for valid username format (alphanumeric plus some special chars)
  static const std::regex usernamePattern("^[a-zA-Z0-9_.-]{1,64}$");
  return std::regex_match(username, usernamePattern);
}

void lookupUser(MYSQL* conn, const std::string& userInput) {
  // Validate input before processing
  if (!isValidUsername(userInput)) {
    std::cerr << "Invalid username format" << std::endl;
    return;
  }
  
  // Proceed with prepared statement as in the P0 solution
  // ...
}

```

This multi-layered approach provides defense-in-depth, with input validation as a secondary control to supplement prepared statements. The regex pattern should be adjusted based on your specific username requirements and policies.


# References
* CWE-89 | [Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A04:2021 | [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
* CWE-707 | [Improper Neutralization](https://cwe.mitre.org/data/definitions/707.html)
