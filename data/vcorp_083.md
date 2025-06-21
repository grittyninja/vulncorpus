# SQL Injection via String Formatting in Authentication Module

# Vulnerability Case
During Acme Corp's security assessment of their Java web application built on Spring Boot with a MySQL backend, we discovered that a SQL statement was constructed using `String.format` to interpolate user input directly into the query. This vulnerability was identified during manual code reviews and further validated by static analysis tools, which highlighted the use of formatted strings instead of parameterized queries. The affected module, responsible for user authentication, concatenates unsanitized input into the SQL command, making it susceptible to SQL injection. In a production environment, such design oversights can be exploited by remote attackers to manipulate database queries, leading to unauthorized data access. The user mysql have no write permission on file or databases, and strictly on database belongs to this system, scope unchanged.

```java
// Vulnerable code snippet demonstrating unsafe SQL string formatting in a Java web application
String userInput = request.getParameter("username");
String sql = String.format("SELECT * FROM users WHERE username = '%s'", userInput);
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(sql);
```

In this vulnerability, the application leverages a formatted SQL string, which directly incorporates user input without proper sanitization. An attacker could inject malicious SQL by supplying crafted input—such as `' OR '1'='1`—to manipulate the query structure, potentially bypassing authentication and retrieving sensitive records. Exploitation of this flaw in a production environment could result in unauthorized data disclosure, especially given the sensitive nature of data typically managed by enterprise systems running on the Java/Spring Boot stack.


context: java.lang.security.audit.formatted-sql-string.formatted-sql-string Detected a formatted string in a SQL statement. This could lead to SQL injection if variables in the SQL statement are not properly sanitized. Use a prepared statements (java.sql.PreparedStatement) instead. You can obtain a PreparedStatement using 'connection.prepareStatement'.

# Vulnerability Breakdown
This vulnerability involves direct user input interpolation into SQL queries using String.format() in a Java Spring Boot application's authentication module.

1. **Key vulnerability elements**:
   - Direct interpolation of user input via String.format() in SQL queries
   - Absence of parameterized queries or prepared statements
   - Implementation in an authentication module, a critical security boundary
   - Java Spring Boot application with MySQL backend
   - No sanitization of user-supplied input before query construction

2. **Potential attack vectors**:
   - Supplying specially crafted input like `' OR '1'='1` to bypass authentication
   - Using SQL metacharacters (quotes, comments, etc.) to alter query logic
   - Leveraging UNION queries to extract data from other tables
   - Using boolean-based blind techniques if direct output isn't visible
   - Potentially accessing sensitive user data through inference attacks

3. **Severity assessment**:
   - High confidentiality impact as it enables unauthorized data access
   - No integrity impact as MySQL user has read-only permissions
   - No availability impact as database operations remain functional
   - Network attack vector (remotely exploitable web application)
   - Low complexity to exploit using widely available techniques

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): None (N) 
   - Availability (A): None (N) 

# Description
A SQL injection vulnerability has been identified in Acme Corp's Java web application built on Spring Boot with a MySQL backend. The vulnerability exists in the user authentication module where user-supplied input is directly interpolated into SQL queries using Java's `String.format()` method without any validation or sanitization.

```java
String userInput = request.getParameter("username");
String sql = String.format("SELECT * FROM users WHERE username = '%s'", userInput);
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(sql);

```

This implementation allows attackers to inject malicious SQL code by submitting specially crafted input that can alter the query's structure and logic. For example, an attacker could supply `' OR '1'='1` as the username, which would transform the query into `SELECT * FROM users WHERE username = '' OR '1'='1'`, effectively bypassing authentication by making the WHERE clause always evaluate to true.

While the MySQL user has read-only permissions (unable to write to files or modify databases outside its scope), this vulnerability still presents a significant security risk as it could allow unauthorized access to sensitive user information stored in the database.

# CVSS
**Score**: 7.5 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N \
**Severity**: High

The High severity rating (CVSS score 7.5) is justified by the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability exists in a web application accessible over the network, allowing remote exploitation.

- **Low Attack Complexity (AC:L)**: Exploiting this vulnerability requires minimal specialized knowledge. Standard SQL injection techniques and widely available tools can be used.

- **No Privileges Required (PR:N)**: The vulnerability exists in the authentication module, meaning an attacker doesn't need any prior privileges or authentication to exploit it.

- **No User Interaction (UI:N)**: The vulnerability can be exploited without requiring any action from a legitimate user.

- **Unchanged Scope (S:U)**: The impacted component is the same as the vulnerable component, as the exploit affects only the targeted application's database.

- **High Confidentiality Impact (C:H)**: The vulnerability potentially allows access to all data that the application can retrieve from the database, including sensitive user information. Since this affects the authentication module, it could allow complete bypass of access controls.

- **No Integrity Impact (I:N)**: The MySQL user has read-only permissions, preventing data modification or insertion.

- **No Availability Impact (A:N)**: The vulnerability doesn't affect the availability of the system.

The combination of remote accessibility, easy exploitation, and high confidentiality impact makes this a serious vulnerability despite the mitigating factor of read-only database permissions.

# Exploitation Scenarios
**Scenario 1: Authentication Bypass**
An attacker attempts to log in to the application by entering `' OR '1'='1` in the username field and any text in the password field. When the application constructs the SQL query using String.format(), it creates the statement: `SELECT * FROM users WHERE username = '' OR '1'='1'`. Since the condition `'1'='1'` always evaluates to true, the query returns all user records from the database rather than just the intended user. If the application then uses the first returned record to authenticate the user, the attacker gains access to the system, potentially with administrative privileges if the first user in the database is an administrator.

**Scenario 2: Data Extraction via UNION Attacks**
An attacker enters `' UNION SELECT username, password, email, NULL, NULL FROM users WHERE '1'='1` as the username (adjusting the number of NULL values to match the columns in the original query). This injection creates a UNION query that appends all usernames, password hashes, and email addresses from the users table to the result set. The application then processes and potentially displays this information, giving the attacker access to all user credentials stored in the database.

**Scenario 3: Information Schema Mining**
An attacker uses a series of boolean-based blind SQL injection techniques by entering payloads like `' AND (SELECT COUNT(*) FROM information_schema.tables) > 10 AND '1'='1`. By systematically modifying these queries and observing the application's responses, the attacker can enumerate database tables, columns, and eventually extract sensitive data, even if the application doesn't directly display query results. This allows for comprehensive mapping of the database structure and subsequent targeted data extraction.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive user information including credentials, personal details, and potentially financial data
- Breach of confidentiality for all data accessible to the application's database user
- Potential violation of data protection regulations (GDPR, CCPA, etc.) leading to legal and financial penalties
- Reputation damage and loss of customer trust if a breach is disclosed publicly
- Authentication bypass potentially enabling future attacks and unauthorized use of system features
- Costs associated with incident response, forensic investigation, and remediation efforts
- Possible need to notify affected users about potential data exposure

**Technical Impact:**
- Complete exposure of all user data stored in the database tables accessible to the application
- Authentication system compromise allowing unauthorized access to protected functionality
- Potential for horizontal privilege escalation (accessing other users' accounts)
- Exposure of database schema and application logic through error messages
- Disclosure of password hashes that could be cracked offline to reveal plaintext passwords
- Risk of credential reuse attacks if users employ the same passwords across multiple services
- Information disclosure that could facilitate other attacks against the system or its users

# Technical Details
The vulnerability occurs in the authentication module of a Java Spring Boot application connecting to a MySQL database. The root issue is the direct interpolation of user input into SQL queries using `String.format()` instead of using parameterized queries.

```java
String userInput = request.getParameter("username");
String sql = String.format("SELECT * FROM users WHERE username = '%s'", userInput);
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(sql);

```

**Vulnerability Mechanics:**

1. The application retrieves user input from an HTTP request parameter (`username`)
2. This input is directly inserted into a SQL query template using `String.format()`
3. The formatted SQL string is executed using `createStatement()` and `executeQuery()`
4. No input validation, sanitization, or parameterization occurs before execution

**SQL Injection Attack Process:**

When an attacker supplies a specially crafted input like `' OR '1'='1`, the resulting SQL query becomes:

```sql
SELECT * FROM users WHERE username = '' OR '1'='1'

```

This altered query will return all records from the users table because the condition `'1'='1'` always evaluates to true.

**Technical Constraints and Limitations:**

1. **Read-Only Access**: The MySQL user has read-only permissions, which prevents attackers from:
   - Using `INSERT`, `UPDATE`, or `DELETE` statements to modify data
   - Executing commands that write to the filesystem
   - Creating or modifying stored procedures, functions, or triggers

2. **MySQL Multiple Statement Limitation**: By default, JDBC does not allow multiple SQL statements in a single query (separated by semicolons), which prevents certain attack techniques like:
   - Adding destructive queries after the initial query
   - Creating temporary procedures
   - Executing administrative commands

Despite these limitations, the vulnerability remains serious because it allows unauthorized access to all data readable by the application's database user, which likely includes sensitive user information given that this is an authentication module.

# Remediation Steps
## Replace String Concatenation with Prepared Statements

**Priority**: P0

Immediately replace the vulnerable string formatting approach with parameterized queries using PreparedStatement:

```java
// Secure implementation using PreparedStatement
String userInput = request.getParameter("username");
String sql = "SELECT * FROM users WHERE username = ?";
PreparedStatement pstmt = connection.prepareStatement(sql);
pstmt.setString(1, userInput);
ResultSet rs = pstmt.executeQuery();

```

With PreparedStatement, the parameter values are transmitted separately from the SQL statement, ensuring that the database treats them strictly as data rather than potentially executable code. This completely prevents SQL injection attacks regardless of what characters are included in the input.

This approach has several advantages:
1. It guarantees security against SQL injection without relying on input validation
2. It's typically more efficient as the database can cache the query execution plan
3. It provides appropriate type handling (strings are properly escaped, numbers are formatted correctly)
4. It aligns with security best practices recommended by OWASP and other security standards
## Implement Input Validation as Defense in Depth

**Priority**: P1

While prepared statements are sufficient to prevent SQL injection, add input validation as an additional layer of defense:

```java
// Input validation combined with prepared statements
String userInput = request.getParameter("username");

// Input validation (complementary to prepared statements)
if (!userInput.matches("^[a-zA-Z0-9_]{3,30}$")) {
    throw new IllegalArgumentException("Invalid username format");
}

// Prepared statement (primary defense)
String sql = "SELECT * FROM users WHERE username = ?";
PreparedStatement pstmt = connection.prepareStatement(sql);
pstmt.setString(1, userInput);
ResultSet rs = pstmt.executeQuery();

```

Input validation serves as a defense-in-depth measure by:
1. Rejecting obviously malicious inputs before they reach the database
2. Enforcing business rules about valid data formats
3. Preventing potential edge cases or zero-day vulnerabilities in the database driver
4. Providing more specific error messages for legitimate errors

Note that input validation alone is not sufficient protection against SQL injection and should always be used in conjunction with prepared statements.


# References
* CWE-89 | [Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A04:2021 | [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
* CWE-564 | [SQL Injection: Hibernate](https://cwe.mitre.org/data/definitions/564.html)
