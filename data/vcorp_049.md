# SQL Injection in gRPC Microservice via String Interpolation

# Vulnerability Case
During a comprehensive review of Acme Corp's gRPC microservice handling SQL operations, our team identified a critical SQL injection vulnerability stemming from the unsafe use of string formatting in Go. The service directly interpolates untrusted input from gRPC requests into a raw SQL query without proper sanitization. During our code review and dynamic testing, we observed that an attacker could craft malicious input to alter the intended SQL command, leading to unauthorized data retrieval or modification. This issue was confirmed on a technology stack that leverages Go, gRPC, and a vanilla SQL database driver. The discovery highlights the risks associated with unsanitized input in dynamic query construction in production environments. Postgresql user only have read access to specific database, also not granted write permission

```go
package main

import (
        "context"
        "database/sql"
        "fmt"
        "log"

        pb "acme.com/microservice/proto" // gRPC generated code package
)

type Server struct {
        db *sql.DB
}

func (s *Server) GetUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
        // Vulnerability: Direct interpolation of user input into SQL query via fmt.Sprintf
        // This enables SQL injection if req.Username contains malicious payloads.
        query := fmt.Sprintf("SELECT id, username, email FROM users WHERE username = '%s'", req.Username)
        row := s.db.QueryRowContext(ctx, query)

        var id int
        var username, email string
        if err := row.Scan(&id, &username, &email); err != nil {
                return nil, err
        }

        return &pb.UserResponse{
                Id:       int32(id),
                Username: username,
                Email:    email,
        }, nil
}

func main() {
        // Sample database initialization (e.g., PostgreSQL) and server startup.
        db, err := sql.Open("postgres", "user=acme dbname=acme_app sslmode=disable")
        if err != nil {
                log.Fatal(err)
        }
        defer db.Close()

        // Assume server initialization with the gRPC framework, binding the GetUser method.
        _ = &Server{db: db}
        // gRPC server code continues...
}
```

The vulnerability occurs because user-supplied input (i.e., `req.Username`) is directly concatenated into the SQL command using `fmt.Sprintf`, bypassing any input sanitization. An attacker can exploit this by submitting a malicious string (e.g., `' OR '1'='1`) to manipulate the SQL query, potentially leading to unauthorized data disclosure, modification, or even execution of arbitrary database commands. Given the business-critical nature of the data managed by this gRPC service, successful exploitation could result in significant data breaches, operational disruptions, or regulatory non-compliance, posing severe financial and reputational risks.


context: go.grpc.sql.grpc-vanillasql-format-string-sqli-taint.grpc-vanillasql-format-string-sqli-taint Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions. When building SQL queries in Go, it is possible to adopt prepared statements by using the `Prepare` and `PrepareContext` calls with parameterized queries. For more information, see: [Prepared statements in Go](https://go.dev/doc/database/prepared-statements).

# Vulnerability Breakdown
This vulnerability involves a classic SQL injection pattern in a Go-based gRPC microservice where user input is directly concatenated into SQL queries without sanitization. However, the impact is constrained by the database user having read-only permissions.

1. **Key vulnerability elements**:
   - Direct interpolation of untrusted user input via `fmt.Sprintf()` into SQL queries
   - Lack of parameterized queries or prepared statements
   - Complete absence of input validation or sanitization
   - Implemented in a high-performance Go gRPC microservice with direct database access
   - **Limited impact**: PostgreSQL user only has read permissions to specific databases

2. **Potential attack vectors**:
   - Sending crafted malicious input like `' OR '1'='1` to bypass authentication
   - Using UNION attacks to extract data from unrelated tables
   - Executing information disclosure queries against system tables
   - Database enumeration and reconnaissance

3. **Severity assessment**:
   - High confidentiality impact (potential access to all readable database data)
   - No integrity impact (database user lacks write permissions)
   - No availability impact (database user cannot delete data or tables)
   - Network-accessible attack surface via gRPC
   - Low complexity to exploit with standard SQL injection techniques

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
A SQL injection vulnerability has been identified in Acme Corp's gRPC microservice. The vulnerability exists in the `GetUser` function where user-supplied input from gRPC requests (`req.Username`) is directly interpolated into a SQL query using `fmt.Sprintf()` without any sanitization or validation.

```go
query := fmt.Sprintf("SELECT id, username, email FROM users WHERE username = '%s'", req.Username)
row := s.db.QueryRowContext(ctx, query)

```

This implementation allows attackers to craft malicious inputs that can manipulate the intended SQL query structure. For example, an input of `' OR '1'='1` would transform the query to return all users in the database, bypassing the intended filtering.

Importantly, the PostgreSQL database user only has read access to specific databases and is not granted write permissions. This significantly limits the impact of the vulnerability to data disclosure scenarios, preventing attackers from modifying or deleting data despite the SQL injection vulnerability. However, even with read-only access, this still represents a serious security issue as it could lead to unauthorized access to sensitive data.

The vulnerability highlights a fundamental secure coding oversight: failing to use parameterized queries (prepared statements) when handling user input in database operations.

# CVSS
**Score**: 7.5 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N \
**Severity**: High

The High severity rating (7.5) is justified by the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability is in a gRPC microservice exposed over the network, making it remotely exploitable without requiring local access.

- **Low Attack Complexity (AC:L)**: SQL injection is well-documented and straightforward to exploit using widely available techniques and tools. The vulnerability requires no special conditions or timing to exploit.

- **No Privileges Required (PR:N)**: An attacker needs no authentication or authorization to exploit the vulnerability; they only need to send a malicious gRPC request with crafted input.

- **No User Interaction (UI:N)**: Exploitation is completely automated and requires no action from legitimate users or administrators.

- **Unchanged Scope (S:U)**: The vulnerability's impact is contained to the database resources that the vulnerable component has access to.

- **High Confidentiality Impact (C:H)**: An attacker can potentially access all readable data in the database, including sensitive user information, internal configurations, or business-critical data.

- **No Integrity Impact (I:N)**: The PostgreSQL user only has read access and no write permissions, preventing attackers from modifying any data in the database.

- **No Availability Impact (A:N)**: The read-only database access prevents attackers from executing destructive SQL commands that would cause service disruption or data loss.

While the read-only database access significantly reduces the potential damage compared to full read-write access (which would rate as Critical 9.8), the vulnerability still poses a serious risk due to the potential for unauthorized access to sensitive data, justifying the High severity rating.

# Exploitation Scenarios
**Scenario 1: Authentication Bypass and Data Enumeration**
An attacker sends a gRPC request to the `GetUser` method with the username parameter set to `' OR '1'='1` which transforms the query to:
```sql
SELECT id, username, email FROM users WHERE username = '' OR '1'='1'

```
This returns all users in the database instead of a specific user. The attacker can then systematically harvest user information including emails, which might be used for phishing attacks or account takeover attempts.

**Scenario 2: Lateral Data Access via UNION Attack**
The attacker uses a more sophisticated payload like:
```
' UNION SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema = 'public' AND '1'='1

```
This allows the attacker to discover the database schema, including tables and columns they weren't intended to access. With this information, they can craft further queries to access sensitive data from other tables.

**Scenario 3: Accessing Specific Sensitive Records**
Using information gleaned from schema discovery, an attacker constructs a targeted query:
```
' UNION SELECT customer_id, credit_score, annual_income FROM customer_financial_data WHERE annual_income > 1000000 AND '1'='1

```
This could expose high-value customer information that should be protected, despite the attacker only having access to the user lookup functionality.

**Scenario 4: Database Version and Configuration Disclosure**
An attacker could extract information about the database configuration:
```
' UNION SELECT version(), current_setting('config_file'), current_setting('data_directory') WHERE '1'='1

```
Revealing database version and configuration details helps attackers identify potential database-specific vulnerabilities, even if they cannot directly modify data due to read-only permissions.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive customer data could trigger data breach notification requirements and regulatory penalties (GDPR, CCPA, etc.)
- Exposure of proprietary business information or intellectual property to competitors
- Reputation damage and loss of customer trust if a breach is disclosed
- Potential legal liability from affected customers or partners whose data was exposed
- Loss of competitive advantage if strategic business data is compromised

**Technical Impact:**
- Compromise of database confidentiality, allowing access to all readable data the service account can reach
- Exposure of database schema and structure, which could reveal sensitive application architecture
- Potential disclosure of internal system information and configurations
- Risk of credential exposure if the database stores authentication information
- Enumeration of user accounts and personal information
- Ability to map the database structure for potential future attacks
- While the read-only nature of the database access prevents data modification, the information disclosure alone represents a significant security breach

The read-only limitation significantly reduces what would otherwise be a catastrophic impact (preventing data corruption, deletion, or modification), but the confidentiality breach remains a serious concern, particularly for organizations handling regulated data types like PII, PHI, or financial information.

# Technical Details
The vulnerability exists due to string interpolation being used to construct SQL queries instead of parameterized queries. Let's analyze the vulnerable code:

```go
func (s *Server) GetUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
    // Vulnerability: Direct interpolation of user input into SQL query via fmt.Sprintf
    query := fmt.Sprintf("SELECT id, username, email FROM users WHERE username = '%s'", req.Username)
    row := s.db.QueryRowContext(ctx, query)

    var id int
    var username, email string
    if err := row.Scan(&id, &username, &email); err != nil {
        return nil, err
    }

    return &pb.UserResponse{
        Id:       int32(id),
        Username: username,
        Email:    email,
    }, nil
}

```

**Vulnerability Analysis:**

1. **String Interpolation**: The code uses `fmt.Sprintf()` to construct a SQL query by directly embedding the user-supplied value `req.Username` into the query string. This fundamental insecure practice creates the SQL injection vulnerability.

2. **No Input Validation**: The code performs no validation or sanitization on the `req.Username` value before using it in the query.

3. **Direct Execution**: The constructed query string is directly passed to `db.QueryRowContext()` for execution.

4. **SQL Structure Manipulation**: Because the input is enclosed in single quotes in the query (`'%s'`), an attacker can break out of the string context by including a single quote in their input.

**Database Permission Context:**

The PostgreSQL database user employed by this service has been configured with read-only permissions to specific databases. This means:

1. The database user cannot execute `INSERT`, `UPDATE`, `DELETE`, or `DROP` statements
2. Data modification attacks are not possible
3. Schema modification attacks are prevented
4. The impact is limited to information disclosure scenarios

**Exploitation Mechanics:**

SQL injection attacks work by manipulating the structure of the SQL query. For example:

- Input: `normal_user` → Query: `SELECT id, username, email FROM users WHERE username = 'normal_user'`
- Input: `' OR '1'='1` → Query: `SELECT id, username, email FROM users WHERE username = '' OR '1'='1'`

The second query returns all rows because the condition `'1'='1'` is always true.

With read-only access, attackers would focus on information disclosure techniques such as:

- UNION attacks: `' UNION SELECT column1, column2, column3 FROM another_table WHERE '1'='1`
- Subqueries: `' AND EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'credit_cards') --`
- Boolean-based blind injection: `' AND (SELECT SUBSTRING(password,1,1) FROM admin_users WHERE username='admin')='a`

While the read-only permissions prevent damage from destructive queries, the information disclosure aspect remains a significant security risk.

# Remediation Steps
## Use Parameterized Queries

**Priority**: P0

Replace string interpolation with parameterized queries to properly separate SQL code from data values:

```go
func (s *Server) GetUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
    // Safe implementation using parameterized query
    query := "SELECT id, username, email FROM users WHERE username = $1"
    row := s.db.QueryRowContext(ctx, query, req.Username)

    var id int
    var username, email string
    if err := row.Scan(&id, &username, &email); err != nil {
        return nil, err
    }

    return &pb.UserResponse{
        Id:       int32(id),
        Username: username,
        Email:    email,
    }, nil
}

```

This approach ensures that the database treats the username value as data, not as part of the SQL command structure. The parameter placeholder syntax ($1) might vary depending on the database (e.g., MySQL uses ? instead of $1).
## Consider Using an ORM or Query Builder

**Priority**: P1

For more comprehensive protection and maintainability, consider using an Object-Relational Mapping (ORM) library like GORM or a query builder like SQLX:

```go
// Using GORM
func (s *Server) GetUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
    var user User
    if err := s.db.WithContext(ctx).Where("username = ?", req.Username).First(&user).Error; err != nil {
        return nil, err
    }

    return &pb.UserResponse{
        Id:       int32(user.ID),
        Username: user.Username,
        Email:    user.Email,
    }, nil
}

// Using SQLX
func (s *Server) GetUser(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
    query := "SELECT id, username, email FROM users WHERE username = ?"
    
    var user User
    if err := s.db.GetContext(ctx, &user, query, req.Username); err != nil {
        return nil, err
    }

    return &pb.UserResponse{
        Id:       int32(user.ID),
        Username: user.Username,
        Email:    user.Email,
    }, nil
}

```

ORMs and query builders provide additional safeguards against SQL injection by handling parameter binding securely. They also offer benefits like automatic mapping between database rows and Go structs, simplifying the code.


# References
* CWE-89 | [Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* CWE-943 | [Improper Neutralization of Special Elements in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html)
* A04:2021 | [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
