# SQL Injection in Go User Management API

# Vulnerability Case
During the assessment of Acme Corp's user management API written in Go, we discovered a SQL injection vulnerability by tracing requests logged during abnormal query execution. The investigation revealed that untrusted input from HTTP parameters was directly concatenated into SQL queries using the Go standard library without sanitization. This vulnerable pattern, observed in a MySQL-backed service using the `github.com/go-sql-driver/mysql` stack, leverages unsafe string formatting via `fmt.Sprintf` to build queries. Consequently, attackers could inject malicious SQL code via user-controlled parameters, compromising data confidentiality and potentially bypassing authentication controls.  

```go  
package main  

import (  
        "database/sql"  
        "fmt"  
        "log"  
        "net/http"  

        _ "github.com/go-sql-driver/mysql"  
)  

var db *sql.DB  

func main() {  
        var err error  
        // Establishing a connection to the MySQL database  
        db, err = sql.Open("mysql", "user:password@tcp(127.0.0.1:3306)/acme_db")  
        if err != nil {  
                log.Fatal(err)  
        }  
        defer db.Close()  

        http.HandleFunc("/search", searchHandler)  
        log.Fatal(http.ListenAndServe(":8080", nil))  
}  

func searchHandler(w http.ResponseWriter, r *http.Request) {  
        // Retrieve the untrusted input  
        username := r.URL.Query().Get("username")  

        // Vulnerability: Direct concatenation of untrusted input into SQL query  
        // Using fmt.Sprintf introduces a SQL injection risk  
        query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)  
        rows, err := db.Query(query)  
        if err != nil {  
                http.Error(w, "Database error", http.StatusInternalServerError)  
                return  
        }  
        defer rows.Close()  

        // Process database rows (omitted for brevity)  
        fmt.Fprintf(w, "Executed query: %s", query)  
}  
```  

The vulnerability arises when an attacker injects crafted input into the `username` parameter, allowing the construction of a malicious SQL payload via the insecure `fmt.Sprintf` concatenation. Exploitation of this flaw could enable an adversary to exfiltrate sensitive user information, bypass authentication mechanisms, or degrade database performance through resource-intensive queries. Given that the affected API is a critical component of Acme Corp’s infrastructure employing Go’s `database/sql` with the MySQL driver, a successful attack could result in severe business impacts including data breaches, regulatory non-compliance, and significant financial and reputational damage.  

**context:** go.net.sql.go-vanillasql-format-string-sqli-taint.go-vanillasql-format-string-sqli-taint Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions. When building SQL queries in Go, it is possible to adopt prepared statements by using the `Prepare` and `PrepareContext` calls with parameterized queries. For more information, see: [Prepared statements in Go](https://go.dev/doc/database/prepared-statements).

# Vulnerability Breakdown
This vulnerability involves direct concatenation of untrusted HTTP parameters into SQL queries in Acme Corp's Go-based user management API, creating a severe SQL injection risk.

1. **Key vulnerability elements**:
   - Direct string concatenation using `fmt.Sprintf()` to build SQL queries
   - No sanitization or validation of user input from HTTP parameters
   - Using standard `database/sql` package without leveraging parameterized queries
   - Vulnerable code exposed in a critical user management API endpoint
   - Query results directly returned to users, potentially exposing sensitive data

2. **Potential attack vectors**:
   - Injecting malicious SQL via the `username` parameter
   - Authentication bypass using `' OR 1=1--` type payloads
   - Data exfiltration through UNION queries
   - Schema enumeration via information_schema queries
   - Performance degradation through complex, resource-intensive queries

3. **Severity assessment**:
   - High confidentiality impact from potential data exposure
   - No integrity impact as MySQL doesn't allow multiple statements and query starts with SELECT
   - Low availability impact from possible database performance degradation
   - Network-accessible attack vector requiring no special privileges
   - Low complexity exploitation requiring basic SQL injection knowledge

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): None (N) 
   - Availability (A): Low (L) 

# Description
A critical SQL injection vulnerability exists in Acme Corp's user management API written in Go. The vulnerability is present in the `/search` endpoint's handler function, where untrusted user input from the `username` query parameter is directly concatenated into a SQL query using string formatting (`fmt.Sprintf`) without proper sanitization or parameterization.

```go
// Vulnerability: Direct concatenation of untrusted input into SQL query
query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
rows, err := db.Query(query)

```

This insecure implementation allows attackers to inject arbitrary SQL code by manipulating the `username` parameter in HTTP requests. The vulnerability is further exacerbated by the fact that the application returns the executed query in the response, making it easier for attackers to craft and refine their injection payloads.

The API uses the standard Go `database/sql` package with the MySQL driver (`github.com/go-sql-driver/mysql`), which supports parameterized queries that would prevent this vulnerability, but the application fails to leverage this security feature. As a user management API, this component likely handles sensitive information, making the impact of exploitation particularly severe.

# CVSS
**Score**: 8.1 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L \
**Severity**: High

The High severity rating (8.1) is justified by the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability is exploitable remotely through the API endpoint without requiring local access.

- **Low Attack Complexity (AC:L)**: Exploitation requires only basic SQL injection knowledge and techniques. No specialized conditions or timing requirements exist.

- **No Privileges Required (PR:N)**: An attacker doesn't need any authentication or special privileges to exploit the vulnerability, as the affected endpoint appears to be publicly accessible.

- **No User Interaction (UI:N)**: Exploitation can be fully automated and doesn't require any action from legitimate users or administrators.

- **Unchanged Scope (S:U)**: The vulnerability impacts only the components within the authorization scope of the vulnerable API service.

- **High Confidentiality Impact (C:H)**: Through SQL injection, an attacker can potentially access all data in the connected database, including sensitive user information and credentials.

- **No Integrity Impact (I:N)**: Due to MySQL's restriction on multiple SQL statements in a single query and the fact that the query begins with a SELECT statement, modifying the database is not possible. The MySQL user also lacks file write permissions, preventing additional attack vectors.

- **Low Availability Impact (A:L)**: Attackers can inject complex, resource-intensive queries that might cause database performance degradation, though not a complete system outage.

This rating reflects the serious nature of SQL injection in a user management system, where data exposure presents significant risks to the organization, even with limitations on data modification.

# Exploitation Scenarios
**Data Exfiltration Attack**
An attacker sends a request to `/search?username=x' UNION SELECT username, password, email FROM users--` to extract all usernames, password hashes, and email addresses from the database. By leveraging UNION-based SQL injection, the attacker can dump sensitive data from multiple tables, potentially compromising all user accounts in the system.

**Authentication Bypass**
By sending a request to `/search?username=' OR 1=1--`, an attacker can bypass authentication checks that rely on this query, as the injected condition makes the WHERE clause true for all rows. This could allow the attacker to impersonate users or access restricted functionality.

**Database Schema Enumeration**
An attacker can map the database structure by sending queries like `/search?username=x' UNION SELECT table_name, column_name, 1 FROM information_schema.columns WHERE table_schema='acme_db'--`. This information gathering step reveals table names, column names, and other schema details, enabling more targeted attacks.

**Performance Degradation**
An attacker could cause resource exhaustion by injecting computationally intensive queries like `/search?username=x' UNION SELECT *, BENCHMARK(1000000,MD5(RAND()))--`, potentially slowing down the database server and affecting other users and applications sharing the same database resources.

**Data Leakage via Error Messages**
By injecting deliberately malformed SQL like `/search?username=x' AND (SELECT EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e)))--`, an attacker can force error messages that may reveal additional information about the database environment, facilitating further attacks.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive user data including personal information and credentials
- Potential for complete compromise of the user management system
- Regulatory violations and compliance failures (GDPR, CCPA, etc.) resulting in legal penalties
- Breach notification costs and potential class-action lawsuits
- Reputation damage affecting customer trust and business relationships
- Financial losses from remediation efforts, legal expenses, and potential customer compensation
- Operational disruption during incident response and remediation phases

**Technical Impact:**
- Complete database exposure allowing extraction of all stored data
- Exposure of internal network architecture through error messages
- Database performance degradation from malicious complex queries
- Possible authentication bypass and unauthorized access to user accounts
- Audit trail pollution making it difficult to trace legitimate vs. malicious activity
- Chain reaction vulnerabilities if harvested credentials are reused across systems
- Information disclosure about database schema, version, and configuration

# Technical Details
The vulnerability exists in the `searchHandler` function of Acme Corp's Go-based user management API. The root cause is the insecure construction of SQL queries using string concatenation:

```go
func searchHandler(w http.ResponseWriter, r *http.Request) {
    // Retrieve the untrusted input
    username := r.URL.Query().Get("username")

    // Vulnerability: Direct concatenation of untrusted input into SQL query
    // Using fmt.Sprintf introduces a SQL injection risk
    query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
    rows, err := db.Query(query)
    if err != nil {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    // Process database rows (omitted for brevity)
    fmt.Fprintf(w, "Executed query: %s", query)
}

```

**Vulnerability Mechanics:**

1. The application receives user input via the `username` query parameter
2. This input is directly embedded into a SQL query string using `fmt.Sprintf`
3. No validation, sanitization, or escaping of the input occurs
4. The query is executed against the MySQL database
5. The raw query is even echoed back in the response, aiding attackers in crafting exploits

**Why This Is Exploitable:**

When a user provides a malicious input containing SQL syntax characters, the query structure is altered. For example, if `username = x' OR '1'='1`, the resulting query becomes:

```sql
SELECT * FROM users WHERE username = 'x' OR '1'='1'

```

This transforms the query to return all users instead of just matching 'x'.

**Exploitation Limitations:**

1. **Multiple Statement Restriction**: MySQL's default configuration doesn't allow multiple SQL statements in a single query through the standard API, limiting the attack to a single statement.

2. **Initial SELECT Statement**: Since the query begins with a SELECT, attackers can't directly modify data using UPDATE/INSERT/DELETE statements.

3. **MySQL User Permissions**: The database user lacks file system write permissions, preventing attacks that might attempt to write to the filesystem.

**Missing Security Controls:**

1. **Parameterized Queries**: Go's `database/sql` package supports parameterized queries using placeholders (`?`), which would prevent SQL injection:

```go
rows, err := db.Query("SELECT * FROM users WHERE username = ?", username)

```

2. **Input Validation**: No validation of the username parameter occurs before use

3. **Error Handling**: Errors are not properly logged, and raw queries are exposed to users

4. **Least Privilege**: No indication of using a database connection with minimum required privileges

# Remediation Steps
## Implement Parameterized Queries

**Priority**: P0

Replace the vulnerable string concatenation with parameterized queries to ensure proper separation of code and data:

```go
func searchHandler(w http.ResponseWriter, r *http.Request) {
    // Retrieve the input
    username := r.URL.Query().Get("username")
    
    // Use parameterized query with placeholder (?)
    query := "SELECT * FROM users WHERE username = ?"
    rows, err := db.Query(query, username)
    if err != nil {
        // Log error internally but don't expose details to user
        log.Printf("Database error: %v", err)
        http.Error(w, "An error occurred processing your request", http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    
    // Process database rows
    // ...
    
    // Don't echo back the raw query to users
}

```

This approach ensures that user input is always treated as data and never as executable code, regardless of what characters it contains. The MySQL driver will properly escape the parameter values, preventing SQL injection attacks.
## Implement Input Validation and Prepared Statements

**Priority**: P1

Add input validation as a defense-in-depth measure and use prepared statements for frequently executed queries:

```go
func searchHandler(w http.ResponseWriter, r *http.Request) {
    // Retrieve the input
    username := r.URL.Query().Get("username")
    
    // Input validation
    if !isValidUsername(username) {
        http.Error(w, "Invalid username format", http.StatusBadRequest)
        return
    }
    
    // Prepare the statement once (can be moved to init function for reuse)
    stmt, err := db.Prepare("SELECT * FROM users WHERE username = ?")
    if err != nil {
        log.Printf("Failed to prepare statement: %v", err)
        http.Error(w, "Server error", http.StatusInternalServerError)
        return
    }
    defer stmt.Close()
    
    // Execute the prepared statement
    rows, err := stmt.Query(username)
    if err != nil {
        log.Printf("Query error: %v", err)
        http.Error(w, "An error occurred processing your request", http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    
    // Process results
    // ...
}

func isValidUsername(username string) bool {
    // Example validation: username should be 3-20 alphanumeric characters
    if len(username) < 3 || len(username) > 20 {
        return false
    }
    
    // Check for alphanumeric characters only
    for _, char := range username {
        if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '_' {
            return false
        }
    }
    
    return true
}

```

This implementation adds multiple layers of protection:
1. Input validation rejects potentially malicious inputs before processing
2. Prepared statements provide optimal protection against SQL injection
3. Error logging occurs without exposing sensitive details to users
4. Statement preparation happens once and can be reused for performance optimization


# References
* CWE-89 | [Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* GO-DB-SECURITY | [Prepared statements in Go](https://go.dev/doc/database/prepared-statements)
