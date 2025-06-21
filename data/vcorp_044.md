# SQL Injection in Go Web Application User Search Endpoint

# Vulnerability Case
During the security assessment of Acme Corp's Go-based web application—which leverages the Gorilla toolkit for routing—we identified a potential SQL injection vulnerability in an API endpoint responsible for user search. The issue was discovered during a manual code review where untrusted input from URL query parameters was directly concatenated into an SQL statement using string formatting. This insecure pattern was evident in the endpoint that constructs its database query without utilizing prepared statements or parameterized queries. Our analysis indicates that an attacker could supply crafted input to manipulate the SQL query, enabling unauthorized data access, modification, or even execution of arbitrary SQL commands. The vulnerability poses a serious risk to the confidentiality and integrity of data stored in the MySQL database used in production. Attacker needs administrative privileges to access the vulnerable search user functionality.

```go
package main

import (
        "database/sql"
        "fmt"
        "log"
        "net/http"

        "github.com/gorilla/mux"
        _ "github.com/go-sql-driver/mysql"
)

// searchUserHandler demonstrates a vulnerable endpoint where untrusted
// input is directly concatenated into a SQL query.
func searchUserHandler(w http.ResponseWriter, r *http.Request) {
        db, err := sql.Open("mysql", "user:password@tcp(localhost:3306)/acmedb")
        if err != nil {
                http.Error(w, "Database connection error", http.StatusInternalServerError)
                return
        }
        defer db.Close()

        // Vulnerability: Directly using untrusted user input in an SQL query.
        search := r.URL.Query().Get("username")
        query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", search)

        rows, err := db.Query(query)
        if err != nil {
                http.Error(w, "Query execution error", http.StatusInternalServerError)
                return
        }
        defer rows.Close()
        // Process rows (omitted for brevity)
        fmt.Fprintf(w, "User data retrieved")
}

func main() {
        r := mux.NewRouter()
        r.HandleFunc("/search", searchUserHandler)
        log.Fatal(http.ListenAndServe(":8080", r))
}
```

The vulnerability arises from the use of string concatenation to embed unsanitized user input directly into the SQL query, permitting an attacker to inject malicious SQL fragments. By exploiting this flaw—such as submitting a payload like `\' OR \'1=1\' -- ` via the `/search` endpoint—the attacker could bypass authentication checks or retrieve unauthorized records. Additionally, with modified queries, an attacker might alter or delete critical records, potentially chaining the injection with further system compromises. The business impact involves severe data breaches, legal and regulatory consequences due to compromised sensitive information, and the potential erosion of customer trust, all of which could lead to substantial financial losses.


context: go.gorilla.sql.gorilla-go-vanillasql-format-string-sqli-taint-med-conf.gorilla-go-vanillasql-format-string-sqli-taint-med-conf Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions. When building SQL queries in Go, it is possible to adopt prepared statements by using the `Prepare` and `PrepareContext` calls with parameterized queries. For more information, see: [Prepared statements in Go](https://go.dev/doc/database/prepared-statements).

# Vulnerability Breakdown
This vulnerability involves improper handling of user input in a Go web application that directly concatenates untrusted data into SQL queries, allowing potential SQL injection attacks.

1. **Key vulnerability elements**:
   - Direct string concatenation of URL query parameters into SQL statements using `fmt.Sprintf`
   - Lack of prepared statements or parameterized queries
   - Insufficient input validation and sanitization
   - Exposure via an admin-only API endpoint
   - Implementation in Go using the standard database/sql package

2. **Potential attack vectors**:
   - Injection of malicious SQL fragments via the `username` query parameter
   - Authentication bypass using payloads like `' OR '1'='1' --`
   - Data extraction using UNION-based attacks
   - Potential for data modification or deletion using injected commands

3. **Severity assessment**:
   - Network-based attack vector allowing remote exploitation
   - Low complexity to execute with widely available SQL injection techniques
   - High privileges required as only administrators can access the endpoint
   - High potential impact on data confidentiality and integrity
   - Unchanged scope limited to the database component

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): High (H) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): Low (L) 

# Description
A SQL injection vulnerability exists in Acme Corp's Go-based web application, specifically in the admin-only user search API endpoint. The vulnerability stems from insecure coding practices where user input from URL query parameters is directly concatenated into SQL queries without proper sanitization or parameterization.

```go
// Vulnerability: Directly using untrusted user input in an SQL query.
search := r.URL.Query().Get("username")
query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", search)

rows, err := db.Query(query)

```

This vulnerable implementation allows attackers with administrative access to craft malicious inputs that can manipulate the structure of the SQL query, potentially allowing unauthorized access to sensitive data, modification of database contents, or even execution of administrative database commands. The vulnerability affects the `/search` endpoint that directly interfaces with the MySQL database, exposing critical user data to potential compromise.

# CVSS
**Score**: 6.7 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:L \
**Severity**: Medium

This SQL injection vulnerability received a Medium severity rating (CVSS score 6.7) due to several key factors:

- **Network Attack Vector (AV:N)**: The vulnerability is exploitable remotely over the internet as it exists in a web application endpoint, maximizing its accessibility to potential attackers.

- **Low Attack Complexity (AC:L)**: Exploiting this vulnerability requires minimal preparation or special conditions. Standard SQL injection techniques are well-documented and widely available, making exploitation straightforward for attackers with basic knowledge.

- **High Privileges Required (PR:H)**: The vulnerable `/search` endpoint is only accessible to administrators, significantly limiting the potential attacker pool to those who already have administrative access to the application. This substantially reduces the exploitability of the vulnerability.

- **No User Interaction (UI:N)**: Exploitation can be accomplished without requiring any action from users or administrators, making this a passive vulnerability that can be exploited silently.

- **Unchanged Scope (S:U)**: While serious, the vulnerability's impact remains within the affected component (the database and application), without directly compromising other system components.

- **High Confidentiality Impact (C:H)**: Successful exploitation could allow attackers to access all data stored in the database, potentially including sensitive user information, credentials, or business data.

- **High Integrity Impact (I:H)**: Attackers could potentially modify or delete data within the database, affecting data integrity and potentially manipulating application functionality.

- **Low Availability Impact (A:L)**: While the vulnerability primarily affects confidentiality and integrity, certain SQL injection attacks could cause resource consumption or trigger errors that temporarily impact service availability.

# Exploitation Scenarios
**Scenario 1: Privileged User Data Exfiltration**
An attacker who has gained administrative credentials through phishing or other means accesses the vulnerable `/search` endpoint and tests it with a simple payload: `' OR '1'='1' --`. When submitted as the username parameter:

```
GET /search?username=%27%20OR%20%271%27%3D%271%27%20--%20

```

The application constructs the following SQL query:

```sql
SELECT * FROM users WHERE username = '' OR '1'='1' --'

```

The injected code modifies the query logic, causing it to return all users in the database instead of a specific user. The attacker can then progressively extract more information using UNION-based attacks:

```
GET /search?username=%27%20UNION%20SELECT%20username,password,email,NULL%20FROM%20users%20--%20

```

**Scenario 2: Database Schema Enumeration by Administrator**
A malicious administrator uses error-based SQL injection to determine the database structure. By injecting payloads that cause SQL syntax errors, they extract information from error messages:

```
GET /search?username=%27%20AND%20(SELECT%201%20FROM%20(SELECT%20COUNT(*),CONCAT(DATABASE(),0x3a,TABLE_NAME,0x3a,COLUMN_NAME,FLOOR(RAND(0)*2))%20FROM%20INFORMATION_SCHEMA.COLUMNS%20GROUP%20BY%20x)a)%20--%20

```

This helps the attacker map out the database schema, including table names and column structures, facilitating more targeted attacks.

**Scenario 3: Unauthorized Data Modification by Insider Threat**
An administrator with malicious intent injects SQL to modify data beyond their intended permissions:

```
GET /search?username=%27%3B%20UPDATE%20users%20SET%20is_admin%3D1%20WHERE%20username%3D%27accomplice%27%3B%20--%20

```

This injection attempts to escalate privileges for another user by setting their admin flag to true. If successful, the administrator has now created another administrative account that may not be monitored as closely, providing additional persistent access to the system.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive customer data by administrators acting beyond their intended permissions
- Potential insider threats from administrators with malicious intent
- Regulatory compliance violations (GDPR, CCPA, etc.) resulting in financial penalties if a privileged user exploits the vulnerability
- Reputational damage and loss of customer trust if a data breach occurs through admin account compromise
- Legal liability from affected users whose data was compromised
- Financial losses from breach notification, remediation, and potential litigation
- Operational disruption during incident response and remediation efforts
- Potential intellectual property theft if proprietary information is stored in the database

**Technical Impact:**
- Complete compromise of database confidentiality by users who already have significant access
- Data integrity violations allowing administrative users to modify or corrupt critical information beyond their intended capabilities
- Potential for privilege escalation within the system if admin credentials can be manipulated
- Authentication system compromise if credential data is accessed or modified
- Possibility of lateral movement if database contains connection strings or credentials to other systems
- Creation of persistent backdoors through injected database content by privileged insiders
- Database service disruption if destructive queries are executed
- Potential for server-side command execution in specific database configurations

# Technical Details
The SQL injection vulnerability exists in the `searchUserHandler` function of Acme Corp's Go web application. The vulnerable pattern involves three critical issues:

1. **Direct User Input Handling**: The application extracts the `username` parameter from the URL query string without any validation or sanitization:

```go
search := r.URL.Query().Get("username")

```

2. **String Interpolation for Query Construction**: Instead of using parameterized queries, the code directly interpolates the user input into the SQL statement using `fmt.Sprintf`:

```go
query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", search)

```

3. **Direct Query Execution**: The constructed query string is then executed directly against the database:

```go
rows, err := db.Query(query)

```

This creates a classic SQL injection vulnerability. When a normal username is provided, the query functions as intended. For example, with `username=john`, the resulting query would be:

```sql
SELECT * FROM users WHERE username = 'john'

```

However, an attacker with administrative access can manipulate the query structure by including single quotes and SQL syntax. For instance, with `username=' OR '1'='1`, the resulting query becomes:

```sql
SELECT * FROM users WHERE username = '' OR '1'='1'

```

This modified query would return all rows from the users table, as the condition `'1'='1'` is always true.

More sophisticated attacks could leverage SQL features like:

- **UNION statements** to combine results with other tables
- **Subqueries** to extract information from other tables
- **Multiple statements** if the database driver allows it (though Go's standard MySQL driver typically doesn't)
- **Error-based injection** techniques to extract information through error messages

The vulnerability is particularly concerning because:

1. It exists in a user search function that likely has access to sensitive user data
2. While it requires administrative access, it allows privileged users to bypass any application-level data access controls
3. The direct string concatenation pattern is used without any mitigating controls
4. The database connection uses what appears to be a privileged account (`user:password@tcp(localhost:3306)/acmedb`)

# Remediation Steps
## Implement Parameterized Queries

**Priority**: P0

Replace the vulnerable string concatenation with parameterized queries using Go's `database/sql` package:

```go
func searchUserHandler(w http.ResponseWriter, r *http.Request) {
    db, err := sql.Open("mysql", "user:password@tcp(localhost:3306)/acmedb")
    if err != nil {
        http.Error(w, "Database connection error", http.StatusInternalServerError)
        return
    }
    defer db.Close()

    // Get the search parameter
    search := r.URL.Query().Get("username")

    // Use parameterized query instead of string concatenation
    query := "SELECT * FROM users WHERE username = ?"
    
    // Execute with parameter safely passed to the database
    rows, err := db.Query(query, search)
    if err != nil {
        http.Error(w, "Query execution error", http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    
    // Process rows (omitted for brevity)
    fmt.Fprintf(w, "User data retrieved")
}

```

This approach ensures that user input is properly separated from the SQL command structure, preventing injection attacks. The database driver will handle proper escaping and quoting of the parameter value based on the database's requirements.
## Add Input Validation and Sanitization

**Priority**: P1

Implement strict input validation to ensure the username parameter meets expected format requirements:

```go
func searchUserHandler(w http.ResponseWriter, r *http.Request) {
    db, err := sql.Open("mysql", "user:password@tcp(localhost:3306)/acmedb")
    if err != nil {
        http.Error(w, "Database connection error", http.StatusInternalServerError)
        return
    }
    defer db.Close()

    // Get the search parameter
    search := r.URL.Query().Get("username")
    
    // Input validation
    if search == "" {
        http.Error(w, "Username parameter is required", http.StatusBadRequest)
        return
    }
    
    // Add validation regex for username (alphanumeric + some special chars)
    validUsername := regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,64}$`)
    if !validUsername.MatchString(search) {
        http.Error(w, "Invalid username format", http.StatusBadRequest)
        return
    }
    
    // Continue with parameterized query
    query := "SELECT * FROM users WHERE username = ?"
    rows, err := db.Query(query, search)
    // ...
}

```

While parameterized queries are the primary defense, adding input validation provides defense-in-depth and helps catch potential issues early. This approach also improves error handling by providing meaningful responses for invalid inputs.


# References
* CWE-89 | [Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A04:2021 | [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
* CWE-707 | [Improper Neutralization](https://cwe.mitre.org/data/definitions/707.html)
