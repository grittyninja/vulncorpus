# LDAP Injection in HR Management System

# Vulnerability Case
During an internal security audit of Acme Corp's Java-based HR management system built on Spring Boot, an LDAP injection vulnerability was identified in the user search module. The code directly concatenates unsanitized external input into an LDAP query string, enabling potential attackers to manipulate query logic. This issue was discovered when reviewing log entries from the java.lang.security.audit.ldap-injection process, which flagged non-constant data being passed to LDAP query construction. The vulnerability may allow malicious users to bypass intended access controls and retrieve sensitive directory data, posing significant risks to data confidentiality.

```java
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;

public class LdapUserSearch {

  // Vulnerable method: unsanitized input concatenated into LDAP query
  public List<SearchResult> searchUser(HttpServletRequest request) throws NamingException {
    String username = request.getParameter("username");
    // Vulnerable pattern: Directly embedding user input into the LDAP filter
    String filter = "(&(objectClass=person)(uid=" + username + "))";

    SearchControls sc = new SearchControls();
    sc.setSearchScope(SearchControls.SUBTREE_SCOPE);

    NamingEnumeration<SearchResult> results =
        LdapContextProvider.getContext()
          .search("ou=users,dc=acme,dc=corp", filter, sc);

    List<SearchResult> foundUsers = new ArrayList<>();
    while (results.hasMore()) {
      foundUsers.add(results.next());
    }
    return foundUsers;
  }
}
```

The vulnerability originates from unsanitized external input (`username`) being directly concatenated into the LDAP search filter. An attacker can exploit this by supplying crafted inputs such as `*)(|(uid=*))`, which can transform the intended query into one that always returns true, effectively bypassing authentication or data access controls. This exploitation method may allow unauthorized disclosure of user directory information, lateral movement within trusted networks, and potential data exfiltration. The attack’s business impact includes loss of sensitive personal data, erosion of user trust, and possible regulatory non-compliance liabilities, especially given Acme Corp’s reliance on a Java/Spring Boot stack integrated with LDAP services for identity management.


context: java.lang.security.audit.ldap-injection.ldap-injection Detected non-constant data passed into an LDAP query. If this data can be controlled by an external user, this is an LDAP injection. Ensure data passed to an LDAP query is not controllable; or properly sanitize the data.

# Vulnerability Breakdown
This vulnerability involves an LDAP injection issue in Acme Corp's Java-based HR management system, built on Spring Boot. The user search module directly concatenates unsanitized user input into LDAP query strings, allowing manipulation of query logic.

1. **Key vulnerability elements**:
   - Direct string concatenation of user input into LDAP queries
   - No input validation or sanitization
   - Potentially exposes all data in the LDAP directory
   - Allows query logic manipulation

2. **Potential attack vectors**:
   - Authentication bypass by manipulating the LDAP filter
   - Information disclosure of sensitive directory data
   - Access control bypass to retrieve unauthorized information
   - Potential for lateral movement within trusted networks

3. **Severity assessment**:
   - High confidentiality impact due to potential exposure of all directory data
   - Low integrity impact as system may make decisions based on compromised query results
   - Network-based attack vector with low complexity
   - Some privileges required to access the vulnerable functionality

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): Low (L) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): Low (L) 
   - Availability (A): None (N) 

# Description
An LDAP injection vulnerability has been identified in Acme Corp's Java-based HR management system that uses Spring Boot. The vulnerability is located in the user search module, specifically in the `LdapUserSearch.searchUser()` method. The code directly concatenates unsanitized user input from HTTP request parameters into an LDAP query filter without proper validation or encoding.

```java
String username = request.getParameter("username");
String filter = "(&(objectClass=person)(uid=" + username + "))";`

```

This vulnerability allows attackers to manipulate the LDAP query logic by injecting special characters and control sequences. For example, an attacker could supply input like `*)(|(uid=*))` to modify the query structure, potentially bypassing access controls and retrieving sensitive directory information about employees. The internal security audit specifically flagged this as passing non-constant data to LDAP query construction, violating secure coding practices for directory service interactions.

# CVSS
**Score**: 7.0 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N \
**Severity**: High

The High severity rating (7.0) is based on:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely through the web-based HR management system
- **Low Attack Complexity (AC:L)**: Exploitation is straightforward and doesn't require special conditions or timing
- **Low Privileges Required (PR:L)**: Some level of access to the HR system is needed to reach the vulnerable function
- **No User Interaction (UI:N)**: The vulnerability can be exploited without requiring actions from other users
- **Unchanged Scope (S:U)**: The impact is confined to the vulnerable component and its directly accessible resources
- **High Confidentiality Impact (C:H)**: The vulnerability can lead to disclosure of sensitive employee data across the LDAP directory
- **Low Integrity Impact (I:L)**: Some impact on data integrity is possible if the system makes access control decisions based on query results
- **No Availability Impact (A:N)**: The vulnerability doesn't directly affect system availability

The primary concern is the potential exposure of sensitive personal information stored in the LDAP directory, which could lead to regulatory violations and further attacks leveraging the obtained information.

# Exploitation Scenarios
**Authentication Bypass Scenario**
An attacker with basic access to the HR portal modifies the username parameter in their request to: `*)(|(uid=*))`. When the application constructs the LDAP filter, it becomes: `(&(objectClass=person)(uid=*)(|(uid=*)))`. This creates a logical condition that always evaluates to true, causing the LDAP search to return information for all users in the directory instead of just the intended user. The attacker can then access sensitive information about any employee in the system.

**Information Harvesting Scenario**
An attacker injects: `dummy)(cn=*)(objectClass=person`. This transforms the original filter to: `(&(objectClass=person)(uid=dummy)(cn=*)(objectClass=person))`. The modified query searches for any person object with common names, potentially leaking a complete directory of employee names regardless of access controls. The attacker iteratively harvests various attributes by constructing similar queries targeting specific fields like `mail` or `telephoneNumber`.

**Privilege Discovery Scenario**
The attacker injects: `*)(memberOf=cn=Administrators,ou=groups,dc=acme,dc=corp))(&(objectclass=`. This modifies the query to search for members of the Administrators group. The results reveal which accounts have administrative privileges, providing valuable information for targeting privileged accounts in subsequent attacks. The attacker could enumerate different group memberships to map out the organization's role structure and identify high-value targets.

# Impact Analysis
**Business Impact:**
- Unauthorized disclosure of sensitive employee information including personal identifiable information (PII)
- Potential regulatory violations (GDPR, CCPA, HIPAA) if employee personal data is exposed
- Legal liability and financial penalties from compliance failures
- Erosion of employee trust in HR systems and data protection practices
- Reputational damage if a breach becomes public
- Additional compliance audit requirements and remediation costs

**Technical Impact:**
- Complete exposure of LDAP directory structure and content
- Unauthorized access to employee records, potentially including salary information, performance reviews, and personal details
- Compromise of authentication systems if password hashes or other credentials are accessible via LDAP
- Mapping of organizational structure, roles, and privileges that could facilitate further targeted attacks
- Potential use of harvested information for social engineering against employees
- Risk of lateral movement if directory information includes access details for other systems
- Circumvention of access controls implemented in the application layer

# Technical Details
The vulnerability occurs in the `LdapUserSearch` class of the HR management system, specifically in the `searchUser` method that processes user search requests. The critical security flaw is the direct concatenation of unsanitized user input into an LDAP query filter.

```java
public List<SearchResult> searchUser(HttpServletRequest request) throws NamingException {
  String username = request.getParameter("username");
  // Vulnerable pattern: Directly embedding user input into the LDAP filter
  String filter = "(&(objectClass=person)(uid=" + username + "))";

  SearchControls sc = new SearchControls();
  sc.setSearchScope(SearchControls.SUBTREE_SCOPE);

  NamingEnumeration<SearchResult> results =
      LdapContextProvider.getContext()
        .search("ou=users,dc=acme,dc=corp", filter, sc);

  List<SearchResult> foundUsers = new ArrayList<>();
  while (results.hasMore()) {
    foundUsers.add(results.next());
  }
  return foundUsers;
}

```

**Exploitation Mechanics:**

LDAP filters use special characters for logical operations including:
- `&` for AND operations
- `|` for OR operations
- `!` for NOT operations
- Parentheses `(` and `)` for grouping
- `*` as a wildcard character

By injecting these special characters, an attacker can manipulate the LDAP query logic. For example:

1. Original intended filter: `(&(objectClass=person)(uid=username))`
2. User input: `*)(|(uid=*))`
3. Resulting filter: `(&(objectClass=person)(uid=*)(|(uid=*)))`

This modified filter creates a condition that always evaluates to true because:
- The first condition `(objectClass=person)` matches any person object
- The second condition `(uid=*)` matches any user with a uid attribute (which would be all users)
- The third condition `(|(uid=*))` is an OR condition that will match any user with a uid, which is redundant but ensures a match

The parentheses injection changes the logical structure of the query, allowing conditions to be terminated early and new conditions to be introduced.

**Root Cause Analysis:**

The vulnerability stems from three fundamental issues:

1. **No Input Validation**: The code doesn't validate that the username parameter contains only safe characters
2. **Direct String Concatenation**: Using string concatenation instead of parameterized queries
3. **No LDAP Encoding**: Special characters in the input aren't properly escaped or encoded

The issue is compounded by the use of the SUBTREE_SCOPE search context, which causes the query to search the entire subtree under "ou=users,dc=acme,dc=corp", potentially exposing large amounts of data.

# Remediation Steps
## Implement JNDI Filter Parameters

**Priority**: P0

Replace direct string concatenation with JNDI filter parameters to properly escape special characters in LDAP queries:

```java
public List<SearchResult> searchUser(HttpServletRequest request) throws NamingException {
  String username = request.getParameter("username");
  
  // Use filter arguments instead of string concatenation
  String filter = "(&(objectClass=person)(uid={0}))";
  
  SearchControls sc = new SearchControls();
  sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
  
  // Pass username as a separate filter argument that will be properly escaped
  NamingEnumeration<SearchResult> results =
      LdapContextProvider.getContext()
        .search("ou=users,dc=acme,dc=corp", filter, new Object[]{username}, sc);
  
  List<SearchResult> foundUsers = new ArrayList<>();
  while (results.hasMore()) {
    foundUsers.add(results.next());
  }
  return foundUsers;
}

```

This approach uses the built-in parameter substitution mechanism of JNDI, which automatically handles escaping of special characters in LDAP filters. The `{0}` placeholder is replaced with the properly escaped username value, preventing LDAP injection attacks.
## Implement Input Validation

**Priority**: P1

Add strict input validation to ensure that only safe characters are allowed in the username parameter:

```java
public List<SearchResult> searchUser(HttpServletRequest request) throws NamingException {
  String username = request.getParameter("username");
  
  // Validate input against a strict pattern of allowed characters
  if (username == null || !username.matches("^[a-zA-Z0-9_.-]{1,64}$")) {
    throw new IllegalArgumentException("Invalid username format");
  }
  
  // Use filter arguments as in the previous solution
  String filter = "(&(objectClass=person)(uid={0}))";
  
  SearchControls sc = new SearchControls();
  sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
  
  NamingEnumeration<SearchResult> results =
      LdapContextProvider.getContext()
        .search("ou=users,dc=acme,dc=corp", filter, new Object[]{username}, sc);
  
  List<SearchResult> foundUsers = new ArrayList<>();
  while (results.hasMore()) {
    foundUsers.add(results.next());
  }
  return foundUsers;
}

```

This adds a defensive layer that rejects usernames containing potentially dangerous characters, ensuring that only alphanumeric characters, underscores, periods, and hyphens are allowed, with a reasonable maximum length. This validation complements the parameterized query approach for defense in depth.


# References
* CWE-90 | [Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* CWE-74 | [Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* ASVS | [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
