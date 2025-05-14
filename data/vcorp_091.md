# LDAP Injection in User Search Servlet

# Vulnerability Case
During our comprehensive security assessment of Acme Corp's Java-based web application (running on Apache Tomcat with integration to Active Directory), we identified an LDAP injection vulnerability (flagged as `java.lang.security.audit.tainted-ldapi-from-http-request.tainted-ldapi-from-http-request`). The vulnerability was discovered during a manual code review combined with log analysis, where unsanitized HTTPServletRequest parameters were directly incorporated into LDAP query filters. An attacker controlling the input can manipulate the query to inject additional LDAP clauses, enabling unauthorized data disclosure from the directory service. This flaw poses a significant risk of exposing sensitive user attributes, organizational structure, and other confidential information stored in Active Directory.

```java
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class UserSearchServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    // Tainted input directly retrieved from the HTTP request
    String uid = request.getParameter("uid");
    
    // Vulnerable LDAP query: unsanitized input concatenated directly
    String searchFilter = "(&(objectClass=user)(uid=" + uid + "))";
    
    try {
      DirContext ctx = new InitialDirContext();
      SearchControls constraints = new SearchControls();
      constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
      
      NamingEnumeration<SearchResult> results = ctx.search(
        "ou=users,dc=acme,dc=local",
        searchFilter,
        constraints
      );
      
      while (results.hasMore()) {
        SearchResult sr = results.next();
        // Process LDAP search result
      }
    } catch (NamingException e) {
      // Log exception details - potential indicator of exploitation attempts
      e.printStackTrace();
    }
  }
}
```

The LDAP injection vulnerability stems from the failure to sanitize user-supplied input from the `HttpServletRequest`, which is concatenated directly into the LDAP search filter instead of using parameterized queries. Exploitation methods may involve crafting a malicious `uid` parameter to inject additional filter conditions (e.g., `*)(|(uid=*))`), thereby bypassing intended access controls or altering query semantics to retrieve unauthorized data. In a business context, successful exploitation could lead to:  
- Exposure of personnel information and organizational data  
- Violations of data protection regulations (GDPR, HIPAA)  
- Enhanced attacker reconnaissance for follow-on attacks  

**Impact Clarification:**  
The vulnerable endpoint performs read-only operations, limiting the impact to confidentiality breaches. There is no evidence in the code that directory objects can be modified through this vulnerability, contrary to initial assessment. The primary risks are information disclosure and authorization bypasses, not direct modification of LDAP data.

context: java.lang.security.audit.tainted-ldapi-from-http-request.tainted-ldapi-from-http-request Detected input from a HTTPServletRequest going into an LDAP query. This could lead to LDAP injection if the input is not properly sanitized, which could result in attackers modifying objects in the LDAP tree structure. Ensure data passed to an LDAP query is not controllable or properly sanitize the data.

# Vulnerability Breakdown
This vulnerability involves unsanitized user input being directly incorporated into LDAP query filters in Acme Corp's Java-based web application, creating a significant LDAP injection risk.

1. **Key vulnerability elements**:
   - Direct concatenation of the user-supplied `uid` parameter into LDAP search filter
   - No input validation or sanitization
   - No proper encoding of special LDAP filter characters
   - Integration with Active Directory increases impact scope
   - Running on Apache Tomcat with integration to enterprise directory services

2. **Potential attack vectors**:
   - Injection of LDAP filter metacharacters (e.g., `*`, `(`, `)`, `|`, `&`, `!`)
   - Creation of always-true conditions like `*)(|(uid=*)`
   - Filter manipulation to access unauthorized data
   - Authorization bypasses through filter manipulation

3. **Severity assessment**:
   - High confidentiality impact: Potential exposure of directory information
   - No integrity impact: The endpoint only performs read operations
   - No availability impact: The endpoint does not affect service availability
   - Changed scope: Impacts extend beyond the web application to the directory service
   - Network-based attack vector but with high complexity to craft effective payloads

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): High (H) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Changed (C)
   - Confidentiality (C): High (H) 
   - Integrity (I): None (N) 
   - Availability (A): None (N) 

CVSS Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N

# Description
An LDAP injection vulnerability has been identified in Acme Corp's Java-based web application running on Apache Tomcat with Active Directory integration. The vulnerability exists in the `UserSearchServlet` class where the application directly incorporates an unsanitized HTTP request parameter (`uid`) into an LDAP search filter without proper validation or escaping.

```java
// Tainted input directly retrieved from the HTTP request
String uid = request.getParameter("uid");

// Vulnerable LDAP query: unsanitized input concatenated directly
String searchFilter = "(&(objectClass=user)(uid=" + uid + "))";

```

This vulnerability allows attackers to inject arbitrary LDAP filter syntax, potentially manipulating the query logic to access unauthorized information from the directory. The affected endpoint performs read-only operations, with the primary risk being unauthorized access to sensitive directory information.

# CVSS
**Score**: 6.8 \
**Vector**: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N \
**Severity**: Medium

The Medium severity rating (CVSS score: 6.8) is justified by several factors:

- **Network Attack Vector (AV:N)**: The vulnerability is exploitable remotely through HTTP requests to the web application, allowing attackers to reach the vulnerable component from anywhere with network access.

- **High Attack Complexity (AC:H)**: Exploiting this vulnerability requires specialized knowledge of LDAP filter syntax and directory structure. Crafting effective payloads that return useful information is complex and requires specific technical expertise.

- **No Privileges Required (PR:N)**: The vulnerable endpoint appears to be accessible without authentication, allowing unauthenticated attackers to exploit the vulnerability.

- **No User Interaction (UI:N)**: The attack can be executed without requiring any action from legitimate users of the system.

- **Changed Scope (S:C)**: The vulnerability allows impact beyond the vulnerable web application to the underlying LDAP directory service (Active Directory), potentially affecting other systems and applications that rely on the directory.

- **High Confidentiality Impact (C:H)**: Successful exploitation could expose sensitive user and organizational data stored in the directory service, including user attributes, group memberships, and other privileged information.

- **No Integrity Impact (I:N)**: The specific endpoint shown only performs read operations, not writes. There is no direct modification of data in the directory service through this vulnerability.

- **No Availability Impact (A:N)**: The vulnerability does not directly impact the availability of the application or directory service.

# Exploitation Scenarios
**Scenario 1: Authentication Bypass**
An attacker modifies the `uid` parameter to inject a filter that always evaluates to true, such as `*)(|(objectClass=*)`. The resulting LDAP query becomes `(&(objectClass=user)(uid=*)(|(objectClass=*)))`, which matches any user object regardless of UID. If the application uses this search to authenticate users, the attacker could bypass authentication checks and gain unauthorized access to the application.

**Scenario 2: Information Disclosure**
By injecting a modified filter like `*)(uid=admin)(sAMAccountName=*`, an attacker can retrieve information about the admin user regardless of the original search intention. The query becomes `(&(objectClass=user)(uid=*)(uid=admin)(sAMAccountName=*))`, allowing targeted extraction of sensitive data about specific high-value accounts.

**Scenario 3: Enterprise-Wide Reconnaissance**
An attacker injects `*))(&(objectClass=*))(|(objectClass=*` to bypass the original filter constraints entirely. The resulting query retrieves all objects in the directory, providing comprehensive reconnaissance of the organizational structure, user accounts, groups, and potentially other network resources defined in Active Directory.

# Impact Analysis
**Business Impact:**
- Unauthorized access to personnel information stored in the directory service
- Potential breach of confidential company data if directory contains protected resources
- Violation of regulatory requirements (GDPR, HIPAA, etc.) if personal information is exposed
- Reputational damage if security incidents result from exposed information
- Financial losses from incident response and potential legal liabilities

**Technical Impact:**
- Compromise of the directory service's information confidentiality
- Unauthorized access to user attributes and organizational structure
- Ability to enumerate users, groups, and organizational units in the directory
- Information gathering that could facilitate further attacks against the organization
- Enhanced reconnaissance capabilities for attackers targeting the enterprise

**Important Context on Impact Limitations:**
The specific vulnerable endpoint shown in the code performs only read operations (not direct writes to the directory). This means that:

1. The direct impact is limited to confidentiality breaches (information disclosure)

2. There is no direct integrity impact as the endpoint cannot modify directory data

3. There is no direct availability impact on the directory service or application

# Technical Details
The vulnerability exists in the `UserSearchServlet` class which processes HTTP requests to search for users in the LDAP directory. The core issue is in the `doGet` method, where user input is directly concatenated into an LDAP search filter without any validation or sanitization:

```java
protected void doGet(HttpServletRequest request, HttpServletResponse response)
    throws IOException {
  // Tainted input directly retrieved from the HTTP request
  String uid = request.getParameter("uid");
  
  // Vulnerable LDAP query: unsanitized input concatenated directly
  String searchFilter = "(&(objectClass=user)(uid=" + uid + "))";
  
  try {
    DirContext ctx = new InitialDirContext();
    SearchControls constraints = new SearchControls();
    constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
    
    NamingEnumeration<SearchResult> results = ctx.search(
      "ou=users,dc=acme,dc=local",
      searchFilter,
      constraints
    );
    
    // Process results... (read-only operations)
  } catch (NamingException e) {
    e.printStackTrace();
  }
}

```

**Key Technical Context:**

1. **Read-Only Nature**: This specific endpoint only performs read operations. There are no direct write operations (`modifyAttributes()`, `createSubcontext()`, or similar) visible in this code.

**LDAP Injection Mechanics:**

The vulnerability stems from LDAP's filter syntax, which uses special characters like parentheses, asterisks, and logical operators. When these characters are included in the user input, they can alter the structure and logic of the intended LDAP query.

In a normal operation, if a user provides `john.doe` as the UID, the resulting filter would be:
```
(&(objectClass=user)(uid=john.doe))

```

However, an attacker can inject special characters to manipulate the query. For example, with an input of `*)(|(uid=*`, the filter becomes:
```
(&(objectClass=user)(uid=*)(|(uid=*)))

```

This transforms the logical structure of the query, creating an "OR" condition that matches any user with any UID, effectively bypassing the search restriction.

**Additional Technical Concerns:**

1. The application connects to Active Directory, which typically contains sensitive organizational data

2. The code uses SUBTREE_SCOPE for the search, which means the query runs against the entire directory tree under the specified base DN

3. No error handling or filtering is implemented to detect or prevent injection attempts

4. Stack traces are output directly (`e.printStackTrace()`), potentially leaking implementation details to attackers

# Remediation Steps
## Implement LDAP Filter Encoding

**Priority**: P0

Replace direct string concatenation with proper LDAP filter encoding to neutralize special characters in user input:

```java
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

public class UserSearchServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    String uid = request.getParameter("uid");
    
    // Validate uid is not null or empty
    if (uid == null || uid.trim().isEmpty()) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST, "UID parameter is required");
      return;
    }
    
    // Encode the LDAP filter value to escape special characters
    String encodedUid = filterEncode(uid);
    
    // Now construct the search filter with the encoded value
    String searchFilter = "(&(objectClass=user)(uid=" + encodedUid + "))";
    
    try {
      // Rest of the code...
    } catch (NamingException e) {
      // Secure error handling
      logger.error("LDAP search error", e);
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "An error occurred while processing your request");
    }
  }
  
  // Method to encode LDAP filter values
  private String filterEncode(String value) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      switch (c) {
        case '*':
          sb.append("\\2a");
          break;
        case '(':
          sb.append("\\28");
          break;
        case ')':
          sb.append("\\29");
          break;
        case '\\':
          sb.append("\\5c");
          break;
        case '\u0000':
          sb.append("\\00");
          break;
        default:
          sb.append(c);
      }
    }
    return sb.toString();
  }
}

```

This implementation properly encodes LDAP special characters, preventing them from altering the filter's logical structure while still allowing legitimate search functionality.
## Use JNDI Attribute Value Controls

**Priority**: P1

Replace string concatenation entirely by using the more secure JNDI controls for handling attribute values in search operations:

```java
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;

public class UserSearchServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    String uid = request.getParameter("uid");
    
    // Validate uid is not null or empty
    if (uid == null || uid.trim().isEmpty()) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST, "UID parameter is required");
      return;
    }
    
    try {
      DirContext ctx = new InitialDirContext();
      SearchControls constraints = new SearchControls();
      constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
      
      // Create attribute set for safer searching
      Attributes matchAttrs = new BasicAttributes(true); // Case-insensitive matching
      matchAttrs.put(new BasicAttribute("objectClass", "user"));
      matchAttrs.put(new BasicAttribute("uid", uid));
      
      // Use getAttributes instead of search with filter string
      NamingEnumeration<SearchResult> results = ctx.search(
        "ou=users,dc=acme,dc=local",
        matchAttrs,
        new String[] {"cn", "mail", "displayName"} // Only return these attributes
      );
      
      // Process results safely...
      // ...
      
    } catch (NamingException e) {
      // Secure error handling with appropriate logging
      logger.error("LDAP search error", e);
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "An error occurred while processing your request");
    }
  }
}

```

This approach uses JNDI's built-in attribute matching system rather than string-based filters, inherently protecting against LDAP injection. It also limits the attributes that can be returned, implementing the principle of least privilege at the data access level.


# References
* CWE-90 | [Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* CWE-116 | [Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)
