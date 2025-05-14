# Insecure Java Deserialization Vulnerability

# Vulnerability Case
During our security assessment of Acme Corp's Java-based enterprise application deployed on an Apache Tomcat server with Spring Boot, we discovered an object deserialization vulnerability. The application utilizes Java's native deserialization mechanism via `ObjectInputStream` to process incoming HTTP POST requests without verifying whether the data originates from a trusted source. This was noted during a review of the servlet responsible for processing client payloads, where deserialization of entire Java objects occurs directly from the network stream. The unvalidated deserialization of user-controlled data exposes the system to potential remote code execution (RCE) through crafted object streams leveraging gadget chains available in the application's classpath. The vulnerability poses a significant business risk by potentially allowing attackers to execute arbitrary code and compromise critical backend systems.

```java
import java.io.ObjectInputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class DeserializationServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        try (ObjectInputStream ois = new ObjectInputStream(request.getInputStream())) {
            // Vulnerable: Deserializes user-supplied input without validation
            Object data = ois.readObject();
            // Process the deserialized object without type or integrity checks
            processData(data);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private void processData(Object data) {
        // Business logic processing the deserialized object
    }
}
```

The exploitation vector involves an attacker sending a carefully crafted serialized Java object stream that, when deserialized by the vulnerable endpoint, triggers a gadget chain capable of executing arbitrary code. This can lead to remote code execution (RCE) within the application's runtime environment, allowing the attacker to manipulate backend resources, access sensitive data, or even pivot deeper into the network. Given that the application forms a critical component of Acme Corp’s infrastructure, a successful exploit could result in substantial operational disruption, data compromise, and long-term reputational and financial damage.


context: java.lang.security.audit.object-deserialization.object-deserialization Found object deserialization using ObjectInputStream. Deserializing entire Java objects is dangerous because malicious actors can create Java object streams with unintended consequences. Ensure that the objects being deserialized are not user-controlled. If this must be done, consider using HMACs to sign the data stream to make sure it is not tampered with, or consider only transmitting object fields and populating a new object.

# Vulnerability Breakdown
This vulnerability involves unsafe Java object deserialization in an enterprise web application, creating a high-severity remote code execution risk.

1. **Key vulnerability elements**:
   - Direct use of `ObjectInputStream` to deserialize user-controlled data from HTTP requests
   - No validation, type checking, or integrity verification of incoming serialized objects
   - Lack of filtering or whitelisting of classes that can be deserialized
   - Processing of untrusted data in a high-privilege context (server-side application)
   - Potential for gadget chain exploitation through application classpath dependencies

2. **Potential attack vectors**:
   - Crafting malicious serialized Java objects containing known gadget chains
   - Sending specially crafted HTTP POST requests to the vulnerable endpoint
   - Leveraging common Java libraries present in the classpath (e.g., Apache Commons Collections)
   - Chaining serialized objects to achieve arbitrary code execution
   - Using existing exploitation frameworks like ysoserial to generate attack payloads

3. **Severity assessment**:
   - High confidentiality impact through potential access to sensitive application data
   - High integrity impact through ability to modify application behavior and data
   - High availability impact through potential to crash the application or execute denial of service
   - Network-based attack vector making it remotely exploitable
   - High complexity exploitation requiring specific knowledge of gadget chains and application classpath

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): High (H) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): High (H) 
   - Availability (A): High (H) 

CVSS Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H

# Description
A critical insecure deserialization vulnerability has been identified in Acme Corp's Java-based enterprise application running on Apache Tomcat with Spring Boot. The affected component is a servlet that processes incoming HTTP POST requests by directly deserializing Java objects from the request input stream without any validation or integrity checking.

```java
try (ObjectInputStream ois = new ObjectInputStream(request.getInputStream())) {
    // Vulnerable: Deserializes user-supplied input without validation
    Object data = ois.readObject();
    // Process the deserialized object without type or integrity checks
    processData(data);
}

```

This unsafe deserialization practice allows an attacker to send specially crafted serialized objects that, when processed by the application, can trigger execution chains (gadget chains) leading to remote code execution (RCE). The vulnerability exists because the application blindly trusts and deserializes data directly from the HTTP request without implementing any form of validation, whitelisting, or integrity verification.

As a critical component of Acme Corp's infrastructure, successful exploitation could result in complete system compromise, unauthorized access to sensitive data, lateral movement within internal networks, and significant business disruption.

# CVSS
**Score**: 8.1 \
**Vector**: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H \
**Severity**: High

The High severity rating (CVSS score: 8.1) is justified by the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability is remotely exploitable over HTTP without requiring local access or adjacency to the target network.

- **High Attack Complexity (AC:H)**: Exploitation is complex and requires specialized knowledge. An attacker must:
  1. Identify vulnerable libraries in the application's classpath
  2. Have technical expertise to construct appropriate gadget chains
  3. Understand JVM internals and serialization mechanisms
  4. Navigate potential protections like security managers or classloaders
  5. Create precisely crafted payloads that will execute in the target environment

- **No Privileges Required (PR:N)**: The vulnerable endpoint is accessible without authentication, allowing unauthenticated attackers to exploit the vulnerability.

- **No User Interaction (UI:N)**: The attack can be fully automated without requiring any action from users or administrators of the system.

- **Unchanged Scope (S:U)**: While the impact is severe, the vulnerability does not inherently allow the attacker to affect components beyond the vulnerable application's security scope.

- **High Confidentiality Impact (C:H)**: Successful exploitation gives attackers access to all data handled by the application, potentially including sensitive business information and user credentials.

- **High Integrity Impact (I:H)**: Attackers can modify data, inject malicious code, and potentially alter the application's behavior completely.

- **High Availability Impact (A:H)**: The vulnerability allows attackers to crash the application, execute denial of service conditions, or otherwise render the service unavailable.

The reduction from Critical to High severity (from 9.8 to 8.1) reflects the complex nature of successfully exploiting Java deserialization vulnerabilities, which requires substantial technical expertise and knowledge of the specific application environment.

# Exploitation Scenarios
**Scenario 1: Remote Code Execution via Commons Collections**
An attacker discovers that the application has Apache Commons Collections in its classpath. Using the ysoserial tool, they generate a malicious serialized object that leverages the Commons Collections gadget chain. The attacker crafts an HTTP POST request containing this payload to the vulnerable `/deserialize` endpoint. When the server deserializes this object, it triggers the embedded gadget chain, resulting in arbitrary command execution. The attacker uses this to launch a reverse shell, gaining interactive access to the server's operating system with the privileges of the Tomcat process.

**Scenario 2: Data Exfiltration Attack**
An attacker creates a serialized object that, when deserialized, establishes a connection to their command and control server. The payload is designed to search for and exfiltrate sensitive configuration files, database credentials, and business data. Using the vulnerable deserialization endpoint, they deploy this payload, allowing them to silently extract critical data over time without disrupting services, making detection more difficult.

**Scenario 3: Persistent Backdoor Installation**
An attacker exploits the vulnerability to execute commands that modify the application's startup scripts or deploy additional malicious components. This creates a persistent backdoor that survives application restarts or updates. The attacker uses this backdoor to maintain long-term access to the system, potentially installing additional malware, moving laterally within the network, or conducting reconnaissance activities to identify higher-value targets within the organization's infrastructure.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive business data, including financial information, customer records, and intellectual property
- Potential compliance violations and regulatory penalties if personal data is compromised (GDPR, CCPA, etc.)
- Operational disruption if attackers manipulate or disable critical business processes
- Reputational damage and loss of customer trust if a breach is disclosed or discovered
- Financial losses from business interruption, incident response costs, forensic investigation, and potential legal liabilities
- Possible ransomware deployment utilizing the initial RCE vulnerability as an entry point

**Technical Impact:**
- Complete compromise of the application server environment (confidentiality, integrity, availability)
- Access to application secrets, configuration files, and credentials stored in the application context
- Potential lateral movement to other systems using compromised credentials or trust relationships
- Data theft, modification, or deletion affecting database integrity and application reliability
- Installation of persistent backdoors allowing ongoing unauthorized access
- Potential for supply chain attacks if the compromised application is part of a larger ecosystem
- Infrastructure misuse for cryptocurrency mining, botnet participation, or as a launching point for attacks on other systems

# Technical Details
The vulnerability exists in the `DeserializationServlet` class that processes incoming HTTP POST requests. The core issue is the direct use of Java's native deserialization mechanism via `ObjectInputStream` without any security controls:

```java
public class DeserializationServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        try (ObjectInputStream ois = new ObjectInputStream(request.getInputStream())) {
            // Vulnerable: Deserializes user-supplied input without validation
            Object data = ois.readObject();
            // Process the deserialized object without type or integrity checks
            processData(data);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private void processData(Object data) {
        // Business logic processing the deserialized object
    }
}

```

**Key Vulnerability Factors:**

1. **Unsafe Deserialization Pattern**: The code directly deserializes data from the HTTP request input stream without any validation, filtering, or integrity verification.

2. **No Type Safety**: The code accepts any serialized Java object rather than expecting specific known classes, allowing attackers to introduce arbitrary object types.

3. **Exception Handling**: The broad catch block for `Exception` with only `printStackTrace()` means that deserialization attempts that fail might not be properly logged or monitored.

4. **Gadget Chain Exploitation**: Java deserialization vulnerabilities rely on "gadget chains" - sequences of method calls triggered during deserialization that ultimately lead to malicious actions. Common libraries like Apache Commons Collections, Spring, and certain Groovy components contain gadgets that can be exploited.

**Exploitation Mechanics:**

1. An attacker identifies the vulnerable endpoint through reconnaissance or source code review.

2. They determine which potentially exploitable libraries exist in the application's classpath.

3. Using tools like ysoserial, they generate a serialized object payload that leverages a gadget chain present in the application's dependencies.

4. The attacker sends this payload in an HTTP POST request to the vulnerable servlet.

5. When the application deserializes the payload using `ObjectInputStream.readObject()`, the malicious object's `readObject()` method is invoked, triggering the gadget chain.

6. This leads to execution of arbitrary code within the context of the application server process.

**Technical Impact Vectors:**

- **Code Execution**: The immediate impact is arbitrary code execution within the JVM context.
- **Command Execution**: Many gadget chains allow OS command execution with the privileges of the application server user.
- **File System Access**: Attackers can read sensitive files or write malicious ones to achieve persistence.
- **Network Connections**: Malicious code can establish outbound connections for data exfiltration or command and control.
- **Memory Access**: Access to the JVM's memory space may expose sensitive data loaded by other parts of the application.

# Remediation Steps
## Implement Serialization Filter or Replace with Safe Alternative

**Priority**: P0

The most critical immediate fix is to either implement Java's serialization filtering mechanism or replace native Java deserialization entirely with a safer alternative:

**Option 1: Use Java Serialization Filters (for Java 8u121+ or higher)**

```java
import java.io.ObjectInputStream;
import java.io.InvalidClassException;

public class DeserializationServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Create filtered input stream
            ObjectInputStream ois = new ObjectInputStream(request.getInputStream()) {
                @Override
                protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
                    // Reject dangerous classes and packages
                    String className = desc.getName();
                    if (className.startsWith("org.apache.commons.collections") ||
                        className.startsWith("java.lang.Runtime") ||
                        className.startsWith("java.lang.ProcessBuilder")) {
                        throw new InvalidClassException("Unauthorized deserialization attempt", className);
                    }
                    
                    // Whitelist approach (even safer)
                    if (!className.startsWith("com.acmecorp.model.")) {
                        throw new InvalidClassException("Only com.acmecorp.model classes allowed", className);
                    }
                    
                    return super.resolveClass(desc);
                }
            };
            
            // Deserialize with filters in place
            Object data = ois.readObject();
            
            // Process only if it's an expected type
            if (data instanceof com.acmecorp.model.Message) {
                processData((com.acmecorp.model.Message) data);
            } else {
                throw new SecurityException("Unexpected object type");
            }
        } catch (Exception ex) {
            // Log properly and return error response
            logger.error("Deserialization failed", ex);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid data format");
        }
    }
}

```

**Option 2: Replace with JSON/XML Serialization**

```java
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

public class DeserializationServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Configure secure ObjectMapper with whitelist
            ObjectMapper mapper = JsonMapper.builder()
                .activateDefaultTyping(
                    BasicPolymorphicTypeValidator.builder()
                        .allowIfBaseType(com.acmecorp.model.Message.class)
                        .build(), 
                    ObjectMapper.DefaultTyping.JAVA_LANG_OBJECT)
                .build();
            
            // Deserialize from JSON instead of binary Java serialization
            com.acmecorp.model.Message data = mapper.readValue(
                request.getInputStream(), 
                com.acmecorp.model.Message.class);
            
            // Process the safely deserialized object
            processData(data);
        } catch (Exception ex) {
            logger.error("Deserialization failed", ex);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid data format");
        }
    }
}

```

Both approaches significantly reduce the attack surface by either strictly filtering allowed classes or replacing Java deserialization entirely with safer alternatives like JSON.
## Implement HMAC Validation for Serialized Data

**Priority**: P1

If Native Java deserialization must be used, implement cryptographic verification of serialized data using HMAC:

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class DeserializationServlet extends HttpServlet {
    private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
    private static final byte[] HMAC_KEY = getSecretKeyFromSecureStorage(); // Implement secure key retrieval
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Get HMAC signature from header
            String expectedSignature = request.getHeader("X-Data-Signature");
            if (expectedSignature == null || expectedSignature.isEmpty()) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing data signature");
                return;
            }
            
            // Read the entire request body for verification
            byte[] requestBody = readAllBytes(request.getInputStream());
            
            // Verify HMAC signature before deserialization
            if (!verifySignature(requestBody, expectedSignature)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid data signature");
                logger.warn("Attempted deserialization with invalid signature");
                return;
            }
            
            // Only deserialize after verification
            ByteArrayInputStream bais = new ByteArrayInputStream(requestBody);
            ObjectInputStream ois = new FilteredObjectInputStream(bais); // Use with filters from P0
            Object data = ois.readObject();
            
            // Type checking
            if (data instanceof com.acmecorp.model.Message) {
                processData((com.acmecorp.model.Message) data);
            } else {
                throw new SecurityException("Unexpected object type");
            }
            
        } catch (Exception ex) {
            logger.error("Secure deserialization failed", ex);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid data format");
        }
    }
    
    private boolean verifySignature(byte[] data, String expectedSignature) {
        try {
            Mac hmac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
            SecretKeySpec secretKey = new SecretKeySpec(HMAC_KEY, HMAC_SHA256_ALGORITHM);
            hmac.init(secretKey);
            byte[] calculatedHmac = hmac.doFinal(data);
            String calculatedSignature = Base64.getEncoder().encodeToString(calculatedHmac);
            
            return calculatedSignature.equals(expectedSignature);
        } catch (Exception ex) {
            logger.error("HMAC verification failed", ex);
            return false;
        }
    }
    
    private byte[] readAllBytes(InputStream is) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int nRead;
        byte[] data = new byte[16384];
        
        while ((nRead = is.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }
        
        return buffer.toByteArray();
    }
}

```

This approach ensures that only data created by trusted sources (with access to the HMAC key) can be deserialized. This should be combined with the serialization filtering from P0 for defense in depth.


# References
* CWE-502 | [Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
* CWE-94 | [Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A08:2021 | [Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
