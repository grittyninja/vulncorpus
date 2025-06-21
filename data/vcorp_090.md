# XXE Vulnerability in Java XML Parser Configuration

# Vulnerability Case
During our assessment of Acme Corp's enterprise Java application, we identified that its XML parsing component, implemented with Java's built-in parser (commonly used within frameworks like Spring Boot deployed on Apache Tomcat), was not securely configured. The parser neglected to disable external DTDs and entity resolution, allowing user-controlled XML inputs to process potentially malicious DTDs. This vulnerability was uncovered during source code analysis and confirmed by sending crafted XML payloads to an API endpoint that processes XML data. The lack of configuration safeguards renders the application susceptible to XML External Entity (XXE) attacks, which can cascade into more severe vulnerabilities such as LFI, SSRF, RCE, or even DoS via entity expansion.


```java
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.InputSource;
import org.w3c.dom.Document;
import java.io.StringReader;

public class VulnerableXMLProcessor {
    public Document parseXml(String xmlInput) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // Vulnerable configuration: External entity processing is not disabled
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new InputSource(new StringReader(xmlInput)));
    }
}
```

The uncovered vulnerability stems from failing to set secure parser configurations, such as disabling the processing of external DTDs via `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`.


context: java.lang.security.xxe.xmlreader-xxe.xmlreader-xxe The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a Billion Laughs Attack. It is our recommendation to secure this parser against XXE attacks by configuring $FACTORY with `$PARSER.setFeature(http://apache.org/xml/features/disallow-doctype-decl, true)`. Alternatively, the following configurations also provide protection against XXE attacks. `$PARSER.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "")` `$PARSER.setFeature("http://xml.org/sax/features/external-general-entities", false)`. For more information, see: [Java XXE prevention](https://semgrep.dev/docs/cheat-sheets/java-xxe/)

# Vulnerability Breakdown
This vulnerability involves an insecurely configured XML parser in Acme Corp's enterprise Java application that enables XML External Entity (XXE) attacks.

1. **Key vulnerability elements**:
   - XML parser allows processing of external DTDs and entity resolution
   - DocumentBuilderFactory lacks secure configuration settings
   - User-controlled XML input is processed without validation
   - Missing critical security features like disabling external entity processing
   - Vulnerability exists in a framework commonly used in enterprise environments (Spring Boot/Tomcat)

2. **Potential attack vectors**:
   - Submitting specially crafted XML with malicious external entity references
   - Exploiting DTD processing to access local files (Local File Inclusion)
   - Leveraging XXE for Server-Side Request Forgery (SSRF)
   - Using recursive entity expansion to cause Denial of Service
   - Potentially achieving Remote Code Execution depending on system configuration

3. **Severity assessment**:
   - High confidentiality impact through ability to read sensitive files
   - Low integrity impact through potential system manipulation via SSRF
   - Low availability impact through potential DoS attacks (billion laughs)
   - Network-based attack vector allowing remote exploitation
   - Low complexity to exploit with widely available attack tools

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): High (H) 
   - Integrity (I): Low (L) 
   - Availability (A): Low (L) 

# Description
An XML External Entity (XXE) vulnerability has been discovered in Acme Corp's enterprise Java application. The vulnerability exists in the XML parsing component that uses Java's built-in DocumentBuilderFactory without proper security configurations. Specifically, the application fails to disable the processing of external Document Type Definitions (DTDs) and external entities, making it susceptible to XXE attacks when processing user-controlled XML input.

```java
public Document parseXml(String xmlInput) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    // Vulnerable configuration: External entity processing is not disabled
    DocumentBuilder builder = factory.newDocumentBuilder();
    return builder.parse(new InputSource(new StringReader(xmlInput)));
}

```

This vulnerability can lead to multiple security issues including Local File Inclusion (LFI), Server-Side Request Forgery (SSRF), potential Remote Code Execution (RCE), and Denial of Service (DoS) through entity expansion attacks (also known as Billion Laughs attacks). An attacker can craft malicious XML payloads that reference external entities, potentially allowing them to read sensitive files from the server, make the server initiate connections to internal resources, or exhaust system resources.

# CVSS
**Score**: 8.6 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L \
**Severity**: High

The High severity rating (8.6) is justified by the following factors:

- **Network attack vector (AV:N)**: The vulnerability can be exploited remotely by sending malicious XML to the application's API endpoint.

- **Low attack complexity (AC:L)**: Exploiting XXE vulnerabilities requires only basic knowledge of XML and entity references. There are numerous tools and payloads available that simplify exploitation.

- **No privileges required (PR:N)**: Any unauthenticated user who can send XML to the parsing endpoint can exploit this vulnerability.

- **No user interaction required (UI:N)**: The vulnerability can be triggered by directly sending malicious XML to the application, without any action needed from other users.

- **Unchanged scope (S:U)**: The vulnerability impacts only the vulnerable component and its containing system.

- **High confidentiality impact (C:H)**: XXE allows attackers to read arbitrary files accessible to the application process, potentially including sensitive configuration files, credentials, and other confidential data.

- **Low integrity impact (I:L)**: While XXE primarily affects confidentiality, SSRF capabilities enabled by XXE could potentially lead to limited data modification through interaction with internal systems.

- **Low availability impact (A:L)**: XML entity expansion attacks (Billion Laughs) can cause resource exhaustion and denial of service conditions, though modern systems often have some mitigations against extreme resource consumption.

# Exploitation Scenarios
**Scenario 1: Local File Disclosure**
An attacker submits the following XML payload to the API endpoint that processes XML:

```xml
<!DOCTYPE test [ 
  <!ENTITY xxe SYSTEM "file:///etc/passwd"> 
]>
<root>
  <data>&xxe;</data>
</root>

```

When the vulnerable XML processor parses this input, it resolves the external entity reference to `/etc/passwd` and includes the content of this file in the response. This allows the attacker to read sensitive system files accessible to the application process.

**Scenario 2: Server-Side Request Forgery**
An attacker exploits the XXE vulnerability to make the server initiate connections to internal systems:

```xml
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://internal-service.local:8080/admin/users">
]>
<root>
  <data>&xxe;</data>
</root>

```

This payload causes the server to make an HTTP request to an internal service, potentially accessing resources that should only be available within the internal network. The response from the internal service might be returned to the attacker, allowing them to map the internal network and access restricted services.

**Scenario 3: Denial of Service via Entity Expansion**
An attacker sends a "Billion Laughs" attack payload designed to exhaust server resources:

```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>

```

When parsed, this XML causes exponential entity expansion, potentially consuming all available memory and CPU resources, leading to a denial of service condition.

# Impact Analysis
**Business Impact:**
- Potential data breaches leading to exposure of sensitive customer information and intellectual property
- Regulatory compliance violations (GDPR, CCPA, etc.) if personal data is compromised
- Financial losses from remediation costs, potential fines, and business disruption
- Reputational damage affecting customer trust and business relationships
- Legal liability from failure to implement standard security controls
- Extended incident response efforts to identify what data may have been compromised

**Technical Impact:**
- Unauthorized access to sensitive configuration files, including database credentials, API keys, and other secrets
- Ability to read internal system files containing potentially sensitive information
- Server-Side Request Forgery enabling attackers to probe and interact with internal systems
- Potential for privilege escalation if sensitive credential information is exposed
- Denial of service through resource exhaustion affecting application availability
- Possible lateral movement throughout internal infrastructure if internal network details are exposed
- Undermined integrity of the application's security architecture
- Additional attack surface for secondary exploitation attempts

# Technical Details
The vulnerability exists in the `VulnerableXMLProcessor` class which implements XML parsing without proper security configurations:

```java
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.InputSource;
import org.w3c.dom.Document;
import java.io.StringReader;

public class VulnerableXMLProcessor {
    public Document parseXml(String xmlInput) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // Vulnerable configuration: External entity processing is not disabled
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new InputSource(new StringReader(xmlInput)));
    }
}

```

The root cause is the failure to configure the XML parser securely. By default, Java's DocumentBuilderFactory enables the processing of external DTDs and entity references, which should be explicitly disabled in security-sensitive applications.

**How XXE Attacks Work:**

XML allows the definition of entities via Document Type Definitions (DTDs). These entities can reference external resources using the SYSTEM keyword:

```xml
<!DOCTYPE foo [
  <!ENTITY ext SYSTEM "http://example.com/file.txt">
]>
<foo>&ext;</foo>

```

When processed by a vulnerable parser, the XML processor will:

1. Encounter the DOCTYPE declaration and process the DTD
2. Parse the entity declaration for "ext" which references an external resource
3. Fetch the content from the specified URI (file, HTTP, etc.)
4. Replace the entity reference (&ext;) with the fetched content

This behavior enables various attack vectors:

1. **File access**: Using the `file://` protocol to read local files
2. **SSRF**: Using HTTP/HTTPS protocols to make the server issue requests
3. **DoS**: Using recursive entity definitions to cause resource exhaustion

**Parser Behavior:**

Java's DocumentBuilderFactory creates parsers with these default settings:
- External DTD processing: Enabled
- External general entities: Enabled
- External parameter entities: Enabled

These default settings prioritize compatibility over security, making parsers vulnerable to XXE attacks unless explicitly configured otherwise.

# Remediation Steps
## Disable DTD Processing

**Priority**: P0

The most effective and straightforward remediation is to completely disable DTD processing in the XML parser:

```java
public Document parseXml(String xmlInput) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    
    // Disable DTD processing, which prevents external entity references
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    
    DocumentBuilder builder = factory.newDocumentBuilder();
    return builder.parse(new InputSource(new StringReader(xmlInput)));
}

```

This approach eliminates XXE vulnerabilities by preventing the processing of any DOCTYPE declarations, effectively disabling both internal and external entity processing. This is the recommended approach for most applications that don't require DTD processing.
## Comprehensive XML Parser Hardening

**Priority**: P1

If DTD processing is required for application functionality, implement a more comprehensive set of security configurations to disable only the dangerous features:

```java
public Document parseXml(String xmlInput) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    
    // Disable external entity processing
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    
    // Disable entity expansion
    factory.setExpandEntityReferences(false);
    
    // Limit entity expansion (for JDK >= 7)
    factory.setXIncludeAware(false);
    
    // Prohibit the use of all protocols by external entities (JDK >= 7u67, JDK >= 8u20)
    factory.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD, "");
    factory.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    
    // Create the builder with enhanced security features
    DocumentBuilder builder = factory.newDocumentBuilder();
    
    // Optionally add a custom EntityResolver to prevent external entity resolution
    builder.setEntityResolver((publicId, systemId) -> new InputSource(new StringReader("")));
    
    return builder.parse(new InputSource(new StringReader(xmlInput)));
}

```

This approach provides defense-in-depth by disabling multiple aspects of external entity processing, which is more robust against parser implementation variations and potential bypass techniques.


# References
* CWE-611 | [Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
* A04:2021 | [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
* A03:2021 | [Injection](https://owasp.org/Top10/A03_2021-Injection/)
* CWE-776 | [Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')](https://cwe.mitre.org/data/definitions/776.html)
* CWE-918 | [Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
