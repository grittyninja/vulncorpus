# XML External Entity (XXE) Injection in ASP.NET Core Application

# Vulnerability Case
During the recent vulnerability assessment of Acme Corp's ASP.NET Core application, our security team discovered that the XML processing module improperly configured the built-in .NET XML parser, leaving Document Type Definition (DTD) processing enabled. The flaw was identified during a combined effort of dynamic testing and source code review and involves the direct loading of user-controlled XML via .NET’s `XmlDocument` without disabling external entity resolution. This misconfiguration allows attackers to introduce malicious DTDs or XInclude directives, potentially exploiting the service via XML External Entity (XXE) attacks to perform Local File Inclusion (LFI), Server-Side Request Forgery (SSRF), or resource exhaustion attacks (DoS) or even remote code execution under certain conditions. The vulnerable endpoint is implemented in C# on the ASP.NET Core 3.1 stack, a technology widely used in modern enterprise applications.  

```csharp
using Microsoft.AspNetCore.Mvc;
using System.Xml;

namespace AcmeCorp.Api.Controllers
{
    [ApiController]
    [Route("api/xml")]
    public class XmlController : ControllerBase
    {
        [HttpPost("process")]
        public IActionResult ProcessXml([FromBody] string xmlContent)
        {
            try
            {
                var doc = new XmlDocument();
                // Vulnerable configuration: DTD processing is not disabled,
                // allowing potential external entity resolution.
                doc.LoadXml(xmlContent);
                
                // Subsequent processing of the XML document...
                return Ok("XML processed successfully.");
            }
            catch (XmlException)
            {
                return BadRequest("Invalid XML content.");
            }
        }
    }
}
```

Exploitation of this vulnerability typically involves crafting XML payloads with a malicious DOCTYPE declaration that references external entities. An attacker can construct such an XML file to reference sensitive server files (e.g., system configuration files or password repositories) or invoke internal network services, effectively using the XML parser as a proxy (SSRF). Moreover, recursive entity expansion—popularly known as the Billion Laughs attack—could be used to exhaust server resources, leading to a denial-of-service (DoS) condition. The business impact is significant, potentially leading to unauthorized data disclosure, service outages, and limited integrity impacts through indirect data manipulation and, in a worst-case scenario, remote code execution that jeopardizes the integrity of the entire application environment.  

context: csharp.dotnet-core.xxe.xml-dtd-allowed.xml-dtd-allowed The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) or XIncludes which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a `Billion Laughs Attack`. The best defense against XXE is to have an XML parser that supports disabling DTDs. Limiting the use of external entities from the start can prevent the parser from being used to process untrusted XML files. Reducing dependencies on external resources is also a good practice for performance reasons. It is difficult to guarantee that even a trusted XML file on your server or during transmission has not been tampered with by a malicious third-party.

# Vulnerability Breakdown
This vulnerability involves a classic XML External Entity (XXE) injection flaw in Acme Corp's ASP.NET Core application where the XML parser is improperly configured with DTD processing enabled.

1. **Key vulnerability elements**:
   - XmlDocument is used without disabling external entity resolution
   - Direct processing of user-controlled XML input
   - Missing configuration for secure XML parsing
   - Implementation in ASP.NET Core 3.1 technology stack
   - Exposed API endpoint accepting XML content from users

2. **Potential attack vectors**:
   - Injection of DOCTYPE declarations with malicious external entities
   - References to local system files for unauthorized data access
   - References to internal network resources enabling SSRF attacks
   - Entity expansion for resource exhaustion (Billion Laughs attack)
   - XInclude injection to incorporate unauthorized content

3. **Severity assessment**:
   - High confidentiality impact through access to sensitive files
   - Low integrity impact through potential data modification
   - Low availability impact through resource exhaustion attacks
   - Network-based attack vector allowing remote exploitation
   - Low complexity to execute with readily available tools

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
An XML External Entity (XXE) vulnerability exists in Acme Corp's ASP.NET Core application due to improper configuration of the built-in XML parser. The application's XML processing module accepts user-provided XML through an API endpoint but fails to disable Document Type Definition (DTD) processing, creating a significant security risk.

The vulnerable code in the XmlController's ProcessXml endpoint directly loads XML content with an XmlDocument object without disabling external entity resolution:

```csharp
[HttpPost("process")]
public IActionResult ProcessXml([FromBody] string xmlContent)
{
    try
    {
        var doc = new XmlDocument();
        // Vulnerable configuration: DTD processing is not disabled,
        // allowing potential external entity resolution.
        doc.LoadXml(xmlContent);
        
        // Subsequent processing of the XML document...
        return Ok("XML processed successfully.");
    }
    catch (XmlException)
    {
        return BadRequest("Invalid XML content.");
    }
}

```

This misconfiguration allows attackers to include malicious DOCTYPE declarations in XML payloads that reference external entities. These entities can point to local files (exposing sensitive system information), internal services (enabling SSRF attacks), or recursive definitions (causing DoS conditions through the Billion Laughs attack).

# CVSS
**Score**: 8.6 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L \
**Severity**: High

The High severity rating (8.6) is justified by the following factors:

- **Network attack vector (AV:N)**: The vulnerability is exploitable remotely through the application's API endpoint, making it accessible to any attacker who can send HTTP requests to the application.

- **Low attack complexity (AC:L)**: Exploiting this vulnerability requires only basic knowledge of XXE attacks and crafting malicious XML payloads, with numerous tools and examples readily available.

- **No privileges required (PR:N)**: The vulnerable endpoint does not require authentication or specific privileges to submit XML content for processing.

- **No user interaction (UI:N)**: The vulnerability can be exploited without any action from legitimate users, as it involves a direct API request to the vulnerable endpoint.

- **Unchanged scope (S:U)**: The impact is limited to the privileges and resources available to the vulnerable component itself, though these effects can be significant.

- **High confidentiality impact (C:H)**: The vulnerability enables access to sensitive files on the system, potentially including configuration files, credentials, and other protected information.

- **Low integrity impact (I:L)**: While direct data modification is limited, the vulnerability could allow partial modification of data through indirect means in some scenarios.

- **Low availability impact (A:L)**: The Billion Laughs attack vector creates a potential for denial of service through resource exhaustion, though this would likely be limited to the XML processing component rather than the entire system.

# Exploitation Scenarios
**Scenario 1: Local File Inclusion**
An attacker submits the following XML payload to the vulnerable endpoint:

```xml
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<test>&xxe;</test>

```

When processed, the XML parser resolves the external entity by reading the contents of /etc/passwd from the server's file system and includes it in the parsed XML document. The application then processes this data, potentially returning it to the attacker or incorporating it into application logic, effectively disclosing sensitive system information.

**Scenario 2: Server-Side Request Forgery (SSRF)**
An attacker crafts an XML payload targeting internal network resources:

```xml
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://internal-network.acmecorp.local/api/sensitive-data">
]>
<test>&xxe;</test>

```

The XML parser resolves this entity by making an HTTP request to the internal network address, which would normally be inaccessible from the outside. This effectively uses the server as a proxy to access internal services, potentially bypassing network segregation and firewall controls.

**Scenario 3: Denial of Service via Billion Laughs Attack**
An attacker submits a specially crafted XML containing recursively defined entities:

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

When the parser attempts to process this XML, it expands the entities recursively, creating billions of "lol" strings and consuming excessive memory and CPU resources. This can lead to a denial of service condition, potentially making the application unresponsive or crashing it entirely.

# Impact Analysis
**Business Impact:**
- Unauthorized access to sensitive configuration data, potentially including database connection strings, API keys, and other credentials
- Exposure of personally identifiable information (PII) or other protected data stored in accessible files
- Regulatory compliance violations if sensitive customer data is exposed (GDPR, CCPA, etc.)
- Service disruption from successful denial of service attacks
- Reputational damage if security breach becomes public
- Financial impact from remediation costs, potential legal actions, and lost business

**Technical Impact:**
- Disclosure of sensitive files (configuration files, credentials, user data)
- Unauthorized access to internal network services through SSRF attacks
- Potential for server compromise if attackers gain access to sensitive configuration information
- Server resource exhaustion through entity expansion attacks
- System instability or crashes from memory consumption
- Information disclosure about application structure and implementation details
- Potential for lateral movement within the network if internal services are compromised
- Possibility of further exploitation by chaining this vulnerability with others

# Technical Details
The vulnerability arises from the improper configuration of the XmlDocument object in the ProcessXml method of the XmlController class. The core issue is that the default configuration of XmlDocument in .NET allows for processing of Document Type Definitions (DTDs) and resolution of external entities.

In the vulnerable code, an XmlDocument is created and directly loads user-provided XML without any security configurations:

```csharp
var doc = new XmlDocument();
doc.LoadXml(xmlContent);

```

When XML containing a DOCTYPE declaration with external entities is processed by this code, the parser will attempt to resolve those entities by:

1. Reading local files if a `file://` URI is specified
2. Making network requests if an `http://` or `https://` URI is specified
3. Expanding recursive entity definitions that can cause exponential resource consumption

For example, when processing XML like:

```xml
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

```

The XmlDocument will:
1. Parse the DOCTYPE declaration
2. Identify the external entity "xxe" with a system identifier "file:///etc/passwd"
3. Resolve this entity by reading the contents of the /etc/passwd file
4. Replace the reference `&xxe;` in the document with the contents of that file

The vulnerability is particularly dangerous because:

1. It can be exploited using standard HTTP requests with malicious XML payloads
2. It doesn't require authentication or special privileges
3. It provides access to files and resources otherwise protected from direct access
4. It can be used to probe internal networks that are normally inaccessible
5. It affects a public API endpoint, increasing the attack surface

The ASP.NET Core 3.1 framework itself provides mechanisms to prevent this vulnerability, but they must be explicitly used. The default behavior of XmlDocument prioritizes compatibility over security, which is why secure configuration is essential when processing untrusted XML.

# Remediation Steps
## Disable External Entity Resolution in XmlDocument

**Priority**: P0

The immediate fix is to explicitly disable external entity resolution in the XmlDocument object:

```csharp
[HttpPost("process")]
public IActionResult ProcessXml([FromBody] string xmlContent)
{
    try
    {
        var doc = new XmlDocument();
        
        // Disable external entity resolution
        doc.XmlResolver = null;
        
        doc.LoadXml(xmlContent);
        
        // Subsequent processing of the XML document...
        return Ok("XML processed successfully.");
    }
    catch (XmlException)
    {
        return BadRequest("Invalid XML content.");
    }
}

```

Setting `XmlResolver = null` prevents the resolution of external entities, effectively blocking XXE attacks while still allowing XML processing. This is the simplest and most direct mitigation for this vulnerability.
## Implement Secure XML Processing with XmlReader

**Priority**: P1

For a more comprehensive solution, replace the direct use of XmlDocument with a properly configured XmlReader:

```csharp
[HttpPost("process")]
public IActionResult ProcessXml([FromBody] string xmlContent)
{
    try
    {
        // Create secure XML reader settings
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            ValidationType = ValidationType.None,
            MaxCharactersFromEntities = 1024,
            MaxCharactersInDocument = 1024 * 1024 // 1MB limit
        };

        // Use StringReader to create input stream from the XML string
        using (var stringReader = new StringReader(xmlContent))
        // Create secure XML reader
        using (var xmlReader = XmlReader.Create(stringReader, settings))
        {
            var doc = new XmlDocument();
            // Load with secure reader instead of direct string loading
            doc.Load(xmlReader);
            
            // Subsequent processing of the XML document...
            return Ok("XML processed successfully.");
        }
    }
    catch (XmlException ex)
    {
        // Log detailed exception internally for troubleshooting
        _logger.LogError(ex, "XML processing error");
        // Return generic message to user
        return BadRequest("Invalid XML content.");
    }
}

```

This implementation:

1. Explicitly prohibits DTD processing with `DtdProcessing.Prohibit`
2. Sets the XML resolver to null, preventing external entity resolution
3. Sets limits on entity expansion and document size to prevent DoS attacks
4. Uses a properly configured XmlReader to load the XmlDocument
5. Implements proper resource disposal with using statements
6. Includes secure error handling that doesn't leak implementation details


# References
* CWE-611 | [Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* CWE-776 | [Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')](https://cwe.mitre.org/data/definitions/776.html)
* A05:2021 | [Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
* A08:2021 | [Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
