# Information Disclosure via Stack Trace Exposure in Production

# Vulnerability Case
During a routine security assessment of Acme Corp's ASP.NET Core web API, we discovered that detailed stack trace information was inadvertently displayed to end users in the production environment. This was uncovered when simulating error states, where an exception triggered the display of sensitive internal data—such as file paths, method names, and line numbers—directly on the error page. The investigation revealed that the error handling configuration was misapplied, using development settings in production. This misconfiguration exposes internal application logic, significantly aiding threat actors in reconnaissance for further exploitation. The affected system relies on the .NET Core framework hosted on IIS, a common stack in enterprise environments.

```csharp
public void Configure(IApplicationBuilder app, IHostingEnvironment env)
{
    if (env.IsDevelopment())
    {
        app.UseDeveloperExceptionPage();
    }
    else
    {
        // Vulnerability: Incorrectly using the Developer Exception Page in production
        // which discloses detailed stack trace information to end users.
        app.UseDeveloperExceptionPage();
        
        // Alternatively, a misconfigured global exception handler:
        /*
        app.UseExceptionHandler(errorApp =>
        {
            errorApp.Run(async context =>
            {
                context.Response.StatusCode = 500;
                context.Response.ContentType = "text/plain";
                var exceptionHandlerFeature =
                    context.Features.Get<IExceptionHandlerFeature>();
                if (exceptionHandlerFeature != null)
                {
                    // Inappropriate disclosure of exception details in production
                    await context.Response.WriteAsync(
                        exceptionHandlerFeature.Error.ToString());
                }
            });
        });
        */
    }

    app.UseMvc();
}
```

The vulnerability arises from the improper use of development-level exception handling in a production setting, which reveals extensive debugging information through stack traces. Attackers can exploit this disclosure by deliberately triggering errors—via malformed requests or unexpected inputs—to collect sensitive internal configuration data and execution paths, thereby mapping the application's architecture. This reconnaissance can fuel targeted attacks, including privilege escalation or injection of crafted payloads, ultimately compromising sensitive corporate data and undermining system integrity. Such exposure significantly increases the attack surface and can lead to both reputational and financial losses for the business.

context: csharp.lang.security.stacktrace-disclosure.stacktrace-disclosure Stacktrace information is displayed in a non-Development environment. Accidentally disclosing sensitive stack trace information in a production environment aids an attacker in reconnaissance and information gathering.

# Vulnerability Breakdown
This vulnerability involves the improper configuration of error handling in an ASP.NET Core web API, causing detailed stack traces to be exposed to end users in a production environment.

1. **Key vulnerability elements**:
   - Development-level exception handling enabled in production environment
   - Detailed stack traces containing file paths, method names, and line numbers exposed to users
   - Internal application logic and structure revealed through error messages
   - ASP.NET Core application hosted on IIS with misconfigured error handling

2. **Potential attack vectors**:
   - Deliberate triggering of errors through malformed requests
   - Reconnaissance by analyzing exposed stack traces
   - Mapping of application architecture through error information
   - Targeted attacks based on internal implementation details

3. **Severity assessment**:
   - The vulnerability primarily impacts confidentiality through information disclosure
   - No direct impact on integrity or availability
   - Attack vector is network-based (remotely exploitable)
   - Low complexity to exploit (simply trigger errors)
   - No privileges required to exploit

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): None (N) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): Low (L) 
   - Integrity (I): None (N) 
   - Availability (A): None (N) 

# Description
A security vulnerability was identified in Acme Corp's ASP.NET Core web API running in production, where detailed stack trace information is inappropriately disclosed to end users when errors occur. This misconfiguration exposes sensitive internal details including file paths, method names, line numbers, and potentially database structure, significantly assisting attackers in reconnaissance and targeted exploitation efforts.

The root cause is a configuration error in the application's startup code, where `app.UseDeveloperExceptionPage()` is incorrectly called in both development and production environments, when it should only be used during development. This developer-oriented error page reveals extensive debugging information that provides attackers with valuable insights into the application's internal structure and potential vulnerabilities.

# CVSS
**Score**: 5.3 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N \
**Severity**: Medium

The Medium severity rating is based on a calculated CVSS score of 5.3, derived from the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability is exploitable remotely by anyone who can send requests to the web API
- **Low Attack Complexity (AC:L)**: Exploitation is straightforward and requires minimal effort; an attacker simply needs to trigger errors
- **No Privileges Required (PR:N)**: No authentication or authorization is needed to exploit the vulnerability
- **No User Interaction (UI:N)**: The vulnerability can be exploited without any action from legitimate users
- **Unchanged Scope (S:U)**: The vulnerability impacts only the vulnerable component itself
- **Low Confidentiality Impact (C:L)**: While sensitive implementation details are exposed, direct access to credentials or PII is not granted
- **No Integrity Impact (I:N)**: The vulnerability does not allow modification of system data
- **No Availability Impact (A:N)**: The vulnerability does not impact system availability

While this vulnerability doesn't directly lead to system compromise, it significantly aids reconnaissance and can enable more targeted attacks, making it a serious security concern that should be addressed promptly.

# Exploitation Scenarios
**Scenario 1: Application Mapping and Reconnaissance**
An attacker systematically sends malformed requests (invalid parameters, out-of-range values, special characters) to the API endpoints to intentionally trigger errors. Each error reveals detailed stack traces containing file paths, method names, class structures, and line numbers. By collecting and analyzing these traces, the attacker builds a comprehensive map of the application's internal architecture, identifying potential weak points and attack surfaces. This information allows for more precise and targeted attacks against specific components.

**Scenario 2: Framework and Library Enumeration**
By analyzing the stack traces, an attacker identifies the exact versions of frameworks and libraries used by the application. The attacker then researches known vulnerabilities in these specific versions and crafts exploits targeting these vulnerabilities. For example, discovering the application uses an outdated JSON parsing library with a known deserialization vulnerability would allow the attacker to craft a specific payload exploiting that vulnerability.

**Scenario 3: SQL Injection Refinement**
An attacker attempts basic SQL injection attacks against the API's data endpoints. While initial attempts fail, the detailed stack traces reveal the exact SQL query structure, parameter names, and database schema details. This information allows the attacker to refine their injection techniques, crafting payload variations specifically tailored to the application's exact query structure, significantly increasing the likelihood of a successful SQL injection attack.

# Impact Analysis
**Business Impact:**
- Increased vulnerability to targeted attacks due to exposed implementation details
- Potential regulatory non-compliance (many standards prohibit information disclosure)
- Reduced customer confidence if technical error details are visible to end users
- Possible intellectual property concerns if proprietary algorithms or business logic are exposed
- Risk of follow-up attacks leveraging the disclosed information, potentially leading to data breaches

**Technical Impact:**
- Exposure of internal file paths and directory structures enabling server mapping
- Disclosure of method names and code organization revealing application architecture
- Potential exposure of database schema, table names, and query structures
- Revelation of third-party libraries and their versions, enabling targeted attacks against known vulnerabilities
- Disclosure of internal API endpoints not intended for public use
- Simplified attack surface mapping for malicious actors
- Enhanced ability for attackers to craft precisely targeted exploits

# Technical Details
The vulnerability stems from a misconfiguration in the ASP.NET Core application's startup code, specifically in the error handling pipeline configuration. In ASP.NET Core, different error handling middleware should be used depending on the environment:

```csharp
public void Configure(IApplicationBuilder app, IHostingEnvironment env)
{
    if (env.IsDevelopment())
    {
        app.UseDeveloperExceptionPage();
    }
    else
    {
        // Vulnerability: Incorrectly using the Developer Exception Page in production
        // which discloses detailed stack trace information to end users.
        app.UseDeveloperExceptionPage(); // THIS LINE SHOULD NOT BE HERE
        
        // Should use this instead:
        // app.UseExceptionHandler("/Error");
        // app.UseHsts();
    }

    app.UseMvc();
}

```

The `UseDeveloperExceptionPage()` middleware is specifically designed for development environments and captures exceptions during the request pipeline, generating HTML pages with detailed error information including:

1. **Full stack trace** with method call hierarchy
2. **Source code snippets** around the error location (if source is available)
3. **Query string parameters** and form values
4. **Cookies and headers** from the request
5. **Route data** and other request details

When an exception occurs in production with this configuration, instead of showing a generic error page, the application reveals these detailed internals to anyone who can trigger an error.

The vulnerability is particularly concerning because:

1. It's trivial to exploit - simply sending malformed requests that cause exceptions
2. It requires no authentication or special privileges
3. It reveals information across the entire application, not just specific components
4. The information disclosed is highly valuable for planning more sophisticated attacks

Examples of sensitive information that might be exposed include:

- Physical file paths: `c:\inetpub\wwwroot\AcmeApp\Controllers\UserController.cs:line 127`
- Method signatures: `at AcmeApp.Services.AuthenticationService.ValidateToken(String token, Int32 userId)`
- Database details: `System.Data.SqlClient.SqlException: Invalid column name 'user_role_id'`
- Framework versions: Stack frames showing exact versions of dependencies

# Remediation Steps
## Implement Proper Production Error Handling

**Priority**: P0

Remove the developer exception page from the production environment and implement appropriate error handling:

```csharp
public void Configure(IApplicationBuilder app, IHostingEnvironment env)
{
    if (env.IsDevelopment())
    {
        app.UseDeveloperExceptionPage();
    }
    else
    {
        // Use production-appropriate error handling
        app.UseExceptionHandler("/Error");
        app.UseHsts();
    }
    
    app.UseMvc();
}

```

This change ensures that production errors are handled by a generic error page that doesn't reveal implementation details. The `/Error` endpoint should display a user-friendly message without technical details. Additionally, implement HSTS (HTTP Strict Transport Security) as a security best practice for production environments.
## Implement Comprehensive Error Handling Strategy

**Priority**: P1

Develop a robust error handling strategy that properly logs errors while presenting appropriate information to users:

```csharp
public void Configure(IApplicationBuilder app, IHostingEnvironment env)
{
    if (env.IsDevelopment())
    {
        app.UseDeveloperExceptionPage();
    }
    else
    {
        app.UseExceptionHandler(errorApp =>
        {
            errorApp.Run(async context =>
            {
                var exceptionHandlerPathFeature = context.Features.Get<IExceptionHandlerPathFeature>();
                var exception = exceptionHandlerPathFeature?.Error;
                
                // Log the error (with full details) for internal use
                _logger.LogError(exception, "An unhandled exception occurred");
                
                // Return a generic error response to the user
                context.Response.StatusCode = 500;
                context.Response.ContentType = "application/json";
                
                await context.Response.WriteAsync(JsonConvert.SerializeObject(new {
                    error = "An unexpected error occurred. Please try again later.",
                    reference = Activity.Current?.Id ?? context.TraceIdentifier
                }));
            });
        });
        
        app.UseHsts();
    }
    
    app.UseStatusCodePagesWithReExecute("/Error/{0}");
    app.UseMvc();
}

```

This implementation:
1. Logs detailed exception information securely for debugging and monitoring
2. Returns a generic error message to users with a reference ID
3. Maintains the correlation between user-facing error references and detailed internal logs
4. Handles HTTP status code errors with custom error pages


# References
* CWE-209 | [Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
* CWE-200 | [Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
* A05:2021 | [Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
* A09:2021 | [Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)
* CWE-497 | [Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)
