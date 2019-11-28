# Secapp
Secapp
https://docs.microsoft.com/en-us/visualstudio/code-quality/ca2102?view=vs-2019

https://ourcodeworld.com/articles/read/1007/what-is-the-billion-laughs-xml-dos-attack-on-the-net-framework-c-sharp-xml-parser

https://subscription.packtpub.com/book/networking_and_servers/9781785284588/5

https://www.geekboy.ninja/blog/tag/flash-csrf/

https://blog.appsecco.com/


# Information Exposure Through an Error Message
The application calls the java.net.URL.openConnection() function, which may expose information about the application logic or other details such as the names and versions of the application container and associated components. This information can be useful in executing other attacks and can also enable the attacker to target known vulnerabilities in application components. openConnection() was called on the (new URL(...)) object, which contains data from an error message (possibly containing untrusted data). The data from an error message (possibly containing untrusted data) originated from earlier calls to java.lang.Throwable.toString, java.lang.Throwable.getMessage, java.io.InvalidClassException.getMessage, and com.fasterxml.jackson.core.JsonProcessingException.getMessage.
Ensure that error codes or other messages returned to end users are not overly verbose. Sanitize all messages of any sensitive information that is not absolutely necessary.

# Cross-Site Scripting
This call to Node.appendChild() contains a cross-site scripting (XSS) flaw. The application populates the HTTP response with untrusted input, allowing an attacker to embed malicious content, such as Javascript code, which will be executed in the context of the victim's browser. XSS vulnerabilities are commonly exploited to steal or manipulate cookies, modify presentation of content, and compromise confidential information, with new attack vectors being discovered on a regular basis.
Use contextual escaping on all untrusted data before using it to construct any portion of an HTTP response. The escaping method should be chosen based on the specific use case of the untrusted data, otherwise it may not protect fully against the attack. For example, if the data is being written to the body of an HTML page, use HTML entity escaping; if the data is being written to an attribute, use attribute escaping; etc. Both the OWASP Java Encoder library and the Microsoft AntiXSS library provide contextual escaping methods. For more details on contextual escaping, see https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md. In addition, as a best practice, always validate untrusted input to ensure that it conforms to the expected format, using centralized data validation routines when possible.
CVE: SRCCLR-SID-3606, Jersey common is vulnerable to billion laugh attacks. These attacks are possible because it does not disable XML Entity Expansion (XEE).

# Handlebars is vulnerable to prototype pollution.
A remote attacker is able to add or modify properties to the Object prototype using a malicious template, potentially allowing execution of arbitrary code.
XML external entity attacks. This vulnerability is similar to CVE-2016-3720 whereby the external DTD is not disabled, allowing an attacker to retrieve system files, or perform requests on behalf of the server using malicious XML documents
Arbitrary code execution. The vulnerability exists as the lookup helper does not properly validate templates, allowing the execution of JavaScript code in templates
Information Exposure Through Sent Data
The application calls the javax.servlet.http.HttpServletResponse.setHeader() function, which will result in data being transferred out of the application (via the network or another medium). This data contains sensitive information.
Ensure that the transfer of the sensitive data is intended and that it does not violate application security policy. This flaw is categorized as low severity because it only impacts confidentiality, not integrity or availability. However, in the context of a mobile application, the significance of an information leak may be much greater, especially if misaligned with user expectations or data privacy policies.
invalid curve attack

# Hash collision attacks.
The library keystore files uses a HMAC hash that is only 16 bits long, allowing a malicious user to retrieve the password used for keystore integrity verification checks. This vulnerability only affects users of the `deee` keystore format
Padding oracle attack
Open redirector attack that can leak an authorization code. A malicious user or attacker can craft a request to the authorization endpoint using the authorization code grant type, and specify a manipulated redirection URI via the redirect_uri parameter. This can cause the authorization server to redirect the resource owner user-agent to a URI under the control of the attacker with the leaked authorization code

# Log forging attack. 
Writing untrusted data into a log file allows an attacker to forge log entries or inject malicious content into log files. Corrupted log files can be used to cover an attacker's tracks or as a delivery mechanism for an attack on a log viewing or processing utility. For example, if a web administrator uses a browser-based utility to review logs, a cross-site scripting attack might be possible. The first argument to info() contains tainted data.

Avoid directly embedding user input in log files when possible. Sanitize untrusted data used to construct log entries by using a safe logging mechanism such as the OWASP ESAPI Logger, which will automatically remove unexpected carriage returns and line feeds and can be configured to use HTML entity encoding for non-alphanumeric data. Alternatively, some of the XSS escaping functions from the OWASP Java Encoder project will also sanitize CRLF sequences. Only write custom blacklisting code when absolutely necessary. Always validate untrusted input to ensure that it conforms to the expected format, using centralized data validation routines when possible.
