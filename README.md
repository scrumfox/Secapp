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

# Timing side-channel attacks
on a noncompliant MAC check operation during the processing of malformed CBC padding, which allows remote attackers to conduct distinguishing attacks and plaintext-recovery attacks via statistical analysis of timing data for crafted packets…


This call to java.lang.ClassLoader.loadClass() uses reflection in an unsafe manner. An attacker can specify the class name to be instantiated, which may create unexpected control flow paths through the application. Depending on how reflection is being used, the attack vector may allow the attacker to bypass security checks or otherwise cause the application to behave in an unexpected manner. Even if the object does not implement the specified interface and a ClassCastException is thrown, the constructor of the untrusted class name will have already executed. The first argument to loadClass() contains tainted data from the variable val$descriptorOuterClass. The tainted data originated from an earlier call to com.experian.google.protobuf.GeneratedMessage.newFileScopedGeneratedExtension.
Validate the class name against a combination of white and black lists to ensure that only expected behavior is produced.


# Regular expression denial of service (ReDoS)
Prototype pollution attacks. Attackers can add or modify existing properties relating to an Object by using the utilities function to change the prototype of said Object. Using this flaw, attackers can trigger denial of service (DoS) attacks and in some situations remote code execution(RCE) attacks.

A malicious user can pass a `GET` request to the application with a `Sec-WebSocket-Extensions` header that uses the `Object.prototype` property name to crash the application.

Apache Axis 1.4 and earlier, as used in PayPal Payments Pro, PayPal Mass Pay, PayPal Transactional Information SOAP, the Java Message Service implementation in Apache ActiveMQ, and other products, does not verify that the server hostname matches a domain name in the subject's Common Name (CN) or subjectAltName field of the X.509 certificate, which allows man-in-the-middle attackers to spoof SSL servers via an arbitrary valid certificate.

Apache CXF-Core is susceptible to denial of service (DoS) attack. The attack exists because it fails to limit the maximum number of message attachments in a given message, allowing an attacker to provide a message with a huge number of attachment and trigger DoS attack.


# Modification of Assumed-Immutable Data (MAID) vulnerability
# The time of check to time of use (TOCTOU) race condition

# Deserialization of Untrusted Data
The serialized-object data stream used in the call to com.thoughtworks.xstream.XStream.fromXML() appears to have been constructed with untrusted data. Attacker manipulation of this stream has the ability to cause the creation of objects of arbitrary Serializable types. Paired with a weakness in another class's constructor, this could result in a denial of service, code execution, or data corruption vulnerability. The first argument to fromXML() contains tainted data from the variable serialized. The tainted data originated from an earlier call to com.experian.eda.component.ad.job.client.interfaces.events.Event.unpack.
Avoid passing untrusted data to ObjectInputStream; if the data is untrusted, consider switching to a safer serialization scheme such as JSON.

# External Control of File Name or Path
This call to java.io.File.!operator_javanewinit() contains a path manipulation flaw. The argument to the function is a filename constructed using untrusted input. If an attacker is allowed to specify all or part of the filename, it may be possible to gain unauthorized access

# Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
This call to jQuery() contains a cross-site scripting (XSS) flaw. The application populates the HTTP response with untrusted input, allowing an attacker to embed malicious content, such as Javascript code, which will be executed in the context of the victim's browser. XSS vulnerabilities are commonly exploited to steal or manipulate cookies, modify presentation of content, and compromise confidential information, with new attack vectors being discovered on a regular basis.
Use contextual escaping on all untrusted data before using it to construct any portion of an HTTP response. The escaping method should be chosen based on the specific use case of the untrusted data, otherwise it may not protect fully against the attack. For example, if the data is being written to the body of an HTML page, use HTML entity escaping; if the data is being written to an attribute, use attribute escaping; etc. Both the OWASP Java Encoder library and the Microsoft AntiXSS library provide contextual escaping methods. For more details on contextual escaping, see https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md. In addition, as a best practice, always validate untrusted input to ensure that it conforms to the expected format, using centralized data validation routines when possible.
# Session fixation and multiple concurrent sessions:

These will be fixed in the same way. The latest forms auth 'AU' cookie issued will be tied to the user's account by storing the last login datetime in the AU cookie encrypted section, and also against the user's account.

The two times will be compared when authenticating the forms auth cookie, and if different the user will be redirected to the login page with an error message saying 'You have been logged out because you have logged in to your account elsewhere.'

Old AU cookies will therefore be unusable past the point of authentication only (when advancing past either username page or mem word page).

Steps to repro (session fixation)

    Login using username and password
    Take a copy of the AU cookie
    Enter correct mem word chars and continue to next page
    Edit cookie value (e.g. in firebug) and set old AU cookie value

Steps to repro (single session)

    Login using username and password
    Open another browser and login using same username and password
    Refresh the page on the first browser

Mitigation:
 The user's current authentication state - saved in an encrypted cookie, so size is important
 filters.Add(new SingleSessionFilter());
        }

# ForgotPasswordOtp brute force:

It is found that it was possible to brute force the security code of the forgot password page. Theu did not successfully bruteforce the security code, as the e-mail was not working and without this we had little idea of the format of the security code. They attempted bruteforcing the code by entering numbers 1 to 10000 using an automated attack tool.

Resolution should be to kick the user out of the forgot password process after a configurable number of attempts to enter the security code (default = 3)

MItigation:
Added the ForgotPasswordOtpAttempts": "3" to configurable
Added new session state to keep forgotpasswordoptAttempts: ForgotPasswordSessionState
Remove the exsting session:
Get the existing FP Sesssion
check the otpattmepts with the configuraiton set item, if it >= 
remove the exisitng session.
Flaw Id Name Proposed Resolution Notes
4 Cross-Site Request Forgery (CSRF) Fix Use the built in MVC 4 Html.AntiForgeryToken on all form pages
  [AllowAnonymous, ValidateAntiForgeryToken]
        public ActionResult LogOn(LogOnModel model, string returnUrl)
		
7 Unmasked Sensitive Data Defer/discuss with Jim This is by design, however we have an outstanding user story to send the reset password by e-mail instead of display on screen
5 Auto-Complete Enabled Fix Easy fix!
3 Security Feature Brute Force Fix Log out helpdesk user and lock account as recommended
2 Security Feature Bypass Fix Instead of randomising the user id values, keep the userid held in session instead of using it on the page
1 Clickjacking Protection Mechanism Failure Fix Easy fix! Was already in place on IDP.
8 SECURE cookie flag not set Fix Easy fix! Was already in place on IDP.
10 SSL RC4 Cipher Suites Supported Defer Already discussed with GTS, a change will impact all customers - with KS to investigate
9 Verbose HTTP Response Headers Fix Easy fix! Was already in place on IDP.
6 Concurrent Login Discuss Annoying fix, but possible. The IDP now disallows concurrent logins.

Changes made:

4. AntiXSS protection when encoding html - this was a global configuration change. I'm not sure how you would be able to test this one.
3. User logged out of helpdesk when failing to answer user security questions multiple times
2. UserID not passed between pages in helpdesk using from variables any more. Now stored in session.
1. Add a HTTP header to helpdesk see pdf for details
8. Set the secure flag on all helpdesk cookies
9. Removed server header etc. see pdf for details

Mitigation to do on Modfied Web.Conf:
	<httpCookies httpOnlyCookies="true" requireSSL="true" />
  <httpRuntime targetFramework="4.5" enableVersionHeader="false" relaxedUrlToFileSystemMapping="true" encoderType="System.Web.Security.AntiXss.AntiXssEncoder, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=xxx" />
	
	<forms loginUrl="~/XXXXX/LogOn" timeout="2880" + requireSSL="true" name="au" />
	
	- <customErrors mode="On" /> // Remove
	+ <customErrors mode="RemoteOnly" />
	
	+ <add name="X-Frame-Options" value="Deny" /.
  
  
