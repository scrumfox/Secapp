Session fixation and multiple concurrent sessions:


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
		
		
ForgotPasswordOtp brute force:


ProCheckUp found that it was possible to brute force the security code of the forgot password page. ProCheckUp did not successfully bruteforce the security code, as the e-mail was not working and without this we had little idea of the format of the security code. ProCheckUp attempted bruteforcing the code by entering numbers 1 to 10000 using an automated attack tool.

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

mofidfied the webconfig :
	<httpCookies httpOnlyCookies="true" requireSSL="true" />
    <httpRuntime targetFramework="4.5" enableVersionHeader="false" relaxedUrlToFileSystemMapping="true" encoderType="System.Web.Security.AntiXss.AntiXssEncoder, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" />
	
	<forms loginUrl="~/Account/LogOn" timeout="2880" + requireSSL="true" name="au" />
	
	- <customErrors mode="On" />
	+ <customErrors mode="RemoteOnly" />
	
	+ <add name="X-Frame-Options" value="Deny" /
	
Scenarion:XSS 

1. Login to the application as an admin user pentestadm1.

2. Go to View Only>Credit Quick>All>ApplicationID->Search as shown in Figure 3.

3. Now open the named file and then click on Continue as shown in Figure 4 and 5.

4. Now click on edit button and then add a file as text format which contains script “><script>alert(document.cookie);</script> and save it as shown in Figure 6.

5. Now when we click on saved file, the XSS payload is executed and a pop-up is displayed as shown in Figure 7.

6. Now log out the application.

7. Now login to the application as an admin user pentestadm2.

8. Follow the same steps as above and click on the saved file, one can see the XSS payload is executed and pop-up is displayed as shown in Figure 8.

 X-XSS-Protection  -  for additional XSS protection
Strict-Transport-Security  - to ensure all traffic is sent over HTTPS.   NB. we only serve HTTPS anyway, so this isn't going to make a difference - but we'll need to add it regardless.

Veracode Fix/Mitigate Cross Site Scripting Flaws-mpin:
document.getElementById("mpinOTPNumber").innerHTML = escape(authData._mpinOTP);

  @Html.Raw(@"            prerollid: '" + Model.Email + "',\r\n");
                <text>prerollid : '@Model.Email',</text>
				
Veracode Fix/Mitigate Encapsulation Flaws

	- return Newtonsoft.Json.JsonConvert.DeserializeObject<WorkflowState>(state);
	+ return JsonConvert.DeserializeObject<WorkflowState>(state, new JsonSerializerSettings
	  {
		TypeNameHandling = TypeNameHandling.None
	  });
	  
Veracode Fix/Mitigate Information Leakage Flaws:
			- using (var xsr = new XmlStringReader(inputXml, new XmlReaderSettings { IgnoreComments = true, IgnoreProcessingInstructions = true, IgnoreWhitespace = true, XmlResolver = null }))
            - {                 
            -    doc.Load(xsr.Reader);                
            
			+ using (StringReader stringReader = new StringReader(inputXml))
            + {
            +    XmlReaderSettings settings = new XmlReaderSettings()
            +    {
            +        IgnoreComments = true,
            +        IgnoreWhitespace = true,
            +        IgnoreProcessingInstructions = true,
            +        XmlResolver = null
            +    };
            +    var xmlTextReader = new XmlTextReader(stringReader);

            +    using (var xsr = XmlReader.Create(xmlTextReader, settings))
            +    {
            +        doc.Load(xsr);
            +    }
            +}
			
  - using (var internalResponse = await HttpClient.GetAsync(this.configSettings.GetSetting("", "")  "/signature/" + id + "/?regOTT=" + regOTT))

  + using (var internalResponse = await HttpClient.GetAsync(this.configSettings.GetSetting("", "")  "/signature/" + Uri.EscapeUriString(id) + "/?regOTT=" + Uri.EscapeUriString(regOTT)))
  
  Mitigate CRLF Injection
  
  - public static string EscapeCrlfString(string value)
  + public static string RemoveCrlfsFromString(string value)
        {
            return value.Replace("\r", string.Empty)
                        .Replace("%0d", string.Empty)
                        .Replace("%0D", string.Empty)
                        .Replace("\n", string.Empty)
                        .Replace("%0a", string.Empty)
                        .Replace("%0A", string.Empty);
						
	- filterContext.HttpContext.Response.SetCookie(new HttpCookie("theme") { Value = StringExt.EscapeCrlfString(theme) });
	+ filterContext.HttpContext.Response.SetCookie(new HttpCookie("theme") { Value = StringExt.RemoveCrlfsFromString(theme) });
	
	Veracode Fix/Mitigate Information Leakage Flaws (Helpdesk)
	- using (var httpResponse = await httpClient.GetAsync(@"/api/mmm/mmmm?newStatus=" +- Uri.EscapeDataString(newStatus)))
	
	+ using (var httpResponse = await httpClient.GetAsync(Uri.EscapeUriString(@"/api/mmm/mmmm?newStatus=" + Uri.EscapeDataString(newStatus))))
	
Improper Restriction of XML External Entity Reference ('XXE') 
system_xml_dll.System.Xml.XmlDocument.Load() function to parse an XML document. By default, the default XML entity resolver will attempt to resolve and retrieve external references. If attacker-controlled XML can be submitted to one of these functions, then the attacker could gain access to information about an internal network, local filesystem, or other sensitive data. This is known as an XML eXternal Entity (XXE) attack. The first argument to Load() contains tainted data from the variable templateMetadataPath. The tainted data originated from an earlier call to experian_idaas_accountmanagement_web_dll.virtualcontroller.vc_mvcentry.
Remediation: Configure the XML parser to disable external entity resolution.

 1. XmlDocument xmlDocument = new XmlDocument { XmlResolver = null };
 
 2.    - using (var reader = new StringReader(matchResponse.Body.MatchResult))
       + using (var reader = new XmlStringReader(matchResponse.Body.MatchResult, new XmlReaderSettings { IgnoreComments = true, IgnoreProcessingInstructions = true, IgnoreWhitespace = true, XmlResolver = null }))
                {
                    resultBlock = (ResultBlock)serialiser.Deserialize(reader);
                    resultBlock = (ResultBlock)serialiser.Deserialize(reader.Reader);
                }

 
 
 
 Removed possible carriage returns and line feeds from the cookie value
 
     - filterContext.HttpContext.Response.SetCookie(new HttpCookie("esi", filterContext.HttpContext.Request.Cookies["si"].Value));
	 
	 +   /*Not using Environment.NewLine as it would miss \n or \r on it's own.*/
	 +   var cookieValue = filterContext.HttpContext.Request.Cookies["si"].Value
							.Replace("\n", string.Empty)
							.Replace("\r", string.Empty);
		filterContext.HttpContext.Response.SetCookie(new HttpCookie("esi", cookieValue));

