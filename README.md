<h2>cas-pac4j-saml2-demo</h2>

========

This is an overlayed version of cas-server-webapp.

This demo allows the cas-webapp to be used as a proxy auth service for  shiboleth idp and another cas

used libraries / projects:

- cas-server-support-pac4j https://github.com/Jasig/cas
- pac4j https://github.com/leleuj/pac4j
- spring-security-saml https://github.com/spring-projects/spring-security-saml


<h4>support:</h4>
- CAS login and logout proxy
- SAML (2.0) login and logout proxy with assertion validation
- multiple idp saml
- back channel logout proxy to authenticated apps for saml and cas proxy


<h4>note:</h4>

- saml login assertion is stored as an attribute of the pac4j Credential to be memorized in the TGT ( to allow logout from remote idp, and to back channel to proxy authenticated apps )
- logout-webflow.xml modified to map cas client logout via browser redirect to idp by ClientLogoutAction
- logout-webflow.xml modified to map ClientBackChannelAction to get and send on back channel for a client pac4j 
- spring-security-saml libs used without http config, the beans are wrapped in pac4j BaseClientclass 
- used a RedirectType = DUMMY to delegate all the work to wrapped libs



<h4>to do:</h4>

- saml idp process back channel call
- back channel to proxy authenticated apps (seems that  destroing TGT on CAS 4.0.1-SNAPSHOT isnt sending a proper logoutRequest parameter to webapps) so a remote server logout destroy de proxy server tgt but apps are still logged in



<h4Overview</h4>

			cas-client-remotecas-webapp  	----------------------->		cas-server	----> xml
			
			cas-client-webapp  				----->		caspac		----->		cas-server	----> xml
											----->		caspac		----->		idp  			----> ldap
			
			spring-security-saml2-sample	------------------------->		idp	 			----> ldap
			


-<h4>Quick start & test (Windows config)</h4>

- remap host: Windows\System32\drivers\etc

    	127.0.0.1 idp.alessandro.it
    	127.0.0.1 cas.alessandro.it
    	127.0.0.1 cas2.alessandro.it
    	127.0.0.1 app.alessandro.it
    
- download and install Tomcat

		http://tomcat.apache.org/tomcat-6.0-doc/index.html
		http://tomcat.apache.org/tomcat-7.0-doc/index.html
		
- download and install Shibboleth

		- http://shibboleth.net/downloads/identity-provider/latest/shibboleth-identityprovider-2.4.0-bin.zip
		- shibboleth-identityprovider-2.4.0\install.bat --> installDirectory
		- eclipse import war idp.war
		- copy TOMCAT_HOME/endorsed and copy the .jar files included in the IdP source endorsed directory (not needed for http redirect post 
		- overwrite installDirectory\* with git shibbolethInstall\* 
		- rewrite all absolute path with your absolute path
		
- download and configure ldap

		http://supergsego.com/apache//directory/apacheds/dist/2.0.0-M17/apacheds-2.0.0-M17.zip
	 	- start \apacheds-2.0.0-M17\bin\apacheds.bat    for   localhost:10389
	 	- add partition  id aleditta   suffix o=aleditta
	 	- ad idp user
	 	- dn: cn=aleldap,ou=people,o=aleditta
		- objectclass: top
		- objectclass: inetOrgPerson
		- objectclass: person
		- objectclass: organizationalPerson
		- cn: ale xxx
		- cn: aleldap
		- sn: xxx
		- description: xxxx
		- mail: xxx@neverland
		- uid: aleldap
		- userPassword:: e3NoYX0xdi9hRjhqQUE2SEwxQWNjakFDQ3NrTXNzYzA9	(aleldap)
	 

- eclipse config
		
		server tomcat with VM arguments
			-Djavax.net.ssl.trustStore="C:\your_path\security\trustore\truststore.ts"
			-Djavax.net.ssl.trustStorePassword="tru111"

		- tomcat 7 app.alessandro.it
		- tomcat 7 cas.alessandro.it
		- tomcat 7 cas2.alessandro.it
		- tomcat 6 idp.alessandro.it

		map eclipse server.xml as in \Server\..\server.xml, replace abs path with yours


- map webapps:
			
		- cas client app of proxy cas: https://app.alessandro.it:2443/cas-client-webapp/
		- cas client app of remote cas: https://app.alessandro.it:2443/cas-client-remotecas-webapp/
		- saml client app of idp: https://app.alessandro.it:2443/spring-security-saml2-sample
		- cas proxy: https://cas.alessandro.it:6443/caspac/ 
		- cas remote: https://cas2.alessandro.it:7443/cas-server/ 
		- shibboleth idp: https://idp.alessandro.it/idp/ 
		- ldap: localhost:10389 
 
  
 
- <h4>flows examples</h4>
	
	
		- login:  	browser:			cas-client-webapp --->  caspac --->  idp (aleldap/aleldap)--->  caspac --->  cas-client-webapp
		- logout: 	browser: 			cas-client-webapp --->  caspac --->  idp --->  caspac 
		- back channel:		caspac --> 	cas-client-webapp
	
				
		- login:  	browser:			cas-client-remotecas-webapp --->  cas-server (alecas/alecas) --->  cas-client-remotecas-webapp		
		- login:  	browser:			cas-client-webapp --->  caspac --->  cas-server  --->  caspac --->  cas-client-webapp
		- logout: 	browser: 			cas-client-remotecas-webapp --->  cas-server
		- back channel:		cas-server ---> cas-client-remotecas-webapp
		- back channel:		cas-server ---> caspac ----> cas-client-webapp
				 
	
 

- <h4>SAML HTTP BROWSER FLOW EXAMPLE</h4>

LOGIN

		- https://app.alessandro.it:2443/cas-client-webapp/	HTTPS	GET	200
		- https://app.alessandro.it:2443/cas-client-webapp/p	HTTPS	GET	302
		- /caspac/login?service=https%3A%2F%2Fapp.alessandro.it%3A2443%2Fcas-client-webapp%2Fj_spring_cas_security_check	HTTPS	GET	200
		- /caspac/login?client_name=Saml2ClientWrapper&needs_client_redirection=true&idp=https://idp.alessandro.it/idp/shibboleth	HTTPS	GET	200
		- https://idp.alessandro.it/idp/profile/SAML2/POST/SSO	HTTPS	POST	302
		- https://idp.alessandro.it/idp/AuthnEngine	HTTPS	POST	302
		- https://idp.alessandro.it/idp/Authn/UserPassword	HTTPS	POST	200
		- https://idp.alessandro.it/idp/Authn/UserPassword	HTTPS	POST	302
		- https://idp.alessandro.it/idp/profile/SAML2/POST/SSO	HTTPS	POST	200
		- caspac/login?client_name=Saml2ClientWrapper	HTTPS	POST	302
		- https://app.alessandro.it:2443/cas-client-webapp/j_spring_cas_security_check?ticket=ST-5-AWJ...	HTTPS	POST	302
		- https://app.alessandro.it:2443/cas-client-webapp/p	HTTPS	POST	200


LOGOUT

		- https://app.alessandro.it:2443/cas-client-webapp/j_spring_cas_security_logout	HTTPS	GET	302
		- caspac/logout	HTTPS	GET	302
		- https://idp.alessandro.it/idp/profile/SAML2/Redirect/SLO?SAMLRequest=nZJBb%2BM.......	HTTPS	GET	200
		- https://cas.alessandro.it:6443/caspac/logout?action=SingleLogout	HTTPS	POST	200
 
