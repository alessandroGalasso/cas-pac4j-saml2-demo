<h2>cas-pac4j-saml2-demo</h2>

========

This is an overlayed version of cas-server-webapp.

This demo allows the integration of cas webapp with shiboleth idp.
A client webApp could autenticate to cas ( with simple cas client) and cas manage the saml protocol.


used libraries / projects:

- cas-server-support-pac4j https://github.com/Jasig/cas
- pac4j https://github.com/leleuj/pac4j
- spring-security-saml https://github.com/spring-projects/spring-security-saml


support:

- SAML (2.0) with spring-security-saml
- multiple idp
- logout to remote idp 


note:

- saml login assertion must be stored as atttribute in the cas TGT to allow logout from cas to logged idp
- logout-webflow.xml modified to map cas client logout to idp by ClientLogoutAction
- spring-security-saml / securityContext.xml imported without http config, beans used in wrapper class pac4j
- new RedirectType = DUMMY   to delegate all print outputstream work to wrapped libs
- modified BaseSAMLMessageDecoder to allow params


wip:

- map global saml logout : SAMLLogoutFilter


my localhost (host remapped) test environment:

- cas client app: https://app.alessandro.it:2443/cas-client-webapp/ (Tomcat 7)
- cas webapp: https://cas.alessandro.it:6443/caspac/ (Tomcat 7)
- idp: https://idp.alessandro.it/idp/ (Tomcat 6)
- ldap: localhost:10389 (ApacheDs)
 

flow Example

- LOGIN
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
 
- LOGOUT
- https://app.alessandro.it:2443/cas-client-webapp/j_spring_cas_security_logout	HTTPS	GET	302	0	-609164170
- caspac/logout	HTTPS	GET	302
- https://idp.alessandro.it/idp/profile/SAML2/Redirect/SLO?SAMLRequest=nZJBb%2BM.......	HTTPS	GET	200
- https://cas.alessandro.it:6443/caspac/logout?action=SingleLogout	HTTPS	POST	200
 
