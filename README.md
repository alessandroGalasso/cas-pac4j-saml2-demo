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


my localhost (host remapped) test environment:

- cas client app: https://app.alessandro.it:2443/cas-sec-app-pac/   (Tomcat 7)
- cas webapp: https://cas.alessandro.it:6443/caspac/   (Tomcat 7)
- idp: https://idp.alessandro.it/idp/   (Tomcat 6)

 
wip:

- map global saml logout : SAMLLogoutFilter


