security
========

security demo webApp


This is an overlayed version of cas-server-webapp.

This demo allows the integration of cas webapp with shiboleth idp.
A client webApp could autenticate to cas ( with simple cas client) and cas manage the saml protocol.

used libraries / projects:

- cas-server-support-pac4j
- pac4j
- spring-security-saml

support:

- SAML (2.0) with spring-security-saml
- multiple idp
- logout to remote idp 

note:

- saml assertion must be stored as atttribute in the TGT to allow logout from cas to loggedIn idp
- logout-webflow.xml modified to map cas client logout to idp by ClientLogoutAction
- spring-security-saml / securityContext.xml imported without http config, only the beans are uset to use saml
- new RedirectType = DUMMY   to delegate all the work to wrapped libs
- modified BaseSAMLMessageDecoder to allow params

test environment:

cas client app: https://app.alessandro.it:2443/cas-sec-app-pac/   (Tomcat 7)
cas webapp: https://cas.alessandro.it:6443/caspac/   (Tomcat 7)
idp: https://idp.alessandro.it/idp/   (Tomcat 6)

 
to do:
map global saml logout : SAMLLogoutFilter


