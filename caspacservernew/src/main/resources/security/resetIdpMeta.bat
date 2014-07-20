cd C:\shibbolethtest\shiboleth_install_output\logs
del *.*
cd C:\shibbolethtest\shiboleth_install_output\metadata
del casalessandroit_spNew.xml
cd C:\shibbolethtest\STSworkspace\cas-pac4j-spring-security-saml-demo\src\main\resources\security
copy casalessandroit_spNew.xml  C:\shibbolethtest\shiboleth_install_output\metadata
