<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %> 
<html>
<head>
	<title>Home</title>
</head>
<body>

<P>  The time on the server is ${serverTime}. </P>

<P>${mess}</P>

<P><a href="https://cas2.alessandro.it:7443/cas-server/login?service=https%3A%2F%2Fapp.alessandro.it%3A2443%2Ftest-cas-client-webapp%2Fj_spring_cas_security_check">cas auth</a></P>



<sec:authorize access="isAuthenticated()">
<a href="<c:url value="j_spring_security_logout" />" > Logout</a><br />
<br/><a href="<c:url value="j_spring_cas_security_logout" />" >cas Logout</a><br />



<br />principal: <sec:authentication    property="principal.username" /><br /><br />
<br />auth:<sec:authentication property="principal.authorities"/><br />
</sec:authorize>

<a href="<c:url value="/"/>">home</a>


</body>
</html>
