<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %> 
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Insert title here</title>
</head>
<body>

denied!

<sec:authorize access="isAuthenticated()">
<br/><a href="<c:url value="j_spring_security_logout" />" >Logout</a>
<br />principal: <sec:authentication    property="principal.username" /><br />
<br />auth:<sec:authentication property="principal.authorities"/>
</sec:authorize>


<c:if test="${not empty error}">
		<div style="color:red;" >
			authorization problem!
		</div>
	</c:if>
<br />
<c:if test="${not empty error}">
		<div class="errorblock">
			Your login attempt was not successful, try again.<br /> Caused :
			${sessionScope["SPRING_SECURITY_LAST_EXCEPTION"].message}
		</div>
	</c:if>

<br/><a href="<c:url value="/"/>">home</a>

</body>
</html>