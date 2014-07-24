<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
    <%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Insert title here</title>
</head>
<body>


<c:if test="${not empty error}">invalid credentials</c:if>
<br />
<c:if test="${not empty error}">
			Your login attempt was not successful, try again.<br /> Caused :
			${sessionScope["SPRING_SECURITY_LAST_EXCEPTION"].message}
</c:if>

<form  method="POST" action="j_spring_security_check"  >

		User
		<input size="22" maxlength="14" type="text" value="" name="j_username" id="user"/>
		Password
		<input size="23" maxlength="22" type="password" value="" name="j_password" id="pass" />
		<input type="submit" id="submitbutton6" value="LogIn" />
</form>

<br /><br />

<a href ="https://cas.alessandro.it:6443/cas/login?service=https%3A%2F%2Fapp.alessandro.it%3A2443%2Fapp%2Fj_spring_cas_security_check" >cas auth</a>


</body>
</html>