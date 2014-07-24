/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.authentication.logout;

import java.io.IOException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Logs a principal out.
 * <p>
 * Polls a series of {@link LogoutHandler}s. The handlers should be specified in the order they are required.
 * Generally you will want to call logout handlers <code>TokenBasedRememberMeServices</code> and
 * <code>SecurityContextLogoutHandler</code> (in that order).
 * <p>
 * After logout, a redirect will be performed to the URL determined by either the configured
 * <tt>LogoutSuccessHandler</tt> or the <tt>logoutSuccessUrl</tt>, depending on which constructor was used.
 *
 * @author Ben Alex
 */
public class LogoutFilter extends GenericFilterBean {

    //~ Instance fields ================================================================================================

    private String filterProcessesUrl = "/j_spring_security_logout";
    private final List<LogoutHandler> handlers;
    private final LogoutSuccessHandler logoutSuccessHandler;

    //~ Constructors ===================================================================================================

    /**
     * Constructor which takes a <tt>LogoutSuccessHandler</tt> instance to determine the target destination
     * after logging out. The list of <tt>LogoutHandler</tt>s are intended to perform the actual logout functionality
     * (such as clearing the security context, invalidating the session, etc.).
     */
    public LogoutFilter(LogoutSuccessHandler logoutSuccessHandler, LogoutHandler... handlers) {
        Assert.notEmpty(handlers, "LogoutHandlers are required");
        this.handlers = Arrays.asList(handlers);
        Assert.notNull(logoutSuccessHandler, "logoutSuccessHandler cannot be null");
        this.logoutSuccessHandler = logoutSuccessHandler;
    }

    public LogoutFilter(String logoutSuccessUrl, LogoutHandler... handlers) {
        Assert.notEmpty(handlers, "LogoutHandlers are required");
        this.handlers = Arrays.asList(handlers);
        Assert.isTrue(!StringUtils.hasLength(logoutSuccessUrl) ||
                UrlUtils.isValidRedirectUrl(logoutSuccessUrl), logoutSuccessUrl + " isn't a valid redirect URL");
        SimpleUrlLogoutSuccessHandler urlLogoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
        if (StringUtils.hasText(logoutSuccessUrl)) {
            urlLogoutSuccessHandler.setDefaultTargetUrl(logoutSuccessUrl);
        }
        logoutSuccessHandler = urlLogoutSuccessHandler;
    }

    //~ Methods ========================================================================================================

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        
        
        System.out.println("\n\n=========================================================" );
        System.out.println("cas-client-webapp LogoutFilter requestSingleLogoutFilter " );
        System.out.println("request.method: " +request.getMethod() );
        System.out.println("request.requestURI: " +request.getRequestURI() );
        System.out.println("request.queryString: " +request.getQueryString() );
	    
        	Enumeration enParams = request.getParameterNames(); 
        	while(enParams.hasMoreElements()){
        		String paramName = (String)enParams.nextElement();
        		System.out.println(paramName+": "+request.getParameter(paramName));
        	}
        	System.out.println("=========================================================\n\n" );
      
        
        

        if (requiresLogout(request, response)) {
        	
        	//1 a seguito del mio clic su logout questo e' il primo posto che agisce
        	System.out.println("--->LogoutFilter: if (requiresLogout(request, response)) {" );
        	
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();

            if (logger.isDebugEnabled()) {
                logger.debug("Logging out user '" + auth + "' and transferring to logout destination");
            }

            for (LogoutHandler handler : handlers) {
            	System.out.println("--->2 LogoutFilter:handler.class "+handler.getClass() );
            	
            	SecurityContextLogoutHandler securityContextLogoutHandler = (SecurityContextLogoutHandler) handler;
            	
            	securityContextLogoutHandler.logout(request, response, auth);
            }

            System.out.println("--->3 LogoutFilter:onLogoutSuccess" );
            //--->LogoutFilter:onLogoutSuccess
            
            SimpleUrlLogoutSuccessHandler simpleUrlLogoutSuccessHandler =  (SimpleUrlLogoutSuccessHandler) logoutSuccessHandler;
            
            // super.handle
            // redirectStrategy.sendRedirect(request, response, targetUrl);
             simpleUrlLogoutSuccessHandler.onLogoutSuccess(request, response, auth);

            return;
        }

        System.out.println("--->LogoutFilter:chain.doFilter(request, response);" );
        chain.doFilter(request, response);
    }

    /**
     * Allow subclasses to modify when a logout should take place.
     *
     * @param request the request
     * @param response the response
     *
     * @return <code>true</code> if logout should occur, <code>false</code> otherwise
     */
    protected boolean requiresLogout(HttpServletRequest request, HttpServletResponse response) {
        String uri = request.getRequestURI();
        int pathParamIndex = uri.indexOf(';');

        if (pathParamIndex > 0) {
            // strip everything from the first semi-colon
            uri = uri.substring(0, pathParamIndex);
        }

        int queryParamIndex = uri.indexOf('?');

        if (queryParamIndex > 0) {
            // strip everything from the first question mark
            uri = uri.substring(0, queryParamIndex);
        }

        if ("".equals(request.getContextPath())) {
            return uri.endsWith(filterProcessesUrl);
        }

        return uri.endsWith(request.getContextPath() + filterProcessesUrl);
    }

    public void setFilterProcessesUrl(String filterProcessesUrl) {
        Assert.isTrue(UrlUtils.isValidRedirectUrl(filterProcessesUrl), filterProcessesUrl + " isn't a valid value for" +
                " 'filterProcessesUrl'");
        this.filterProcessesUrl = filterProcessesUrl;
    }

    protected String getFilterProcessesUrl() {
        return filterProcessesUrl;
    }
}
