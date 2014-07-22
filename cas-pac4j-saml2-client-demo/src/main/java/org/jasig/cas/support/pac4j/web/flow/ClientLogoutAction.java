/*
  Copyright 2014 Galasso

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */
package org.jasig.cas.support.pac4j.web.flow;

import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotNull;

import org.apache.commons.lang.StringUtils;
import org.jasig.cas.CentralAuthenticationService;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.services.ServicesManager;
import org.jasig.cas.ticket.TicketGrantingTicket;
import org.jasig.cas.ticket.registry.TicketRegistry;
import org.jasig.cas.web.support.CookieRetrievingCookieGenerator;
import org.jasig.cas.web.support.WebUtils;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.impl.AttributeImpl;
import org.opensaml.xml.XMLObject;
import org.pac4j.cas.client.CasClient;
import org.pac4j.core.client.BaseClient;
import org.pac4j.core.client.Clients;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.saml.client.Saml2Client;
import org.pac4j.saml.client.Saml2ClientWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.w3c.dom.Element;


@SuppressWarnings({ "unchecked" })
public final class ClientLogoutAction extends AbstractAction {

    /**
     * The logger.
     */
    private final Logger logger = LoggerFactory.getLogger(ClientLogoutAction.class);
    
  
    /** CookieGenerator for TGT Cookie. */
    @NotNull
    private final CookieRetrievingCookieGenerator ticketGrantingTicketCookieGenerator;

    /** CookieGenerator for Warn Cookie. */
    @NotNull
    private final CookieRetrievingCookieGenerator warnCookieGenerator;


    @NotNull
    private final TicketRegistry ticketRegistry;

    /** New Ticket Registry for storing and retrieving services tickets. Can point to the same one as the ticketRegistry variable. */
    @NotNull
    private final TicketRegistry serviceTicketRegistry;

    
    @NotNull
    private final ServicesManager servicesManager;

   /**
     * The clients used for authentication.
     */
    @NotNull
    private final Clients clients;

    /**
     * The service for CAS authentication.
     */
    @NotNull
    private final CentralAuthenticationService centralAuthenticationService;

    /**
     * Build the action.
     *
     * @param theCentralAuthenticationService The service for CAS authentication
     * @param theClients The clients for authentication
     */
    public ClientLogoutAction(
    		final CentralAuthenticationService theCentralAuthenticationService,
            final Clients theClients,
            final CookieRetrievingCookieGenerator tgtCookieGenerator,
            final CookieRetrievingCookieGenerator warnCookieGenerator,
            final TicketRegistry ticketRegistry,
            final TicketRegistry serviceTicketRegistry,
            final ServicesManager servicesManager
     		) {
        this.centralAuthenticationService = theCentralAuthenticationService;
        this.clients = theClients;
        this.ticketGrantingTicketCookieGenerator = tgtCookieGenerator;
        this.warnCookieGenerator = warnCookieGenerator;
        this.ticketRegistry = ticketRegistry;
        
        if (serviceTicketRegistry == null) {
            this.serviceTicketRegistry = ticketRegistry;
        } else {
            this.serviceTicketRegistry = serviceTicketRegistry;
        }
          this.servicesManager = servicesManager;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected Event doExecute(final RequestContext context) throws Exception {
    	
  		final HttpServletRequest request = WebUtils.getHttpServletRequest(context);
	    final HttpServletResponse response = WebUtils.getHttpServletResponse(context);
	    final WebContext webContext = new J2EContext(request, response);
	    
	    logger.debug("=========================================================" );
	    logger.debug("ClientLogoutAction.doExecute: " );
        logger.debug("request.method: " +request.getMethod() );
        logger.debug("request.requestURI: " +request.getRequestURI() );
        logger.debug("request.queryString: " +request.getQueryString() );
	    
        	Enumeration enParams = request.getParameterNames(); 
        	while(enParams.hasMoreElements()){
        		String paramName = (String)enParams.nextElement();
        		logger.debug(paramName+": "+request.getParameter(paramName));
        	}
        logger.debug("=========================================================" );
	    
        
        //action is like a filter mapping
	    String action = request.getParameter("action");
	    if(action == null){action = (String) request.getAttribute("action");}
	    
    
    	// in login's webflow : we can get the value from context as it has already been stored
        String tgtId = WebUtils.getTicketGrantingTicketId(context);
        // for logout, we need to get the cookie's value
        if (tgtId == null) {
            tgtId = this.ticketGrantingTicketCookieGenerator.retrieveCookieValue(request);
        }
    	
          
        final TicketGrantingTicket ticketGrantingTicket = 
        		this.ticketRegistry.getTicket(tgtId, TicketGrantingTicket.class);

        Authentication authentication = ticketGrantingTicket.getAuthentication();
        
        //org.springframework.security.core.Authentication samlaut = null;
        //Object casAuth = null;
        
        Object externalAuth = null;
        
        
        
        
        if(authentication==null){
        	//let cas manage
        	return success();
        }else{
        	
        	 Object client = null;
        	
        	 // get external auth client name
             String clientName = authentication.getAttributes().get("clientName").toString();
             
             logger.debug("TGT("+tgtId+"), pac4j client: "+ clientName );
        	
        	 if (StringUtils.isNotBlank(clientName)) {
             	
               	Principal principal = authentication.getPrincipal();
                 
                Map<String,Object> principalAttributes = principal.getAttributes();
                 
             	// get external auth
                client = (BaseClient<Credentials, CommonProfile>) this.clients.findClient(clientName);
             
                 
                 // get external auth
                 for (Map.Entry<String,Object> entry : principalAttributes.entrySet()) {
                
                 	logger.debug("CAS Principal Attributes, key: "+entry.getKey() + " value: " + entry.getValue());
                     
                     if("externalAuthentication".equals(entry.getKey())){
                     	//samlaut = (org.springframework.security.core.Authentication) entry.getValue();
                     	externalAuth = (org.springframework.security.core.Authentication) entry.getValue();
                     }
                     
                 }  
                 
             
                 // log attributes
                 if(externalAuth!=null){
                	 
                   boolean dologout = false; 
                  	
                   if (client instanceof Saml2ClientWrapper){
                 	
               	   SAMLCredential sAMLCredential =  (SAMLCredential)((org.springframework.security.core.Authentication)externalAuth).getCredentials();
                   List<Attribute> attributes = sAMLCredential.getAttributes();
                     
                     for(int i=0;i<attributes.size();i++){
                      	  org.opensaml.saml2.core.impl.AttributeImpl attribute = (AttributeImpl) attributes.get(i);
                      	 logger.debug("TGT("+tgtId+") Attribute(externalLibAuthentication).credentials.attributes.friendlyName: "+ 
                      	  attribute.getFriendlyName() ); 
                     	  
                           for (XMLObject attributeValue : attribute.getAttributeValues()) {
                            	Element attributeValueElement = attributeValue.getDOM();
                               String value = attributeValueElement.getTextContent();
                               logger.debug(attribute.getFriendlyName()+" value: "+ value ); 
                             }
                      } 
                     
                     
                 	Saml2ClientWrapper saml2ClientWrapper = (Saml2ClientWrapper) client;
              	  
                  	logger.debug("TGT("+tgtId+") "+client +" callbackUrl "+saml2ClientWrapper.getCallbackUrl() );
                
                  	
                  	if(action==null){
                  		
                  		//stop flow, redirect post to idp
                   		logger.debug("pac4j client: "+ clientName +" creating logout saml assertion");
                  		saml2ClientWrapper.logout(webContext,(org.springframework.security.core.Authentication) externalAuth);
                  		dologout = false;
                        return new Event(this, "stop");  // redirect to idp, post request logout assertion
              
                  		
                  	}else{
                  		
                  		if(action.equals("SingleLogout")){
                      		
                      		//ok: process response from my request logout assertion
                          	//ok: log out if response assertion is valid
                      	    //to do :  Process request and send response to the sender in case the request is valid
                      		logger.debug("pac4j client: "+ clientName +" processing logout saml assertion");
                      		dologout = saml2ClientWrapper.processLogout(webContext,(org.springframework.security.core.Authentication)externalAuth);
                      	
                       	}else{
                       		
                       		//incoming assertion not mappet to cas logout flow
                       		logger.error("pac4j client: "+ clientName +" action: "+action+ " isnt supported, incoming assertion not mappet to cas logout flow");
                      		
                       		
                       	}
                  		
                  		
                  	}
                     
                   }   
                   
                   
                   
                   
                   
                   //if (client instanceof CasClientWrapper){
                	//   return new Event(this, "stop");
                   //}
                   
                   
                   if(dologout){
                	   
                	   logger.warn("pac4j client: "+ clientName +" authorized logout proceed cas logout flow");
                	   return success();
                	   
                   }else{
                	   
                	   logger.error("pac4j client: "+ clientName +" has not authorized logout, throw error");
                	   return error();
                	   
                   }
                
                 
                 }else{
                	
                	logger.warn("pac4j client: "+ clientName +" doesnt support logout");
                    return success();
                	
                }
                 
                 
             }else{
             	
            	logger.debug("non not a pac4j auth, carry on");
             	return success();
             	
             }
        	
        	
        	
        	
        	
        	
        }
        
       
            
    }

    
}
