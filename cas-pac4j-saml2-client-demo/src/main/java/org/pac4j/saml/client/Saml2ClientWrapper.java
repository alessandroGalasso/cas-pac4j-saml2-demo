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
package org.pac4j.saml.client;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.impl.AttributeImpl;
import org.opensaml.saml2.core.impl.NameIDImpl;
import org.opensaml.xml.XMLObject;
import org.pac4j.core.client.BaseClient;
import org.pac4j.core.client.Protocol;
import org.pac4j.core.client.RedirectAction;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.exception.RequiresHttpAction;
import org.pac4j.saml.credentials.Saml2Credentials;
import org.pac4j.saml.profile.Saml2Profile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.w3c.dom.Element;


public class Saml2ClientWrapper extends BaseClient<Saml2Credentials, Saml2Profile> {

    protected static final Logger logger = LoggerFactory.getLogger(Saml2ClientWrapper.class);

    private SAMLEntryPoint sAMLEntryPoint;
    
    private SAMLProcessingFilter sAMLProcessingFilter;
    
    private SAMLLogoutProcessingFilter sAMLLogoutProcessingFilter;
    
    private SAMLLogoutFilter sAMLLogoutFilter=null;
    
    private String attributeOverwriteId = null;
	
  
	public String getAttributeOverwriteId() {
		return attributeOverwriteId;
	}

	public void setAttributeOverwriteId(String attributeOverwriteId) {
		this.attributeOverwriteId = attributeOverwriteId;
	}

	public SAMLLogoutProcessingFilter getsAMLLogoutProcessingFilter() {
		return sAMLLogoutProcessingFilter;
	}

	public void setsAMLLogoutProcessingFilter(
			SAMLLogoutProcessingFilter sAMLLogoutProcessingFilter) {
		this.sAMLLogoutProcessingFilter = sAMLLogoutProcessingFilter;
	}

	public SAMLLogoutFilter getsAMLLogoutFilter() {
		return sAMLLogoutFilter;
	}

	public void setsAMLLogoutFilter(SAMLLogoutFilter sAMLLogoutFilter) {
		this.sAMLLogoutFilter = sAMLLogoutFilter;
	}



	public SAMLEntryPoint getsAMLEntryPoint() {
		return sAMLEntryPoint;
	}

	public void setsAMLEntryPoint(SAMLEntryPoint sAMLEntryPoint) {
		this.sAMLEntryPoint = sAMLEntryPoint;
	}

	public SAMLProcessingFilter getsAMLProcessingFilter() {
		return sAMLProcessingFilter;
	}

	public void setsAMLProcessingFilter(SAMLProcessingFilter sAMLProcessingFilter) {
		this.sAMLProcessingFilter = sAMLProcessingFilter;
	}

	@Override
    protected void internalInit() {
    }


	

    @Override
    protected Saml2Profile retrieveUserProfile(final Saml2Credentials credentials, final WebContext context) {

    	String overwriteId = null;
   	
        Saml2Profile profile = new Saml2Profile();
        
        profile.setId(credentials.getNameId().getValue());
      
         for (Attribute attribute2 : credentials.getAttributes()) {
       
       		AttributeImpl attribute = (AttributeImpl) attribute2;
        	
            List<String> values = new ArrayList<String>();
            
            for (XMLObject attributeValue : attribute.getAttributeValues()) {
               
            	Element attributeValueElement = attributeValue.getDOM();
                
                String value = attributeValueElement.getTextContent();
                
                values.add(value);
                
                if(attributeOverwriteId.equals(attribute.getFriendlyName())){ 
                	overwriteId =  value;  
                }
                
            }
            
            profile.addAttribute(attribute.getName(), values);
   
         }
        
        
        if(attributeOverwriteId!=null){
        	profile.setId(overwriteId);
        }
        
        profile.addAttribute("externalAuthentication",credentials.getExternalAuthentication());
        
        return profile;
    }

	
    @Override
    protected BaseClient<Saml2Credentials, Saml2Profile> newClient() {
    	Saml2ClientWrapper client = new Saml2ClientWrapper();
         return client;
    }

    @Override
    protected boolean isDirectRedirection() {
        
    	//true to go directly to idp
    	return false;
    }

    
    @Override
    protected RedirectAction retrieveRedirectAction(final WebContext wc) {
	   
	   try {
	   
	   J2EContext jc = (J2EContext) wc;
	   HttpServletRequest request = jc.getRequest();
       HttpServletResponse response = jc.getResponse();
       
       AuthenticationException e = null;
       
       sAMLEntryPoint.commencePac4j(request, response, e);
     
	
       } catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (ServletException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
       
	   return RedirectAction.dummy("dummy");
        
    }
    
    
 
    
    
    
    public boolean processLogout(final WebContext wc,org.springframework.security.core.Authentication authenticationsaml) {

      J2EContext jc = (J2EContext) wc;
   	  HttpServletRequest request = jc.getRequest();
      HttpServletResponse response = jc.getResponse();
      
      boolean dologout = false;
     	  
      try {
		
    	  //to do :  Process request and send response to the sender in case the request is valid
    	  dologout = sAMLLogoutProcessingFilter.processLogoutPac4j(request, response,authenticationsaml);
		
       } catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ServletException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	  
        return dologout;
    }
    
    
    
    
    
    
    
    public String logout(final WebContext wc,org.springframework.security.core.Authentication authenticationsaml
    		) {

      J2EContext jc = (J2EContext) wc;
   	  HttpServletRequest request = jc.getRequest();
      HttpServletResponse response = jc.getResponse();
      
     	  
      try {
		
    	  sAMLLogoutFilter.processLogoutPac4j(request, response,authenticationsaml);
		
       } catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ServletException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	  
        return "SingleLogout";
    }
    
    
    protected Saml2Credentials retrieveCredentials(final WebContext wc) throws RequiresHttpAction {
    	
      J2EContext jc = (J2EContext) wc;
   	  HttpServletRequest request = jc.getRequest();
      HttpServletResponse response = jc.getResponse();
    	
      org.springframework.security.core.Authentication samlAuthentication
      = sAMLProcessingFilter.attemptAuthentication(request, response);
    	
     NameID nameID = (NameID) samlAuthentication.getPrincipal();
      
     SAMLCredential sAMLCredential =  (SAMLCredential) samlAuthentication.getCredentials();
        
      List<Attribute> attributes = sAMLCredential.getAttributes();
        
       Saml2Credentials saml2Credentials = 
      		new	Saml2Credentials(
       				nameID,
      				attributes,
      				this.getClass().getSimpleName(),
      				samlAuthentication
      				);
      
      return saml2Credentials;

    }
    
   
    @Override
    public Protocol getProtocol() {
        return Protocol.SAML;
    }



    
    

}
