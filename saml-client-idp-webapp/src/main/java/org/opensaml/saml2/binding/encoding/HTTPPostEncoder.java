/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.opensaml.saml2.binding.encoding;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;

import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.StatusResponseType;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HTTPTransportUtils;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SAML 2.0 HTTP Post binding message encoder.
 */
public class HTTPPostEncoder extends BaseSAML2MessageEncoder {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(HTTPPostEncoder.class);

    /** Velocity engine used to evaluate the template when performing POST encoding. */
    private VelocityEngine velocityEngine;

    /** ID of the Velocity template used when performing POST encoding. */
    private String velocityTemplateId;

    /**
     * Constructor.
     * 
     * @param engine Velocity engine instance used to create POST body
     * @param templateId ID of the template used to create POST body
     */
    public HTTPPostEncoder(VelocityEngine engine, String templateId) {
        super();
        velocityEngine = engine;
        velocityTemplateId = templateId;
    }

    /** {@inheritDoc} */
    public String getBindingURI() {
        return SAMLConstants.SAML2_POST_BINDING_URI;
    }

    /** {@inheritDoc} */
    public boolean providesMessageConfidentiality(MessageContext messageContext) throws MessageEncodingException {
        return false;
    }

    /** {@inheritDoc} */
    public boolean providesMessageIntegrity(MessageContext messageContext) throws MessageEncodingException {
        return false;
    }

    /** {@inheritDoc} */
    protected void doEncode(MessageContext messageContext) throws MessageEncodingException {
    	
    	
    	System.out.println("---> doEncode");
		
    	
    	
        if (!(messageContext instanceof SAMLMessageContext)) {
            log.error("Invalid message context type, this encoder only support SAMLMessageContext");
            throw new MessageEncodingException(
                    "Invalid message context type, this encoder only support SAMLMessageContext");
        }

        if (!(messageContext.getOutboundMessageTransport() instanceof HTTPOutTransport)) {
            log.error("Invalid outbound message transport type, this encoder only support HTTPOutTransport");
            throw new MessageEncodingException(
                    "Invalid outbound message transport type, this encoder only support HTTPOutTransport");
        }

        SAMLMessageContext samlMsgCtx = (SAMLMessageContext) messageContext;

        SAMLObject outboundMessage = samlMsgCtx.getOutboundSAMLMessage();
        if (outboundMessage == null) {
            throw new MessageEncodingException("No outbound SAML message contained in message context");
        }
        String endpointURL = getEndpointURL(samlMsgCtx).buildURL();

        if (samlMsgCtx.getOutboundSAMLMessage() instanceof StatusResponseType) {
            ((StatusResponseType) samlMsgCtx.getOutboundSAMLMessage()).setDestination(endpointURL);
        }

        signMessage(samlMsgCtx);
        samlMsgCtx.setOutboundMessage(outboundMessage);

        postEncode(samlMsgCtx, endpointURL);
    }

    /**
     * Base64 and POST encodes the outbound message and writes it to the outbound transport.
     * 
     * @param messageContext current message context
     * @param endpointURL endpoint URL to which to encode message
     * 
     * @throws MessageEncodingException thrown if there is a problem encoding the message
     */
    protected void postEncode(SAMLMessageContext messageContext, String endpointURL) throws MessageEncodingException {
        log.debug("Invoking Velocity template to create POST body");
        try {
        	
        	
        	System.out.println("---> postEncode");
    		
            
        	
            VelocityContext context = new VelocityContext();

            populateVelocityContext(context, messageContext, endpointURL);

            HTTPOutTransport outTransport = (HTTPOutTransport) messageContext.getOutboundMessageTransport();
            HTTPTransportUtils.addNoCacheHeaders(outTransport);
            HTTPTransportUtils.setUTF8Encoding(outTransport);
            HTTPTransportUtils.setContentType(outTransport, "text/html");

            if(1==1){
            Writer out = new OutputStreamWriter(outTransport.getOutgoingStream(), "UTF-8");
            velocityEngine.mergeTemplate(velocityTemplateId, "UTF-8", context, out);
            out.flush();
            }else{
            	
            	  Writer out = new OutputStreamWriter(outTransport.getOutgoingStream(), "UTF-8");
                  velocityEngine.mergeTemplate(velocityTemplateId, "UTF-8", context, out);
                         
                  out.write("iiiiiiiiiiiiiiiiiiiiiiiiiiiii");
                  out.flush();
                  
                  
                  
                  //questo stampa esattamente la post al server idp con la richieta di auth
                  
                  
                  /*
                <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
    				<body onload="document.forms[0].submit()">
        		<noscript>
            		<p>
                		<strong>Note:</strong> Since your browser does not support JavaScript,
                		you must press the Continue button once to proceed.
            		</p>
        		</noscript>
        
        			<form action="https&#x3a;&#x2f;&#x2f;idp.alessandro.it&#x2f;idp&#x2f;profile&#x2f;SAML2&#x2f;POST&#x2f;SSO" method="post">
            			<div>
                                
                		<input type="hidden" name="SAMLRequest" value="PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDJwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1sMnA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgQXNzZXJ0aW9uQ29uc3VtZXJTZXJ2aWNlVVJMPSJodHRwczovL2FwcC5hbGVzc2FuZHJvLml0OjI0NDMvc3ByaW5nLXNlY3VyaXR5LXNhbWwyLXNhbXBsZS9zYW1sL1NTTy9hbGlhcy9hcHAuYWxlc3NhbmRyby5pdCIgRGVzdGluYXRpb249Imh0dHBzOi8vaWRwLmFsZXNzYW5kcm8uaXQvaWRwL3Byb2ZpbGUvU0FNTDIvUE9TVC9TU08iIEZvcmNlQXV0aG49ImZhbHNlIiBJRD0iYTUwMDVlYmZqOGQyMTJqMjM4MGQ0aTRnNmY4Z2RpMiIgSXNQYXNzaXZlPSJmYWxzZSIgSXNzdWVJbnN0YW50PSIyMDE0LTA3LTE3VDAwOjIwOjM5LjkyNVoiIFByb3RvY29sQmluZGluZz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmJpbmRpbmdzOkhUVFAtQXJ0aWZhY3QiIFZlcnNpb249IjIuMCI+PHNhbWwyOklzc3VlciB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+YXBwLmFsZXNzYW5kcm8uaXQ8L3NhbWwyOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48ZHM6U2lnbmVkSW5mbz48ZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjcnNhLXNoYTEiLz48ZHM6UmVmZXJlbmNlIFVSST0iI2E1MDA1ZWJmajhkMjEyajIzODBkNGk0ZzZmOGdkaTIiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8+PGRzOkRpZ2VzdFZhbHVlPmdCODN1cktxY0txRWFPTThpTmtiWUJJcWREND08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWU+YXM4OG5xVHVPbXRwYksxclAyVjRSeUxrUUs1Zkw5SW9kUk1sam42RjFpaTdNSHFocVMzb05sdDFtWi9Ma0VDZWowK25NNXRxNU1ncmJMQXB0ejhncFY3aDlpRzVoNjRRcjFHL1cwaTVaZis3elNsSVVXc2IveDNOOFJydlJkY1lmaFNOVlpMZkg5MldKZ2pNay91L0RKTnVaWW9qRlBGOUduRUZRV1JvSnA4NHJMeldlTHc2L3JvZXR2c2d4NFJPY2RrT2Rrd0dPeEdrdXFNTWhXKzNHREdxVkk2QTlmT2xlODVwcnptV293NzM5Z3NuWENmVUkyNEVtdGM2NE85cFRBWVZ1MXI2YTVvYk1qaDhBZnNJMDdqclhxdEU3V2pjbW45blMreFg2c2IybVhFSW9meXdVSThoaGU2WW01VHArR3hObWdnMjQvZDFsb0RaOXE0Y1BRPT08L2RzOlNpZ25hdHVyZVZhbHVlPjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1JSURmekNDQW1lZ0F3SUJBZ0lFR01ZM2NEQU5CZ2txaGtpRzl3MEJBUVVGQURCd01Rc3dDUVlEVlFRR0V3SkpWREVRTUE0R0ExVUUNCkNCTUhWVzVyYm05M2JqRVFNQTRHQTFVRUJ4TUhWVzVyYm05M2JqRVFNQTRHQTFVRUNoTUhWVzVyYm05M2JqRVFNQTRHQTFVRUN4TUgNClZXNXJibTkzYmpFWk1CY0dBMVVFQXhNUWMzQXVZV3hsYzNOaGJtUnlieTVwZERBZUZ3MHhOREEzTURjeE1EQTRORE5hRncweE5ERXcNCk1EVXhNREE0TkROYU1IQXhDekFKQmdOVkJBWVRBa2xVTVJBd0RnWURWUVFJRXdkVmJtdHViM2R1TVJBd0RnWURWUVFIRXdkVmJtdHUNCmIzZHVNUkF3RGdZRFZRUUtFd2RWYm10dWIzZHVNUkF3RGdZRFZRUUxFd2RWYm10dWIzZHVNUmt3RndZRFZRUURFeEJ6Y0M1aGJHVnoNCmMyRnVaSEp2TG1sME1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBaFhRREpKdmM0Y0JQSTBDY0wwbXMNCjRxNndVOEtvcGVLb1Q5bGFDMVVBRDBDRnQ0MHBrWTNCcHdUSkZlR3dlZU9RZzNkL1pnekFWY1I4bXRvRHBXR3ExN29GL0ZPWUNTUy8NCmR2WkhwK2NtM0tTUTFTT29ZaFRvK0QxYzZ3dzNJWDdkZk9wc1djYjR0ejUwTWZkS21SOFFNVEthTW5nYnZZcnlPT0lUcDdkemplV2YNCnhUTDlFUFdwcE5GaVcyWFBDaEJuMllPNUFUYkRlWUEzQ2NCYklQK1ZFbGQ4bXM5VnNsc0V6Y25adkI3R096dmNucTlKbnFsMlhIdGcNCnBWZ2pTRXZONUZJQkRFZGJtaWNqUEZLMjFPdmtZUFFMVllXM1JRTGR5UGxoUVcrVlFJNU5Pbks1T09URS9JQ3BNZE1oT0NxVDBmdDgNCnpQUCtSZVdDM1dPVWsxdk1qUUlEQVFBQm95RXdIekFkQmdOVkhRNEVGZ1FVYjdqbFA4QnJIU1p0RXJtL09OVTVpamNUOXNJd0RRWUoNCktvWklodmNOQVFFRkJRQURnZ0VCQUZxcVUwVTUzTVZjSURPcmFaVGxGdStxeVliaXBpTlZFTTdaRTBJV3drMU1yVEFOS1dHbFNMNFMNCnNCVHk2anFUa1NwaCt6cjV5TGQ2N1o2UVBLUTFMeTdyaEJMVXFZSFcwRW5GUHRWRTR3YWRtbjJrNVpVVkxwNEpFdEhRWm0vZ080ZGYNCkFsOWV2RXE5S05xbzJWSGMzVWowOWV4WmljZytybzBDSHJMb3I4d1V2ZXM3M2ZraTZIRXVuSUlJYlgzdEJvK0tLSzZHN0w4MFpkd3ENCit1Tzh3Wmo0cEdmbkhLYjRnRS9GaEdWMVV5V3pCcnpXSFJKMVo4TjlrK1Y3UkJZc0tiZXl5b29Ncm56Rm5NbDFVQkJsdE9VUXlhK3cNCnVVelppUGxIa1lUYXlscjVPejZVanZPd1JNT2tUQlFwcW9QdlhUQUNKTGdob2w0SGZER1crNlJCVG80PTwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPjwvc2FtbDJwOkF1dGhuUmVxdWVzdD4="/>                
                                
            		</div>
            		<noscript>
                		<div>
                    	<input type="submit" value="Continue"/>
                		</div>
            		</noscript>
        		</form>
        
    			</body>
				</html>iiiiiiiiiiiiiiiiiiiiiiiiiiiii
            	
            	*/
            }
            
            
            
        } catch (Exception e) {
            log.error("Error invoking Velocity template", e);
            throw new MessageEncodingException("Error creating output document", e);
        }
    }

    /**
     * Populate the Velocity context instance which will be used to render the POST body.
     * 
     * @param velocityContext the Velocity context instance to populate with data
     * @param messageContext the SAML message context source of data
     * @param endpointURL endpoint URL to which to encode message
     * @throws MessageEncodingException thrown if there is a problem encoding the message
     */
    protected void populateVelocityContext(VelocityContext velocityContext, SAMLMessageContext messageContext,
            String endpointURL) throws MessageEncodingException {
        
        Encoder esapiEncoder = ESAPI.encoder();

        String encodedEndpointURL = esapiEncoder.encodeForHTMLAttribute(endpointURL);
        log.debug("Encoding action url of '{}' with encoded value '{}'", endpointURL, encodedEndpointURL);
        velocityContext.put("action", encodedEndpointURL);
        velocityContext.put("binding", getBindingURI());

        log.debug("Marshalling and Base64 encoding SAML message");
        if (messageContext.getOutboundSAMLMessage().getDOM() == null) {
            marshallMessage(messageContext.getOutboundSAMLMessage());
        }
        try {
            String messageXML = XMLHelper.nodeToString(messageContext.getOutboundSAMLMessage().getDOM());
            String encodedMessage = Base64.encodeBytes(messageXML.getBytes("UTF-8"), Base64.DONT_BREAK_LINES);
            if (messageContext.getOutboundSAMLMessage() instanceof RequestAbstractType) {
                velocityContext.put("SAMLRequest", encodedMessage);
            } else if (messageContext.getOutboundSAMLMessage() instanceof StatusResponseType) {
                velocityContext.put("SAMLResponse", encodedMessage);
            } else {
                throw new MessageEncodingException(
                        "SAML message is neither a SAML RequestAbstractType or StatusResponseType");
            }
        } catch (UnsupportedEncodingException e) {
            log.error("UTF-8 encoding is not supported, this VM is not Java compliant.");
            throw new MessageEncodingException("Unable to encode message, UTF-8 encoding is not supported");
        }

        String relayState = messageContext.getRelayState();
        if (checkRelayState(relayState)) {
            String encodedRelayState = esapiEncoder.encodeForHTMLAttribute(relayState);
            log.debug("Setting RelayState parameter to: '{}', encoded as '{}'", relayState, encodedRelayState);
            velocityContext.put("RelayState", encodedRelayState);
        }
    }
}