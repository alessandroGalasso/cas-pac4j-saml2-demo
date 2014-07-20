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

package org.opensaml.saml2.core.impl;

import org.opensaml.saml2.core.NameID;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

/**
 * Concrete implementation of {@link org.opensaml.saml2.core.NameID}.
 */
public class NameIDImpl extends AbstractNameIDType implements NameID, Serializable {

	private static final long serialVersionUID = 7526476543622776147L;
	
	
    /**
     * Constructor.
     *
     * @param namespaceURI the namespace the element is in
     * @param elementLocalName the local name of the XML element this Object represents
     * @param namespacePrefix the prefix for the given namespace
     */
    protected NameIDImpl(String namespaceURI, String elementLocalName, String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
    }
     
    /**
     * Always treat de-serialization as a full-blown constructor, by
     * validating the final state of the de-serialized object.
     */
     private void readObject(
       ObjectInputStream aInputStream
     ) throws ClassNotFoundException, IOException {
       aInputStream.defaultReadObject();
     }

      /**
      * This is the default implementation of writeObject.
      * Customise if necessary.
      */
      private void writeObject(
        ObjectOutputStream aOutputStream
      ) throws IOException {
        aOutputStream.defaultWriteObject();
      }
   
    
    
    
    
    
    
    
    
    
    
    
    
    
}