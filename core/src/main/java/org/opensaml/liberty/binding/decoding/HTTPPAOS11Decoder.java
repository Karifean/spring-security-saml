/*
 * Copyright 2010 Jonathan Tellier
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.opensaml.liberty.binding.decoding;

import java.util.ArrayList;
import java.util.List;

import javax.xml.namespace.QName;

//import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPSOAP11Decoder;
import org.opensaml.saml.saml2.ecp.RelayState;
import org.opensaml.saml.saml2.ecp.impl.RelayStateImpl;
//import org.opensaml.ws.message.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.soap.soap11.Envelope;
import org.opensaml.core.xml.XMLObject;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.springframework.security.saml.context.SAMLMessageContext;

import static org.springframework.security.saml.util.SAMLMessageContextAdapter.setRelayState;

public class HTTPPAOS11Decoder extends HTTPSOAP11Decoder {

    public HTTPPAOS11Decoder() {
        super();
        initUnderstoodHeaders();
    }

    public HTTPPAOS11Decoder(ParserPool pool) {
        super();
        initUnderstoodHeaders();
    }

    private void initUnderstoodHeaders() {
        QName paosResponse = new QName(SAMLConstants.PAOS_NS,
                "Response", SAMLConstants.PAOS_PREFIX);
        
        List<QName> headerNames = new ArrayList<QName>();
        headerNames.add(paosResponse);
        
        setUnderstoodHeaders(headerNames);
    }

    @Override
    protected void doDecode(/* MessageContext messageContext */)
            throws MessageDecodingException {
        super.doDecode(/* messageContext */);
        
        // Setting the RelayState in the message context
        SAMLMessageContext samlMsgCtx = (SAMLMessageContext) getMessageContext();
        Envelope soapMessage = (Envelope) samlMsgCtx.getInboundMessage();
        
        List<XMLObject> relayStateHeader = soapMessage.getHeader().getUnknownXMLObjects(
                new QName(SAMLConstants.SAML20ECP_NS,
                        RelayState.DEFAULT_ELEMENT_LOCAL_NAME,
                        SAMLConstants.SAML20ECP_PREFIX));
        
        if (relayStateHeader.size() == 1
            && relayStateHeader.get(0) instanceof RelayStateImpl) {
            setRelayState(samlMsgCtx, ((RelayStateImpl) relayStateHeader.get(0)).getValue());
        }
    }

}
