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

package org.opensaml.liberty.binding.encoding;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
//import org.opensaml.Configuration;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.encoding.impl.BaseSAML2MessageEncoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPSOAP11Encoder;
// import org.opensaml.saml2.ecp.RelayState;
import org.opensaml.saml.saml2.ecp.RelayState;
import org.opensaml.soap.util.SOAPSupport;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.soap.common.SOAPObjectBuilder;
import org.opensaml.soap.soap11.Body;
import org.opensaml.soap.soap11.Envelope;
import org.opensaml.ws.soap.util.SOAPHelper;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HTTPTransportUtils;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.util.SAMLMessageContextAdapter;
import org.w3c.dom.Element;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;

import static org.opensaml.saml.common.messaging.SAMLMessageSecuritySupport.signMessage;
import static org.springframework.security.saml.util.SAMLMessageContextAdapter.getOutboundSAMLMessage;

public class HTTPPAOS11Encoder extends BaseSAML2MessageEncoder {

    /**
     * Logger
     */
    private final Logger log = LoggerFactory.getLogger(HTTPSOAP11Encoder.class);

    @Override
    protected void doEncode() throws MessageEncodingException {

        if (!(getMessageContext() instanceof SAMLMessageContext)) {
            log.error("Invalid message context type, this encoder only support SAMLMessageContext");
            throw new MessageEncodingException(
                    "Invalid message context type, this encoder only support SAMLMessageContext");
        }
        SAMLMessageContext samlMsgCtx = (SAMLMessageContext) getMessageContext();
        if (samlMsgCtx.getResponse() == null) {
            log.error("Invalid outbound message transport type, this encoder only support HTTPOutTransport");
            throw new MessageEncodingException(
                    "Invalid outbound message transport type, this encoder only support HTTPOutTransport");
        }

        // Contains the message body

        SAMLObject samlMessage = getOutboundSAMLMessage(samlMsgCtx.);
        if (samlMessage == null) {
            throw new MessageEncodingException("No outbound SAML message contained in message context");
        }

        // Add RelayState SOAP header if required
        if (SAMLMessageContextAdapter.getRelayState(samlMsgCtx) != null) {
            SOAPSupport.addHeaderBlock(samlMsgCtx, getRelayState(SAMLMessageContextAdapter.getRelayState(samlMsgCtx)));
        }

        signMessage(samlMsgCtx);

        // Contains the entire envelope with any specified headers, but no body
        XMLObject outboundEnveloppe = samlMsgCtx.getOutboundMessage();

        Envelope envelope = buildPAOSMessage(samlMessage, outboundEnveloppe);
        Element envelopeElem = marshallMessage(envelope);

        try {
            HttpServletResponse response = samlMsgCtx.getResponse();
            response.setHeader("Cache-control", "no-cache, no-store");
            response.setHeader("Pragma", "no-cache");
            response.setCharacterEncoding("UTF-8");
            response.setContentType("text/xml");
            response.setHeader("SOAPAction", "http://www.oasis-open.org/committees/security");
//            Writer out = new OutputStreamWriter(outTransport.getOutgoingStream(), "UTF-8");
            SerializeSupport.writeNode(envelopeElem, response.getOutputStream());
//            out.flush();
        } catch (UnsupportedEncodingException e) {
            log.error("JVM does not support required UTF-8 encoding");
            throw new MessageEncodingException("JVM does not support required UTF-8 encoding");
        } catch (IOException e) {
            log.error("Unable to write message content to outbound stream", e);
            throw new MessageEncodingException("Unable to write message content to outbound stream", e);
        }

    }

    /**
     * Method creates a relayState element usable with the ECP profile.
     * @param relayStateValue value to include, mustn't be null
     * @return relay state object
     */
    protected RelayState getRelayState(String relayStateValue) {

        if (relayStateValue == null) {
            throw new IllegalArgumentException("RelayStateValue can't be null");
        }
        if (relayStateValue.length() > 80) {
            throw new IllegalArgumentException("Relay state can't exceed size 80 when using ECP profile");
        }

        XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
        SAMLObjectBuilder<RelayState> relayStateBuilder = (SAMLObjectBuilder<RelayState>) builderFactory.getBuilder(RelayState.DEFAULT_ELEMENT_NAME);
        RelayState relayState = relayStateBuilder.buildObject();
        relayState.setSOAP11Actor(RelayState.SOAP11_ACTOR_NEXT);
        relayState.setSOAP11MustUnderstand(true);
        relayState.setValue(relayStateValue);
        return relayState;

    }

    protected Envelope buildPAOSMessage(SAMLObject samlMessage, XMLObject outboundEnvelope) {

        Envelope envelope;
        XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

        if (outboundEnvelope != null && outboundEnvelope instanceof Envelope) {
            // We already have a complete envelope with specified headers that we want to keep.
            envelope = (Envelope) outboundEnvelope;
        } else {
            // We don't have an existing envelope, so we create it.
            SOAPObjectBuilder<Envelope> envBuilder = (SOAPObjectBuilder<Envelope>) builderFactory.getBuilder(Envelope.DEFAULT_ELEMENT_NAME);
            envelope = envBuilder.buildObject();
        }

        SOAPObjectBuilder<Body> bodyBuilder = (SOAPObjectBuilder<Body>) builderFactory.getBuilder(Body.DEFAULT_ELEMENT_NAME);
        Body body = bodyBuilder.buildObject();
        body.getUnknownXMLObjects().add(samlMessage);
        envelope.setBody(body);

        return envelope;

    }

    public String getBindingURI() {
        return SAMLConstants.SAML2_PAOS_BINDING_URI;
    }

    public boolean providesMessageConfidentiality(MessageContext messageContext) throws MessageEncodingException {
        return contextIsSecure(messageContext);
    }

    public boolean providesMessageIntegrity(MessageContext messageContext) throws MessageEncodingException {
        return contextIsSecure(messageContext);
    }

    private boolean contextIsSecure(MessageContext messageContext) throws MessageEncodingException {
        if (!(messageContext instanceof SAMLMessageContext)) {
            log.error("Invalid message context type, this encoder only support SAMLMessageContext");
            throw new MessageEncodingException(
                    "Invalid message context type, this encoder only support SAMLMessageContext");
        }
        SAMLMessageContext context = (SAMLMessageContext) messageContext;
        return context.getRequest().isSecure();
    }

}
