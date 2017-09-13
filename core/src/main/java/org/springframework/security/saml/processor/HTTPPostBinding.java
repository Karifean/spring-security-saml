/* Copyright 2010 Mandus Elfving
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
package org.springframework.security.saml.processor;

import org.apache.velocity.app.VelocityEngine;
import org.opensaml.common.binding.security.SAMLProtocolMessageXMLSignatureSecurityPolicyRule;
import org.opensaml.messaging.handler.MessageHandler;
import org.opensaml.saml.common.binding.security.impl.SAMLProtocolMessageXMLSignatureSecurityHandler;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPPostDecoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder;
import org.opensaml.saml.saml2.binding.security.impl.SAML2HTTPPostSimpleSignSecurityHandler;
import org.opensaml.saml2.binding.security.SAML2HTTPPostSimpleSignRule;
import org.opensaml.messaging.decoder.MessageDecoder;
import org.opensaml.messaging.encoder.MessageEncoder;
import org.opensaml.ws.security.SecurityPolicyRule;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.springframework.security.saml.context.SAMLMessageContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

/**
 * Http POST binding.
 *
 * @author Mandus Elfving
 */
public class HTTPPostBinding extends SAMLBindingImpl {

    /**
     * Pool for message deserializers.
     */
    protected ParserPool parserPool;

    /**
     * Creates default implementation of the binding.
     *
     * @param parserPool     parserPool for message deserialization
     * @param velocityEngine engine for message formatting
     */
    public HTTPPostBinding(ParserPool parserPool, VelocityEngine velocityEngine) {
        this(parserPool, new HTTPPostDecoder(/* parserPool */), createHTTPPostEncoder(velocityEngine));
    }

    /**
     * Implementation of the binding with custom encoder and decoder.
     *
     * @param parserPool     parserPool for message deserialization
     * @param decoder custom decoder implementation
     * @param encoder custom encoder implementation
     */
    public HTTPPostBinding(ParserPool parserPool, MessageDecoder decoder, MessageEncoder encoder) {
        super(decoder, encoder);
        this.parserPool = parserPool;
    }

    public boolean supports(HttpServletRequest request) {
        return "POST".equalsIgnoreCase(request.getMethod()) &&
                (request.getParameter("SAMLRequest") != null ||
                        request.getParameter("SAMLResponse") != null);
    }

    public boolean supports(HttpServletResponse response) {
        return true;
    }

    public String getBindingURI() {
        return SAMLConstants.SAML2_POST_BINDING_URI;
    }

    @Override
    public void getHandlers(List<MessageHandler> handlers, SAMLMessageContext samlContext) {

        SignatureTrustEngine engine = samlContext.getLocalTrustEngine();
        //TODO securityPolicy.add(new SAML2HTTPPostSimpleSignRule(engine, parserPool, engine.getKeyInfoResolver()));
        //TODO securityPolicy.add(new SAMLProtocolMessageXMLSignatureSecurityPolicyRule(engine));
        SAML2HTTPPostSimpleSignSecurityHandler saml2HTTPPostSimpleSignSecurityHandler = new SAML2HTTPPostSimpleSignSecurityHandler();
        saml2HTTPPostSimpleSignSecurityHandler.setParser(parserPool);
        saml2HTTPPostSimpleSignSecurityHandler.setKeyInfoResolver(engine.getKeyInfoResolver());
        handlers.add(saml2HTTPPostSimpleSignSecurityHandler);
        SAMLProtocolMessageXMLSignatureSecurityHandler samlProtocolMessageXMLSignatureSecurityHandler = new SAMLProtocolMessageXMLSignatureSecurityHandler();
        handlers.add(samlProtocolMessageXMLSignatureSecurityHandler);

    }

}