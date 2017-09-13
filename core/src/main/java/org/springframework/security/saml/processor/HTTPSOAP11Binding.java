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

import org.opensaml.messaging.decoder.MessageDecoder;
import org.opensaml.messaging.handler.MessageHandler;
import org.opensaml.saml.common.binding.security.impl.SAMLProtocolMessageXMLSignatureSecurityHandler;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPSOAP11Encoder;
import org.opensaml.saml2.binding.decoding.HTTPSOAP11DecoderImpl;
import org.opensaml.messaging.encoder.MessageEncoder;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.springframework.security.saml.context.SAMLMessageContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

/**
 * Http SOAP 1.1 binding.
 *
 * @author Mandus Elfving, Vladimir Schaefer
 */
public class HTTPSOAP11Binding extends SAMLBindingImpl {

    /**
     * Creates binding with default encoder and decoder.
     *
     * @param parserPool parser pool
     */
    public HTTPSOAP11Binding(ParserPool parserPool) {
        this(new HTTPSOAP11DecoderImpl(parserPool), new HTTPSOAP11Encoder());
    }

    /**
     * Constructor with customized encoder and decoder
     *
     * @param decoder decoder
     * @param encoder encoder
     */
    public HTTPSOAP11Binding(MessageDecoder decoder, MessageEncoder encoder) {
        super(decoder, encoder);
    }

    public boolean supports(HttpServletRequest request) {
        return "POST".equalsIgnoreCase(request.getMethod()) && request.getContentType() != null && request.getContentType().startsWith("text/xml");
    }

    public boolean supports(HttpServletResponse response) {
        return true;
    }

    public String getBindingURI() {
        return SAMLConstants.SAML2_SOAP11_BINDING_URI;
    }

    @Override
    public void getHandlers(List<MessageHandler> handlers, SAMLMessageContext samlContext) {

        SignatureTrustEngine engine = samlContext.getLocalTrustEngine();
        //TODO securityPolicy.add(new SAMLProtocolMessageXMLSignatureSecurityPolicyRule(engine));

        SAMLProtocolMessageXMLSignatureSecurityHandler samlProtocolMessageXMLSignatureSecurityHandler = new SAMLProtocolMessageXMLSignatureSecurityHandler();
        handlers.add(samlProtocolMessageXMLSignatureSecurityHandler);

    }

}