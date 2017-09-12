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
import org.opensaml.messaging.encoder.MessageEncoder;
import org.opensaml.ws.security.SecurityPolicyRule;
import org.springframework.security.saml.context.SAMLMessageContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

/**
 * Implementation describes a single binding usable for parsing of a SAML message.
 *
 * @author Mandus Elfving
 */
public interface SAMLBinding {

    /**
     * Checks whether current binding can be used to extract SAML message from the request.
     *
     * @param request verify whether this binding supports given transport mechanism
     * @return true if this binding can be used to parse SAML message
     */
    boolean supports(HttpServletRequest request);

    /**
     * Checks whether current binding can be used to send a message using given transport.
     *
     * @param response verify whether this binding supports given transport mechanism
     * @return true if this binding can be used to send message over the transport
     */
    boolean supports(HttpServletResponse response);

    /**
     * Creates decoder capable of parsing message with the given binding
     *
     * @return instance of the decoder
     */
    MessageDecoder getMessageDecoder();

    /**
     * Creates encoder capable of creating messages to be sent using given bindidn.
     *
     * @return encoder
     */
    MessageEncoder getMessageEncoder();

    /**
     * Binding identifier.
     *
     * @return identifier
     */
    String getBindingURI();

    /**
     * Security rules to apply for incoming SAML messages received using the binding.
     *
     * @param securityPolicy storage for created policies
     * @param samlContext processed context
     */
     void getSecurityPolicy(List<SecurityPolicyRule> securityPolicy, SAMLMessageContext samlContext);

}