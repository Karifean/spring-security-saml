/* Copyright 2010 Vladimir Schaefer
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
import org.opensaml.messaging.decoder.MessageDecoder;
import org.opensaml.messaging.encoder.MessageEncoder;
import org.opensaml.messaging.handler.MessageHandler;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder;
import org.springframework.security.saml.context.SAMLMessageContext;

import java.util.List;

/**
 * Implementation contains a static decoder instance returned in case conditions specified in
 * the subclass are satisfied.
 *
 * @author Vladimir Schaefer
 */
public abstract class SAMLBindingImpl implements SAMLBinding {

    private MessageDecoder decoder;
    private MessageEncoder encoder;

    protected SAMLBindingImpl(MessageDecoder decoder, MessageEncoder encoder) {
        this.decoder = decoder;
        this.encoder = encoder;
    }

    protected static HTTPPostEncoder createHTTPPostEncoder(VelocityEngine velocityEngine)
    {
        HTTPPostEncoder httpPostEncoder = new HTTPPostEncoder();
        httpPostEncoder.setVelocityEngine(velocityEngine);
        return httpPostEncoder;
    }

    public MessageDecoder getMessageDecoder() {
        return decoder;
    }

    public MessageEncoder getMessageEncoder() {
        return encoder;
    }

    public void getHandlers(List<MessageHandler> handlers, SAMLMessageContext samlContext) {
    }

}