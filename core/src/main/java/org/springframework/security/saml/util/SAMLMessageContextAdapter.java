package org.springframework.security.saml.util;


import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLMetadataContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.messaging.context.SAMLSelfEntityContext;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.springframework.security.saml.context.SAMLMessageContext;

import javax.xml.namespace.QName;

/**
 * Created by p2017bk on 11.09.2017.
 */
public class SAMLMessageContextAdapter {

    static boolean autoGenerate = true;

    static void setInboundSAMLMessage(SAMLMessageContext context, SAMLObject response){

    }

    static void setInboundSAMLMessageAuthenticated(SAMLMessageContext context, boolean isAuthenticated){

    }

    /*[WebSSOProfileImpl / SingleLogoutProfileImpl]
            # context.getLocalEntityId()
            # context.getLocalEntityRole()
            (SPSSODescriptor) context.getLocalEntityRoleMetadata()
            # (IDPSSODescriptor) context.getPeerEntityRoleMetadata()
*/

    static void setOutboundMessage(SAMLMessageContext context, SAMLObject message){

    }
    static void setOutboundSAMLMessage(SAMLMessageContext context,SAMLObject message){

    }
    static void setPeerEntityEndpoint(SAMLMessageContext context, Endpoint endpoint){
        context.getSubcontext(SAMLPeerEntityContext.class, autoGenerate)
                .getSubcontext(SAMLEndpointContext.class, autoGenerate).setEndpoint(endpoint);
    }

    static Endpoint getPeerEntityEndpoint(SAMLMessageContext context){
        return context.getSubcontext(SAMLPeerEntityContext.class, autoGenerate)
                .getSubcontext(SAMLEndpointContext.class, autoGenerate).getEndpoint();
    }

    static void setPeerEntityId(SAMLMessageContext context, String id){
        context.getSubcontext(SAMLPeerEntityContext.class, autoGenerate).setEntityId(id);
    }


    static String getPeerEntityId(SAMLMessageContext context){
        return context.getSubcontext(SAMLPeerEntityContext.class, autoGenerate).getEntityId();
    }

    static void setPeerEntityMetadata(SAMLMessageContext context, EntityDescriptor metadata){

    }

    static void setPeerEntityRole(SAMLMessageContext context, QName role){
        context.getSubcontext(SAMLPeerEntityContext.class, autoGenerate).setRole(role);
    }

    static QName getPeerEntityRole(SAMLMessageContext context){
        return context.getSubcontext(SAMLPeerEntityContext.class, autoGenerate).getRole();
    }

    static void setPeerEntityRoleMetadata(SAMLMessageContext context, RoleDescriptor role){
        context.getSubcontext(SAMLPeerEntityContext.class, autoGenerate).getSubcontext(SAMLMetadataContext.class, autoGenerate).setRoleDescriptor(role);
    }

    static RoleDescriptor getPeerEntityRoleMetadata(SAMLMessageContext context){
        return context.getSubcontext(SAMLPeerEntityContext.class, autoGenerate).getSubcontext(SAMLMetadataContext.class, autoGenerate).getRoleDescriptor();
    }

    /*[WebSSOProfileConsumerImpl]
            # context.getInboundSAMLMessage()
            # context.getPeerEntityId()
            # context.getPeerEntityMetadata()
            context.isInboundSAMLMessageAuthenticated()
            context.getInboundSAMLMessageId()

            [HTTPSOAP11DecoderImpl] context.getInboundMessageTransport();
    [WebSSOProfileECPImpl] context.getOutboundMessageTransport();
    (HTTPOutTransport)*/

     //       [SAMLContextProviderImpl]
    /*static void setMetadataProvider(SAMLMessageContext context, MetadataProvider provider){

    }*/
    /*static void setInboundMessageTransport(SAMLMessageContext context, inTransport){

    }
    static void setOutboundMessageTransport(SAMLMessageContext context, outTransport){

    }*/

    //[SAMLContextProviderImpl]
    static void setLocalEntityId(SAMLMessageContext context, String id){
        context.getSubcontext(SAMLSelfEntityContext.class, autoGenerate).setEntityId(id);
    }

    static String getLocalEntityId(SAMLMessageContext context){
        return context.getSubcontext(SAMLSelfEntityContext.class, autoGenerate).getEntityId();
    }

    static void setLocalEntityRole(SAMLMessageContext context, QName role){
        context.getSubcontext(SAMLSelfEntityContext.class, autoGenerate).setRole(role);
    }

    static QName getLocalEntityRole(SAMLMessageContext context){
        return context.getSubcontext(SAMLSelfEntityContext.class, autoGenerate).getRole();
    }

}
