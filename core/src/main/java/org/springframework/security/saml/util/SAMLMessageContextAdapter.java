package org.springframework.security.saml.util;


import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.messaging.context.*;
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

    private static boolean autoGenerate = true;

    public static void setInboundMessage(SAMLMessageContext context, SAMLObject message){
        context.setMessage(message);
    }

    public static void setInboundSAMLMessage(SAMLMessageContext context, SAMLObject message){
        context.setMessage(message);
    }

    public static void setOutboundMessage(SAMLMessageContext context, SAMLObject message){
        context.setMessage(message);
    }

    public static void setOutboundSAMLMessage(SAMLMessageContext context, SAMLObject message){
        context.setMessage(message);
    }

    public static SAMLObject getInboundMessage(SAMLMessageContext<? extends SAMLObject> context){
        return context.getMessage();
    }

    public static SAMLObject getInboundSAMLMessage(SAMLMessageContext<? extends SAMLObject> context){
        return context.getMessage();
    }

    public static SAMLObject getOutboundMessage(SAMLMessageContext<? extends SAMLObject> context){
        return context.getMessage();
    }

    public static SAMLObject getOutboundSAMLMessage(SAMLMessageContext<? extends SAMLObject> context){
        return context.getMessage();
    }

    public static void setInboundSAMLMessageAuthenticated(SAMLMessageContext context, boolean isAuthenticated){

    }

    public static Boolean isInboundSAMLMessageAuthenticated(SAMLMessageContext context){
        return null; //TODO
    }

    public static void setPeerEntityEndpoint(SAMLMessageContext context, Endpoint endpoint){
        context.getSubcontext(SAMLPeerEntityContext.class, autoGenerate)
                .getSubcontext(SAMLEndpointContext.class, autoGenerate).setEndpoint(endpoint);
    }

    public static Endpoint getPeerEntityEndpoint(SAMLMessageContext context){
        return context.getSubcontext(SAMLPeerEntityContext.class, autoGenerate)
                .getSubcontext(SAMLEndpointContext.class, autoGenerate).getEndpoint();
    }

    public static void setPeerEntityId(SAMLMessageContext context, String id){
        context.getSubcontext(SAMLPeerEntityContext.class, autoGenerate).setEntityId(id);
    }


    public static String getPeerEntityId(SAMLMessageContext context){
        return context.getSubcontext(SAMLPeerEntityContext.class, autoGenerate).getEntityId();
    }

    public static void setPeerEntityMetadata(SAMLMessageContext context, EntityDescriptor metadata){
        context.getSubcontext(SAMLPeerEntityContext.class, autoGenerate)
                .getSubcontext(SAMLMetadataContext.class, autoGenerate).setEntityDescriptor(metadata);
    }

    public static EntityDescriptor getPeerEntityMetadata(SAMLMessageContext context){
        return context.getSubcontext(SAMLPeerEntityContext.class, autoGenerate)
                .getSubcontext(SAMLMetadataContext.class, autoGenerate).getEntityDescriptor();
    }

    public static void setLocalEntityMetadata(SAMLMessageContext context, EntityDescriptor metadata){
        context.getSubcontext(SAMLSelfEntityContext.class, autoGenerate)
                .getSubcontext(SAMLMetadataContext.class, autoGenerate).setEntityDescriptor(metadata);
    }

    public static EntityDescriptor getLocalEntityMetadata(SAMLMessageContext context){
        return context.getSubcontext(SAMLSelfEntityContext.class, autoGenerate)
                .getSubcontext(SAMLMetadataContext.class, autoGenerate).getEntityDescriptor();
    }

    public static void setPeerEntityRole(SAMLMessageContext context, QName role){
        context.getSubcontext(SAMLPeerEntityContext.class, autoGenerate).setRole(role);
    }

    public static QName getPeerEntityRole(SAMLMessageContext context){
        return context.getSubcontext(SAMLPeerEntityContext.class, autoGenerate).getRole();
    }

    public static void setPeerEntityRoleMetadata(SAMLMessageContext context, RoleDescriptor role){
        context.getSubcontext(SAMLPeerEntityContext.class, autoGenerate)
                .getSubcontext(SAMLMetadataContext.class, autoGenerate).setRoleDescriptor(role);
    }

    public static RoleDescriptor getPeerEntityRoleMetadata(SAMLMessageContext context){
        return context.getSubcontext(SAMLPeerEntityContext.class, autoGenerate).getSubcontext(SAMLMetadataContext.class, autoGenerate).getRoleDescriptor();
    }

    public static void setLocalEntityRoleMetadata(SAMLMessageContext context, RoleDescriptor role){
        context.getSubcontext(SAMLSelfEntityContext.class, autoGenerate)
                .getSubcontext(SAMLMetadataContext.class, autoGenerate).setRoleDescriptor(role);
    }

    public static RoleDescriptor getLocalEntityRoleMetadata(SAMLMessageContext context){
        return context.getSubcontext(SAMLSelfEntityContext.class, autoGenerate).getSubcontext(SAMLMetadataContext.class, autoGenerate).getRoleDescriptor();
    }

    /*[WebSSOProfileConsumerImpl]
            # context.getInboundSAMLMessage()
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

    public static String getInboundSAMLMessageId(SAMLMessageContext context) {
        return context.getSubcontext(SAMLMessageInfoContext.class).getMessageId();
    }

    //[SAMLContextProviderImpl]
    public static void setLocalEntityId(SAMLMessageContext context, String id){
        context.getSubcontext(SAMLSelfEntityContext.class, autoGenerate).setEntityId(id);
    }

    public static String getLocalEntityId(SAMLMessageContext context){
        return context.getSubcontext(SAMLSelfEntityContext.class, autoGenerate).getEntityId();
    }

    public static void setLocalEntityRole(SAMLMessageContext context, QName role){
        context.getSubcontext(SAMLSelfEntityContext.class, autoGenerate).setRole(role);
    }

    public static QName getLocalEntityRole(SAMLMessageContext context){
        return context.getSubcontext(SAMLSelfEntityContext.class, autoGenerate).getRole();
    }

}
