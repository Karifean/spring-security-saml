/* Copyright 2011 Vladimir Schaefer
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
package org.springframework.security.saml.metadata;

import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.filter.MetadataFilter;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.util.Assert;

import java.util.LinkedList;
import java.util.List;
import java.util.Observer;

//import org.opensaml.saml2.metadata.provider.*;

/**
 * Class wraps an existing provider and delegates all method calls to it. Subclasses can thus add additional functionality
 * to existing implementations.
 *
 * @author Vladimir Schaefer
 */
public abstract class AbstractMetadataDelegate implements MetadataResolver /*  ObservableMetadataProvider */ {

    /**
     * Wrapped entity the calls are delegated to.
     */
    private MetadataResolver delegate;

    /**
     * Observers, loaded from the provider.
     */
    List<Observer> observers;

    /**
     * Default constructor assigning the delegate. In case the provider implements observable interface the observation
     * of this instance is delegated as well, otherwise an empty independent list of observers is created.
     *
     * @param delegate delegate to use, can't be null
     */
    public AbstractMetadataDelegate(MetadataResolver delegate) {
        Assert.notNull(delegate, "Delegate can't be null");
        this.delegate = delegate;
/*
        if (delegate instanceof ObservableMetadataProvider) {
            observers = ((ObservableMetadataProvider) delegate).getObservers();
        } else {
            observers = new LinkedList<Observer>();
        }
*/
        observers = new LinkedList<Observer>();
    }

    public boolean isRequireValidMetadata() {
        return delegate.isRequireValidMetadata();
    }

    public void setRequireValidMetadata(boolean requireValidMetadata) {
        delegate.setRequireValidMetadata(requireValidMetadata);
    }

    public MetadataFilter getMetadataFilter() {
        return delegate.getMetadataFilter();
    }

    public void setMetadataFilter(MetadataFilter newFilter) /* throws MetadataProviderException */ {
        delegate.setMetadataFilter(newFilter);
    }

/*
    public XMLObject getMetadata() throws MetadataProviderException {
        return delegate.getMetadata();
    }

    public EntitiesDescriptor getEntitiesDescriptor(String name) throws MetadataProviderException {
        return delegate.getEntitiesDescriptor(name);
    }
*/
    public EntityDescriptor getEntityDescriptor(String entityID) /* throws MetadataProviderException */ {
//        return delegate.getEntityDescriptor(entityID);
        throw new RuntimeException("TODO getEntityDescriptor");
    }

/*
    public List<RoleDescriptor> getRole(String entityID, QName roleName) throws MetadataProviderException {
        return delegate.getRole(entityID, roleName);
    }

    public RoleDescriptor getRole(String entityID, QName roleName, String supportedProtocol) throws MetadataProviderException {
        return delegate.getRole(entityID, roleName, supportedProtocol);
    }
*/

    public List<Observer> getObservers() {
        return observers;
    }

    /**
     * @return original object the calls are delegated to
     */
    public MetadataResolver getDelegate() {
        return delegate;
    }

    /**
     * Equality is based on the object this class delegates to.
     * @param obj object
     * @return true when obj equals delegate, in case obj is a wrapper itself only its delegate is compared
     */
    @Override
    public boolean equals(Object obj) {
        if (obj instanceof ExtendedMetadataDelegate) {
            ExtendedMetadataDelegate del = (ExtendedMetadataDelegate) obj;
            return delegate.equals(del.getDelegate());
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return delegate.hashCode();
    }

}