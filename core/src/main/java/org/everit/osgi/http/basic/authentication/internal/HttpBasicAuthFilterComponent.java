/**
 * This file is part of Everit - HTTP Basic Authentication.
 *
 * Everit - HTTP Basic Authentication is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Everit - HTTP Basic Authentication is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Everit - HTTP Basic Authentication.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.everit.osgi.http.basic.authentication.internal;

import java.util.Dictionary;
import java.util.Hashtable;
import java.util.Map;

import javax.servlet.Filter;

import org.apache.felix.http.whiteboard.HttpWhiteboardConstants;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.ConfigurationPolicy;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.everit.osgi.authentication.context.AuthenticationPropagator;
import org.everit.osgi.authenticator.Authenticator;
import org.everit.osgi.http.basic.authentication.HttpBasicAuthFilterConstants;
import org.everit.osgi.resource.resolver.ResourceIdResolver;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.cm.ConfigurationException;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.log.LogService;

@Component(name = HttpBasicAuthFilterConstants.SERVICE_FACTORYPID_HTTP_BASIC_AUTH, metatype = true,
        configurationFactory = true, policy = ConfigurationPolicy.REQUIRE)
@Properties({
        @Property(name = HttpBasicAuthFilterConstants.PROP_FILTER_NAME,
                value = HttpBasicAuthFilterConstants.DEFAULT_FILTER_NAME),
        @Property(name = HttpWhiteboardConstants.PATTERN,
                value = HttpBasicAuthFilterConstants.DEFAULT_PATTERN),
        @Property(name = HttpWhiteboardConstants.CONTEXT_ID,
                value = HttpBasicAuthFilterConstants.DEFAULT_CONTEXT_ID),
        @Property(name = HttpBasicAuthFilterConstants.PROP_RANKING,
                value = HttpBasicAuthFilterConstants.DEFAULT_RANKING),
        @Property(name = HttpBasicAuthFilterConstants.PROP_REALM,
                value = HttpBasicAuthFilterConstants.DEFAULT_REALM),
        @Property(name = HttpBasicAuthFilterConstants.PROP_AUTHENTICATOR),
        @Property(name = HttpBasicAuthFilterConstants.PROP_RESOURCE_ID_RESOLVER),
        @Property(name = HttpBasicAuthFilterConstants.PROP_AUTHENTICATION_PROPAGATOR),
        @Property(name = HttpBasicAuthFilterConstants.PROP_LOG_SERVICE),
})
public class HttpBasicAuthFilterComponent {

    @Reference(bind = "setAuthenticator")
    private Authenticator authenticator;

    @Reference(bind = "setResourceIdResolver")
    private ResourceIdResolver resourceIdResolver;

    @Reference(bind = "setAuthenticationPropagator")
    private AuthenticationPropagator authenticationPropagator;

    @Reference(bind = "setLogService")
    private LogService logService;

    private ServiceRegistration<Filter> httpBasicAuthFilterSR;

    @Activate
    public void activate(final BundleContext context, final Map<String, Object> componentProperties) throws Exception {

        String realm = getStringProperty(componentProperties, HttpBasicAuthFilterConstants.PROP_REALM);
        String filterName = getStringProperty(componentProperties, HttpBasicAuthFilterConstants.PROP_FILTER_NAME);
        String pattern = getStringProperty(componentProperties, HttpBasicAuthFilterConstants.PROP_PATTERN);
        String contextId = getStringProperty(componentProperties, HttpBasicAuthFilterConstants.PROP_CONTEXT_ID);
        Long ranking = Long.valueOf(getStringProperty(componentProperties, HttpBasicAuthFilterConstants.PROP_RANKING));

        Filter httpBasicAuthFilter = new HttpBasicAuthFilter(authenticator, resourceIdResolver,
                authenticationPropagator, realm, logService);

        Dictionary<String, Object> properties = new Hashtable<>();
        properties.put(HttpBasicAuthFilterConstants.PROP_FILTER_NAME, filterName);
        properties.put(HttpWhiteboardConstants.PATTERN, pattern);
        properties.put(HttpWhiteboardConstants.CONTEXT_ID, contextId);
        properties.put(Constants.SERVICE_RANKING, ranking);
        httpBasicAuthFilterSR = context.registerService(Filter.class, httpBasicAuthFilter, properties);
    }

    @Deactivate
    public void deactivate() {
        if (httpBasicAuthFilterSR != null) {
            httpBasicAuthFilterSR.unregister();
            httpBasicAuthFilterSR = null;
        }
    }

    private String getStringProperty(final Map<String, Object> componentProperties, final String propertyName)
            throws ConfigurationException {
        Object value = componentProperties.get(propertyName);
        if (value == null) {
            throw new ConfigurationException(propertyName, "property not defined");
        }
        return String.valueOf(value);
    }

    public void setAuthenticationPropagator(final AuthenticationPropagator authenticationPropagator) {
        this.authenticationPropagator = authenticationPropagator;
    }

    public void setAuthenticator(final Authenticator authenticator) {
        this.authenticator = authenticator;
    }

    public void setLogService(final LogService logService) {
        this.logService = logService;
    }

    public void setResourceIdResolver(final ResourceIdResolver resourceIdResolver) {
        this.resourceIdResolver = resourceIdResolver;
    }

}
