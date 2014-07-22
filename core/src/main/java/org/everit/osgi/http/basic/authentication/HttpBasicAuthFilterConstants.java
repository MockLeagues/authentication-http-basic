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
package org.everit.osgi.http.basic.authentication;


public class HttpBasicAuthFilterConstants {

    /**
     * The service factory PID of the resource component.
     */
    public static final String SERVICE_FACTORYPID_HTTP_BASIC_AUTH =
            "org.everit.osgi.http.basic.authentication.HttpBasicAuthenticationFilter";

    public static final String PROP_FILTER_NAME = "filterName";

    public static final String PROP_REALM = "realm";

    public static final String PROP_PATTERN = "pattern";

    public static final String PROP_CONTEXT_ID = "contextId";

    public static final String PROP_RANKING = "ranking";

    public static final String PROP_AUTHENTICATOR_TARGET = "authenticator.target";

    public static final String PROP_RESOURCE_ID_RESOLVER_TARGET = "resourceIdResolver.target";

    public static final String PROP_AUTHENTICATION_PROPAGATOR_TARGET = "authenticationPropagator.target";

    public static final String PROP_LOG_SERVICE_TARGET = "logService.target";

    public static final String DEFAULT_FILTER_NAME = "HttpBasicAuthenticationFilter";

    public static final String DEFAULT_PATTERN = "/*";

    public static final String DEFAULT_CONTEXT_ID = "defaultContext";

    public static final String DEFAULT_RANKING = "0";

    public static final String DEFAULT_REALM = "my-realm";

    private HttpBasicAuthFilterConstants() {
    }

}
