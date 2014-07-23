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
package org.everit.osgi.authentication.basic;

/**
 * Constants of the HTTP Basic Authentication Filter component.
 */
public final class HttpBasicAuthFilterConstants {

    /**
     * The service factory PID of the HTTP Basic Authentication Filter component.
     */
    public static final String SERVICE_FACTORYPID_HTTP_BASIC_AUTH =
            "org.everit.osgi.authentication.basic.HttpBasicAuthenticationFilter";

    public static final String PROP_FILTER_NAME = "filterName";

    public static final String PROP_REALM = "realm";

    public static final String PROP_PATTERN = "pattern";

    public static final String PROP_CONTEXT_ID = "contextId";

    public static final String PROP_RANKING = "ranking";

    public static final String PROP_AUTHENTICATOR = "authenticator.target";

    public static final String PROP_RESOURCE_ID_RESOLVER = "resourceIdResolver.target";

    public static final String PROP_AUTHENTICATION_PROPAGATOR = "authenticationPropagator.target";

    public static final String PROP_LOG_SERVICE = "logService.target";

    /**
     * The default value of the {@link #PROP_FILTER_NAME}.
     */
    public static final String DEFAULT_FILTER_NAME = "HttpBasicAuthenticationFilter";

    /**
     * The default value of the {@link org.apache.felix.http.whiteboard.HttpWhiteboardConstants#PATTERN}.
     */
    public static final String DEFAULT_PATTERN = "/*";

    /**
     * The default value of the {@link org.apache.felix.http.whiteboard.HttpWhiteboardConstants#CONTEXT_ID}.
     */
    public static final String DEFAULT_CONTEXT_ID = "defaultContext";

    /**
     * The default value of the {@link #PROP_RANKING}.
     */
    public static final String DEFAULT_RANKING = "0";

    /**
     * The default value of the {@link #PROP_REALM}.
     */
    public static final String DEFAULT_REALM = "my-realm";

    private HttpBasicAuthFilterConstants() {
    }

}
