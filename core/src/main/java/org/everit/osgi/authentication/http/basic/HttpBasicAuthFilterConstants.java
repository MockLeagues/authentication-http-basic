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
package org.everit.osgi.authentication.http.basic;

/**
 * Constants of the HTTP Basic Authentication Filter component.
 */
public final class HttpBasicAuthFilterConstants {

    public static final String SERVICE_FACTORYPID_HTTP_BASIC_AUTH =
            "org.everit.osgi.authentication.http.basic.HttpBasicAuthenticationFilter";

    public static final String DEFAULT_SERVICE_DESCRIPTION_HTTP_BASIC_AUTH =
            "Default HTTP Basic Authentication Filter";

    public static final String PROP_REALM = "realm";

    public static final String DEFAULT_REALM = "default-realm";

    public static final String PROP_AUTHENTICATOR = "authenticator.target";

    public static final String PROP_RESOURCE_ID_RESOLVER = "resourceIdResolver.target";

    public static final String PROP_AUTHENTICATION_PROPAGATOR = "authenticationPropagator.target";

    public static final String PROP_LOG_SERVICE = "logService.target";

    private HttpBasicAuthFilterConstants() {
    }

}
