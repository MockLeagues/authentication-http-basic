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
package org.everit.osgi.authentication.basic.internal;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Base64.Decoder;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.everit.osgi.authentication.context.AuthenticationPropagator;
import org.everit.osgi.authenticator.Authenticator;
import org.everit.osgi.resource.resolver.ResourceIdResolver;
import org.osgi.service.log.LogService;

public class HttpBasicAuthFilter implements Filter {

    private static final String CLIENT_HEADER_AUTHORIZATION = "Authorization";

    private static final String CLEENT_HEADER_VALUE_PREFIX = "Basic ";

    private static final String SERVER_HEADER_WWW_AUTHENTICATE = "WWW-Authenticate";

    private static final String SERVER_HEADER_VALUE = "Basic realm=\"%1$s\"";

    private static final String USERNAME_PASSWORD_SEPARATOR = ":";

    private final Authenticator authenticator;

    private final ResourceIdResolver resourceIdResolver;

    private final AuthenticationPropagator authenticationPropagator;

    private final LogService logService;

    /**
     * The realm attribute (case-insensitive) is required for all authentication schemes which issue a challenge. The
     * realm value (case-sensitive), in combination with the canonical root URL of the server being accessed, defines
     * the protection space. These realms allow the protected resources on a server to be partitioned into a set of
     * protection spaces, each with its own authentication scheme and/or authorization database. The realm value is a
     * string, generally assigned by the origin server, which may have additional semantics specific to the
     * authentication scheme.
     */
    private final String realm;

    public HttpBasicAuthFilter(final Authenticator authenticator, final ResourceIdResolver resourceIdResolver,
            final AuthenticationPropagator authenticationPropagator, final String realm, final LogService logService) {
        super();
        this.authenticator = authenticator;
        this.resourceIdResolver = resourceIdResolver;
        this.authenticationPropagator = authenticationPropagator;
        this.realm = realm;
        this.logService = logService;
    }

    @Override
    public void destroy() {
    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {

        // Check and get authorization request header
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String authorizationHeader = httpServletRequest.getHeader(CLIENT_HEADER_AUTHORIZATION);
        if (authorizationHeader == null) {
            logService.log(LogService.LOG_INFO, "Missing header parameter '" + CLIENT_HEADER_AUTHORIZATION + "'.");
            requestForAuthentication(response);
            return;
        }
        if (!authorizationHeader.startsWith(CLEENT_HEADER_VALUE_PREFIX)) {
            logService.log(LogService.LOG_INFO, "Invalid value for header parameter '" + CLIENT_HEADER_AUTHORIZATION
                    + "'.");
            requestForAuthentication(response);
            return;
        }
        String authorizationBase64 = authorizationHeader.substring(CLEENT_HEADER_VALUE_PREFIX.length());
        Decoder mimeDecoder = Base64.getMimeDecoder();
        byte[] decodedUsernamePassword;
        try {
            decodedUsernamePassword = mimeDecoder.decode(authorizationBase64);
        } catch (IllegalArgumentException e) {
            logService.log(LogService.LOG_INFO, "Invalid BASE64 value for '" + CLIENT_HEADER_AUTHORIZATION
                    + "' header paramter.");
            requestForAuthentication(response);
            return;
        }
        String usernamePassword = new String(decodedUsernamePassword, StandardCharsets.UTF_8);
        int separatorIndex = usernamePassword.indexOf(USERNAME_PASSWORD_SEPARATOR);
        if (separatorIndex == -1) {
            logService.log(LogService.LOG_INFO, "Username and password separator '" + USERNAME_PASSWORD_SEPARATOR
                    + "' does not exists in header parameter '" + CLIENT_HEADER_AUTHORIZATION + "'.");
            requestForAuthentication(response);
            return;
        }
        String username = usernamePassword.substring(0, separatorIndex);
        String password = usernamePassword.substring(separatorIndex + 1);

        // Authentication
        String authenticatedPrincipal = authenticator.authenticate(username, password);
        if (authenticatedPrincipal == null) {
            logService.log(LogService.LOG_INFO, "Failed to authenticate username '" + username + "'.");
            requestForAuthentication(response);
            return;
        }

        // Resource ID mapping
        Long authenticatedResourceId = resourceIdResolver.getResourceId(authenticatedPrincipal);
        if (authenticatedResourceId == null) {
            logService.log(LogService.LOG_INFO, "Authenticated username '" + username
                    + "' (aka mapped principal'" + authenticatedPrincipal + "') cannot be mapped to Resource ID");
            requestForAuthentication(response);
            return;
        }

        // Execute authenticated process
        Exception exception = authenticationPropagator.runAs(authenticatedResourceId, () -> {
            try {
                chain.doFilter(request, response);
                return null;
            } catch (IOException | ServletException e) {
                logService.log(LogService.LOG_ERROR, "Authenticated process execution failed", e);
                return e;
            }
        });
        if (exception != null) {
            if (exception instanceof IOException) {
                throw (IOException) exception;
            } else if (exception instanceof ServletException) {
                throw (ServletException) exception;
            }
        }
    }

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
    }

    private void requestForAuthentication(final ServletResponse servletResponse) {
        HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
        httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        httpServletResponse.setHeader(SERVER_HEADER_WWW_AUTHENTICATE, String.format(SERVER_HEADER_VALUE, realm));
    }

}
