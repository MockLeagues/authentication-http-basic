/*
 * Copyright (C) 2011 Everit Kft. (http://www.everit.biz)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.everit.authentication.http.basic;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Objects;
import java.util.Optional;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.everit.authentication.context.AuthenticationPropagator;
import org.everit.authenticator.Authenticator;
import org.everit.resource.resolver.ResourceIdResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Simple implementation of HTTP Basic Authentication mechanism as a {@link Filter}.
 */
public class HttpBasicAuthFilter implements Filter {

  private static final String CLIENT_HEADER_AUTHORIZATION = "Authorization";

  private static final String CLIENT_HEADER_VALUE_PREFIX = "Basic ";

  private static final Logger LOGGER = LoggerFactory.getLogger(HttpBasicAuthFilter.class);

  private static final String SERVER_HEADER_VALUE = "Basic realm=\"%1$s\"";

  private static final String SERVER_HEADER_WWW_AUTHENTICATE = "WWW-Authenticate";

  private static final String USERNAME_PASSWORD_SEPARATOR = ":";

  private AuthenticationPropagator authenticationPropagator;

  private Authenticator authenticator;

  /**
   * The realm attribute (case-insensitive) is required for all authentication schemes which issue a
   * challenge. The realm value (case-sensitive), in combination with the canonical root URL of the
   * server being accessed, defines the protection space. These realms allow the protected resources
   * on a server to be partitioned into a set of protection spaces, each with its own authentication
   * scheme and/or authorization database. The realm value is a string, generally assigned by the
   * origin server, which may have additional semantics specific to the authentication scheme.
   */
  private String realm;

  private ResourceIdResolver resourceIdResolver;

  /**
   * Constructor.
   *
   * @param authenticationPropagator
   *          the {@link AuthenticationPropagator} instance.
   * @param authenticator
   *          the {@link Authenticator} instance.
   * @param resourceIdResolver
   *          the {@link ResourceIdResolver} instance.
   * @param realm
   *          Pages in the same realm should share credentials. For more information see RFC 1945
   *          (HTTP/1.0) and RFC 2617 (HTTP Authentication referenced by HTTP/1.1).
   *
   * @throws NullPointerException
   *           if one of the parameter is <code>null</code>.
   */
  public HttpBasicAuthFilter(final AuthenticationPropagator authenticationPropagator,
      final Authenticator authenticator, final ResourceIdResolver resourceIdResolver,
      final String realm) {
    this.authenticationPropagator = Objects.requireNonNull(authenticationPropagator,
        "authenticationPropagator cannot be null");
    this.authenticator = Objects.requireNonNull(authenticator, "authenticator cannot be null");
    this.resourceIdResolver =
        Objects.requireNonNull(resourceIdResolver, "resourceIdResolver cannot be null");
    this.realm = Objects.requireNonNull(realm, "realm cannot be null");
  }

  private String checkAndGetAuthorizationRequestHeader(
      final HttpServletRequest httpServletRequest) {
    String authorizationHeader = httpServletRequest.getHeader(CLIENT_HEADER_AUTHORIZATION);
    if (authorizationHeader == null) {
      LOGGER.info("Missing header parameter '" + CLIENT_HEADER_AUTHORIZATION + "'.");
      return null;
    }
    if (!authorizationHeader.startsWith(CLIENT_HEADER_VALUE_PREFIX)) {
      LOGGER.info("Invalid value for header parameter '" + CLIENT_HEADER_AUTHORIZATION + "'.");
      return null;
    }
    return authorizationHeader;
  }

  @Override
  public void destroy() {
  }

  @Override
  public void doFilter(final ServletRequest request, final ServletResponse response,
      final FilterChain chain) throws IOException, ServletException {

    // Check and get authorization request header
    HttpServletRequest httpServletRequest = (HttpServletRequest) request;
    String authorizationHeader = checkAndGetAuthorizationRequestHeader(httpServletRequest);
    if (authorizationHeader == null) {
      requestForAuthentication(response);
      return;
    }

    String authorizationBase64 = authorizationHeader.substring(CLIENT_HEADER_VALUE_PREFIX.length());
    Decoder mimeDecoder = Base64.getMimeDecoder();
    byte[] decodedUsernamePassword;
    try {
      decodedUsernamePassword = mimeDecoder.decode(authorizationBase64);
    } catch (IllegalArgumentException e) {
      LOGGER
          .info("Invalid BASE64 value for '" + CLIENT_HEADER_AUTHORIZATION + "' header paramter.");
      requestForAuthentication(response);
      return;
    }
    String usernamePassword = new String(decodedUsernamePassword, StandardCharsets.UTF_8);
    int separatorIndex = usernamePassword.indexOf(USERNAME_PASSWORD_SEPARATOR);
    if (separatorIndex == -1) {
      LOGGER.info("Username and password separator '" + USERNAME_PASSWORD_SEPARATOR
          + "' does not exists in header parameter '" + CLIENT_HEADER_AUTHORIZATION + "'.");
      requestForAuthentication(response);
      return;
    }
    String username = usernamePassword.substring(0, separatorIndex);
    String password = usernamePassword.substring(separatorIndex + 1);

    // Authentication
    Optional<String> optionalAuthenticatedPrincipal =
        authenticator.authenticate(username, password);
    if (!optionalAuthenticatedPrincipal.isPresent()) {
      LOGGER.info("Failed to authenticate username '" + username + "'.");
      requestForAuthentication(response);
      return;
    }

    // Resource ID mapping
    String authenticatedPrincipal = optionalAuthenticatedPrincipal.get();
    Optional<Long> optionalAuthenticatedResourceId =
        resourceIdResolver.getResourceId(authenticatedPrincipal);
    if (!optionalAuthenticatedResourceId.isPresent()) {
      LOGGER.info("Authenticated username '" + username
          + "' (aka mapped principal '" + authenticatedPrincipal
          + "') cannot be mapped to Resource ID");
      requestForAuthentication(response);
      return;
    }

    // Execute authenticated process
    executeAuthenticatedProcess(request, response, chain, optionalAuthenticatedResourceId);
  }

  private void executeAuthenticatedProcess(final ServletRequest request,
      final ServletResponse response, final FilterChain chain,
      final Optional<Long> optionalAuthenticatedResourceId) throws IOException, ServletException {
    long authenticatedResourceId = optionalAuthenticatedResourceId.get();
    Exception exception = authenticationPropagator.runAs(authenticatedResourceId, () -> {
      try {
        chain.doFilter(request, response);
        return null;
      } catch (IOException | ServletException e) {
        LOGGER.error("Authenticated process execution failed", e);
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
    httpServletResponse.setHeader(SERVER_HEADER_WWW_AUTHENTICATE,
        String.format(SERVER_HEADER_VALUE, realm));
  }

}
