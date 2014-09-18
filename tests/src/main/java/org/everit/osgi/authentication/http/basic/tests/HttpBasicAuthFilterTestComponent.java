/**
 * This file is part of Everit - HTTP Basic Authentication Tests.
 *
 * Everit - HTTP Basic Authentication Tests is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Everit - HTTP Basic Authentication Tests is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Everit - HTTP Basic Authentication Tests.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.everit.osgi.authentication.http.basic.tests;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.Servlet;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.ConfigurationPolicy;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicHeader;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.everit.osgi.authentication.context.AuthenticationContext;
import org.everit.osgi.authentication.simple.SimpleSubject;
import org.everit.osgi.authentication.simple.SimpleSubjectManager;
import org.everit.osgi.dev.testrunner.TestRunnerConstants;
import org.everit.osgi.resource.ResourceService;
import org.junit.Assert;
import org.junit.Test;
import org.osgi.framework.BundleContext;

@Component(name = "HttpBasicAuthFilterTest", metatype = true, configurationFactory = true,
        policy = ConfigurationPolicy.REQUIRE, immediate = true)
@Properties({
        @Property(name = TestRunnerConstants.SERVICE_PROPERTY_TESTRUNNER_ENGINE_TYPE, value = "junit4"),
        @Property(name = TestRunnerConstants.SERVICE_PROPERTY_TEST_ID, value = "HttpBasicAuthFilterTest"),
        @Property(name = "setSimpleSubjectManager.target"),
        @Property(name = "authenticationContext.target"),
        @Property(name = "helloWorldServlet.target"),
        @Property(name = "httpBasicAuthenticationFilter.target")
})
@Service(value = HttpBasicAuthFilterTestComponent.class)
public class HttpBasicAuthFilterTestComponent {

    private static final String HTTP_BASIC_AUTH_FILTER_PATTERN = "/hello/secure";

    private static final String SECURE_HELLO_WORLD_ALIAS = "/hello/secure";

    private static final String PUBLIC_HELLO_WORLD_ALIAS = "/hello";

    private static final String USERNAME = "Aladdin";

    private static final String PASSWORD = "open sesame";

    @Reference(bind = "setSimpleSubjectManager")
    private SimpleSubjectManager simpleSubjectManager;

    @Reference(bind = "setResourceService")
    private ResourceService resourceService;

    @Reference(bind = "setAuthenticationContext")
    private AuthenticationContext authenticationContext;

    @Reference(bind = "setHelloWorldServlet")
    private Servlet helloWorldServlet;

    @Reference(bind = "setHttpBasicAuthenticationFilter")
    private Filter httpBasicAuthenticationFilter;

    private String publicUrl;

    private String secureUrl;

    private long authenticatedResourceId;

    private long defaultResourceId;

    private Server testServer;

    @Activate
    public void activate(final BundleContext context, final Map<String, Object> componentProperties)
            throws Exception {
        testServer = new Server(0);
        ServletContextHandler servletContextHandler = new ServletContextHandler();
        testServer.setHandler(servletContextHandler);

        servletContextHandler.addServlet(
                new ServletHolder("publichelloWorld", helloWorldServlet), PUBLIC_HELLO_WORLD_ALIAS);
        servletContextHandler.addServlet(
                new ServletHolder("securehelloWorld", helloWorldServlet), SECURE_HELLO_WORLD_ALIAS);
        servletContextHandler.addFilter(
                new FilterHolder(httpBasicAuthenticationFilter), HTTP_BASIC_AUTH_FILTER_PATTERN, null);

        testServer.start();

        String testServerURI = testServer.getURI().toString();
        String testServerURL = testServerURI.substring(0, testServerURI.length() - 1);

        publicUrl = testServerURL + PUBLIC_HELLO_WORLD_ALIAS;
        secureUrl = testServerURL + SECURE_HELLO_WORLD_ALIAS;

        long resourceId = resourceService.createResource();
        simpleSubjectManager.delete(USERNAME);
        SimpleSubject simpleSubject = simpleSubjectManager.create(resourceId, USERNAME, PASSWORD);
        authenticatedResourceId = simpleSubject.getResourceId();
        defaultResourceId = authenticationContext.getDefaultResourceId();
    }

    private void assertGet(final String url, final Header header, final int expectedStatusCode,
            final Long expectedResourceId) throws IOException {
        HttpClient httpClient = new DefaultHttpClient();
        HttpGet httpGet = new HttpGet(url);
        if (header != null) {
            httpGet.addHeader(header);
        }
        HttpResponse httpResponse = httpClient.execute(httpGet);
        Assert.assertEquals("Wrong status code on URL [" + url + "] with header [" + header + "]",
                expectedStatusCode,
                httpResponse.getStatusLine().getStatusCode());
        if (expectedStatusCode == HttpStatus.SC_OK) {
            HttpEntity httpEntity = httpResponse.getEntity();
            InputStream inputStream = httpEntity.getContent();
            StringWriter writer = new StringWriter();
            IOUtils.copy(inputStream, writer);
            String responseBodyAsString = writer.toString();
            Assert.assertEquals(expectedResourceId, Long.valueOf(responseBodyAsString));
        }
    }

    @Deactivate
    public void deactivate() throws Exception {
        if (testServer != null) {
            testServer.stop();
            testServer.destroy();
        }
    }

    private String encode(final String plain) {
        Encoder encoder = Base64.getEncoder();
        String encoded = encoder.encodeToString(plain.getBytes(StandardCharsets.UTF_8));
        return encoded;
    }

    public void setAuthenticationContext(final AuthenticationContext authenticationContext) {
        this.authenticationContext = authenticationContext;
    }

    public void setHelloWorldServlet(final Servlet helloWorldServlet) {
        this.helloWorldServlet = helloWorldServlet;
    }

    public void setHttpBasicAuthenticationFilter(final Filter httpBasicAuthenticationFilter) {
        this.httpBasicAuthenticationFilter = httpBasicAuthenticationFilter;
    }

    public void setResourceService(final ResourceService resourceService) {
        this.resourceService = resourceService;
    }

    public void setSimpleSubjectManager(final SimpleSubjectManager simpleSubjectManager) {
        this.simpleSubjectManager = simpleSubjectManager;
    }

    @Test
    public void testAccessPublicUrl() throws IOException {
        assertGet(publicUrl, null,
                HttpServletResponse.SC_OK, defaultResourceId);
    }

    @Test
    public void testAccessSecureUrl() throws IOException {
        assertGet(secureUrl, new BasicHeader("Authorization", "Basic " + encode(USERNAME + ":" + PASSWORD)),
                HttpServletResponse.SC_OK, authenticatedResourceId);
        assertGet(secureUrl, null,
                HttpServletResponse.SC_UNAUTHORIZED, null);
        assertGet(secureUrl, new BasicHeader("Authorization", "BasiC " + encode(USERNAME + ":" + PASSWORD)),
                HttpServletResponse.SC_UNAUTHORIZED, null);
        assertGet(secureUrl, new BasicHeader("Authorization", "Basic " + "1234567890ABCDEFGHI"),
                HttpServletResponse.SC_UNAUTHORIZED, authenticatedResourceId);
        assertGet(secureUrl, new BasicHeader("Authorization", "Basic " + encode(USERNAME + PASSWORD)),
                HttpServletResponse.SC_UNAUTHORIZED, authenticatedResourceId);
        assertGet(secureUrl, new BasicHeader("Authorization", "Basic " + encode(USERNAME + ":" + PASSWORD + "1")),
                HttpServletResponse.SC_UNAUTHORIZED, authenticatedResourceId);
    }
}
