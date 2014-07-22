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
package org.everit.osgi.http.basic.authentication.tests;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.ConfigurationPolicy;
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
import org.everit.osgi.authentication.context.AuthenticationContext;
import org.everit.osgi.authentication.simple.SimpleSubject;
import org.everit.osgi.authentication.simple.SimpleSubjectManager;
import org.everit.osgi.dev.testrunner.TestDuringDevelopment;
import org.everit.osgi.dev.testrunner.TestRunnerConstants;
import org.everit.osgi.resource.ResourceService;
import org.junit.Assert;
import org.junit.Test;
import org.osgi.framework.BundleContext;
import org.osgi.service.http.HttpService;

@Component(name = "HttpBasicAuthFilterTest", immediate = true, configurationFactory = false,
        policy = ConfigurationPolicy.OPTIONAL)
@Properties({
        @Property(name = TestRunnerConstants.SERVICE_PROPERTY_TESTRUNNER_ENGINE_TYPE, value = "junit4"),
        @Property(name = TestRunnerConstants.SERVICE_PROPERTY_TEST_ID, value = "HttpBasicAuthFilterTest"),
        @Property(name = "httpService.target", value = "(org.osgi.service.http.port=*)"),
        @Property(name = "setSimpleSubjectManager.target"),
        @Property(name = "authenticationContext.target")
})
@Service(value = HttpBasicAuthFilterTestComponent.class)
@TestDuringDevelopment
public class HttpBasicAuthFilterTestComponent {

    @Reference(bind = "setHttpService")
    private HttpService httpService;

    @Reference(bind = "setSimpleSubjectManager")
    private SimpleSubjectManager simpleSubjectManager;

    @Reference(bind = "setResourceService")
    private ResourceService resourceService;

    @Reference(bind = "setAuthenticationContext")
    private AuthenticationContext authenticationContext;

    private int port;

    private String publicUrl;

    private String secureUrl;

    private String username = "Aladdin";

    private String password = "open sesame";

    private long authenticatedResourceId;

    private long defaultResourceId;

    @Activate
    public void activate(final BundleContext context, final Map<String, Object> componentProperties)
            throws Exception {
        publicUrl = "http://localhost:" + port + "/hello";
        secureUrl = "http://localhost:" + port + "/hello/secure";

        long resourceId = resourceService.createResource();
        simpleSubjectManager.delete(username);
        SimpleSubject simpleSubject = simpleSubjectManager.create(resourceId, username, password);
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

    private String encode(final String plain) {
        Encoder encoder = Base64.getEncoder();
        String encoded = encoder.encodeToString(plain.getBytes(StandardCharsets.UTF_8));
        return encoded;
    }

    public void setAuthenticationContext(final AuthenticationContext authenticationContext) {
        this.authenticationContext = authenticationContext;
    }

    public void setHttpService(final HttpService httpService, final Map<String, Object> properties) {
        this.httpService = httpService;
        port = Integer.valueOf((String) properties.get("org.osgi.service.http.port"));
        port--; // TODO port must be decremented because the port of the Server is less than the value of the service
        // portperty queried above
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
        assertGet(secureUrl, new BasicHeader("Authorization", "Basic " + encode(username + ":" + password)),
                HttpServletResponse.SC_OK, authenticatedResourceId);
        assertGet(secureUrl, null,
                HttpServletResponse.SC_UNAUTHORIZED, null);
        assertGet(secureUrl, new BasicHeader("Authorization", "BasiC " + encode(username + ":" + password)),
                HttpServletResponse.SC_UNAUTHORIZED, null);
        assertGet(secureUrl, new BasicHeader("Authorization", "Basic " + "!@#$%^&*()_+\\|Đ<>#@{,.-"),
                HttpServletResponse.SC_UNAUTHORIZED, authenticatedResourceId);
        assertGet(secureUrl, new BasicHeader("Authorization", "Basic " + encode(username + password)),
                HttpServletResponse.SC_UNAUTHORIZED, authenticatedResourceId);
    }
}
