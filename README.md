authentication-http-basic
=========================

[HTTP Basic Authentication][2] Servlet Filter based on blog post 
[Everit Authentication][1].

#Component
The module contains one Declarative Services component. The component can be 
instantiated multiple times via Configuration Admin. The component registers 
a *javax.servlet.Filter* OSGi service that implements 
[HTTP Basic Authentication][2]. To do that, the component is built on the 
following modules:
 - [authenticator-api][3]: to authentication the "Authorization" header value
 - [resource-resolver-api][4]: to map the authenticated username sent in the
 "Authorization" header to a Resource ID
 - [authentication-context-api][5]: to execute an authenticated process as the
 mapped Resource ID

[1]: http://everitorg.wordpress.com/2014/07/31/everit-authentication/
[2]: http://en.wikipedia.org/wiki/Basic_access_authentication
[3]: https://github.com/everit-org/authenticator-api
[4]: https://github.com/everit-org/resource-resolver-api
[5]: https://github.com/everit-org/authentication-context-api