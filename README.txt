Spring OAUTH2 Open ID Connect authentication server with client and resource server

In this building block, we create a Spring Security OAuth2 Open ID Connect server, a client and a resource server. The client
will use the Authorization code grant type and after receiving the access token from the authentication server, the client
will retrieve data from the resource server. The resource server on its turn, will verify the access token with the
authorization server and if the tokens are valid, the resource server will give access to the data.

The access tokens are sent between the servers as a non-opaque access tokens (or JWT).
PKCE has not been used here

The sequence of the message exchanged are:
- user accesses the authorization server (as)
- the as responds with a login screen for authentication
- if authenticated, an authorization code is send to a redirect uri at the client
- client will request the access token with the authorization code
- when the client receives the access token, it will retrieve data frorm the resource server (rs)
- rs will verify the access token with the as before releasing the data

Tools involved:
- Java
- Spring Security
- Docker

You can check the endpoints of the authorization server with following uri:
'http://localhost:8081/.well-known/openid-configuration'

Testing:
- start up the as, client and rs with . docker_up.sh
- Type in following uri in the browser
'http://localhost:8081/oauth2/authorize?response_type=code&client_id=client2&scope=openid&redirect_uri=http://localhost:8082/authorized'
- Fill in User 'bill' and Password 'password' at the login screen
- End result shall be a string 'demo'

