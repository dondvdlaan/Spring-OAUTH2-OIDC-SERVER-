<h2>Spring OAUTH2 Open ID Connect authorization server with client and resource server</h2>

<p>In this building block, we create a Spring Security OAuth2 Open ID Connect server, a client and a resource server. The client
will use the Authorization code grant type and after receiving the access token from the authentication server, the client
will retrieve data from the resource server. The resource server on its turn, will verify the access token with the
authorization server and if the tokens are valid, the resource server will give access to the data.</p>

<p>The access tokens are sent between the servers as a non-opaque access tokens (or JWT).
PKCE has not been used here</p>

<h3>The sequence of the messages exchanged are:</h3>
<ul>
<li>user accesses the authorization server (as)</li>
<li>the as responds with a login screen for authentication</li>
<li>if authenticated, an authorization code is sent to a redirect uri at the client</li>
<li>client will request the access token with the authorization code</li>
<li>when the client receives the access token, it will retrieve data frorm the resource server (rs)</li>
<li>rs will verify the access token with the as before releasing the data</li>
</ul>
<h3>Tools involved:</h3>
<ul>
<li>Java</li>
<li>Spring Security</li>
<li>Docker</li>
</ul>
You can check the endpoints of the authorization server with following uri:
'http://localhost:8081/.well-known/openid-configuration'

<h3>Testing:</h3>
<ul>
<li>start up the as, client and rs with . docker_up.sh</li>
<li>Type in following uri in the browser
'http://localhost:8081/oauth2/authorize?response_type=code&client_id=client2&scope=openid&redirect_uri=http://localhost:8082/authorized'</li>
<li>Fill in User 'bill' and Password 'password' at the login screen</li>
<li>End result shall be a string 'demo'</li>
</ul>
