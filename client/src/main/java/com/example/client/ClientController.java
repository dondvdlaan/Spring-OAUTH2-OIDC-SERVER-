package com.example.client;

import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

@RestController
public class ClientController {
    final static Logger logger = LoggerFactory.getLogger(ClientController.class);
    ClientService clientService;

    public ClientController(ClientService clientService) {
        this.clientService = clientService;
    }

    /*
    Redirect from AS for AuthorizationCode grant type
    Testing: type at the browser
    'http://localhost:8081/oauth2/authorize?response_type=code&client_id=client2&scope=openid&redirect_uri=http://localhost:8082/authorized'
     */
    @GetMapping("/authorized")
    public String isAuth(@RequestParam("code") String code) {

        logger.info("Authorized!! authorization code is: " + code);

        // Retrieve Token with the authorization code
        String accesTokenJson = clientService.requestTokenAuthorizationCode(code);
        String accesToken = "<nothingToSeeHere>";

        // Read token from JSON object
        try {
            accesToken = (String) new JSONObject(accesTokenJson).get("access_token");
        } catch (JSONException ex) {
            logger.error(ex.getMessage());
            return null;
        }

        // Retrieve value from resource server
        return clientService.readValueFromRS(accesToken);
    }

    /*
    ClientCredentials grant type
     */
    @GetMapping("/cred")
    public String getClientCredentialsToken() {

        logger.info("In getClientCredentialsToken ");

        // Retrieve token
        return clientService.requestTokenClientCredentials();
    }
}
