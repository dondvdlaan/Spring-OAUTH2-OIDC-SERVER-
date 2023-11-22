package com.example.client;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

@Service
public class ClientService {

    final static Logger logger = LoggerFactory.getLogger(ClientService.class);

    private String PORT_AS;
    private String HOST_AS;
    private String PORT_RS;
    private String HOST_RS;

    public ClientService() {
    }

    @Autowired
    public ClientService(
            @Value("${PORT_AS}") String PORT_AS,
            @Value("${HOST_AS}") String HOST_AS,
            @Value("${PORT_RS}") String PORT_RS,
            @Value("${HOST_RS}") String HOST_RS) {
        this.PORT_AS = PORT_AS;
        this.HOST_AS = HOST_AS;
        this.PORT_RS = PORT_RS;
        this.HOST_RS = HOST_RS;
    }

    public String requestTokenAuthorizationCode(String authCode) {

        logger.debug("In clientService requestToken {}", authCode);

        // authorization_code grant type
        //curl -X POST 'http://localhost:8081/oauth2/token?client_id=client&redirect_uri=http://localhost:8082/token&grant_type=authorization_code&code='nnTSazWVqTyLzR6Ef6vQGy3eJYh9x2KqaNekv1c7zMA469Xwa_sf6X8ifCAVA8ENfusqPFLymnSMXzHQJKoPn_jY9IQUHoG5mQVkux21nKWy6sgjGuOYyIOuEd_bPVt0' --header 'Authorization: Basic Y2xpZW50OnNlY3JldA=='
        String url =
                "http://" +
                        HOST_AS +
                        ":" +
                        PORT_AS +
                        "/oauth2/token" +
                "?client_id=client2" +
                "&redirect_uri=http://localhost:8082/authorized" +
                "&grant_type=authorization_code" +
                "&code=";
        String uri = url + authCode;
        logger.debug("uri {}", uri);

        String headerName = "Authorization";
        byte[] encodedBytes = Base64.getEncoder().encode("client2:secret2".getBytes());
        String headerValue = " Basic " + new String(encodedBytes);
        logger.debug("headerValue: " + headerValue);

        return restTemplateAPI(headerName, headerValue, uri, POST);
        /*
        RestTemplate restTemplate = new RestTemplate();

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set(headerName, headerValue);

            Map<String, String> requestBody = new HashMap<>();
            //requestBody.put("client_id", "client");
            JSONObject jsonObject = new JSONObject(requestBody);
            logger.info("jsonObject: " + jsonObject);

            HttpEntity<JSONObject> entity = new HttpEntity<>(jsonObject, headers);

            ResponseEntity<String> res = restTemplate.exchange(uri, POST, entity, String.class);
            System.out.println("res.getBody(): " + res.getBody());

            return res.getBody();

        } catch (Exception ex) {
            logger.info("In catch requestTokenAuthorizationCode ");
            logger.error(ex.getMessage());
            return ex.getMessage();
        }

         */
    }

    public String requestTokenClientCredentials() {

        logger.info("In clientService requestToken ");

        // client_credentials
        // curl -v -X POST 'http://localhost:8081/oauth2/token?grant_type=client_credentials&scope=CUSTOM' --header 'Authorization: Basic Y2xpZW50OnNlY3JldA=='
        String uri = "http://" +
                HOST_AS +
                ":" +
                PORT_AS +
                "/oauth2/token?grant_type=client_credentials&scope=CUSTOM";
        logger.debug("uri {}", uri);

        String headerName = "Authorization";
        byte[] encodedBytes = Base64.getEncoder().encode("client1:secret1".getBytes());
        String headerValue = " Basic " + new String(encodedBytes);
        //String headerValue = " Basic Y2xpZW50OnNlY3JldA==";
        logger.debug("headerValue: " + headerValue);

        RestTemplate restTemplate = new RestTemplate();

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set(headerName, headerValue);

            Map<String, String> requestBody = new HashMap<>();
            //requestBody.put("client_id", "client");
            JSONObject jsonObject = new JSONObject(requestBody);

            logger.info("jsonObject: " + jsonObject);
            HttpEntity<JSONObject> entity = new HttpEntity<>(jsonObject, headers);

            ResponseEntity<String> res = restTemplate.exchange(uri, POST, entity, String.class);
            System.out.println("res.getBody(): " + res.getBody());

            return res.getBody();

        } catch (Exception ex) {
            logger.info("In catch requestTokenClientCredentials ");
            logger.error(ex.getMessage());
            return ex.getMessage();
        }
    }

    public String readValueFromRS(String accessToken){

        logger.info("In readValueFromRS");

        String uri = "http://" +
                HOST_RS +
                ":" +
                PORT_RS +
                "/demo";
        logger.debug("uri {}", uri);

        String headerName = "Authorization";
        //byte[] encodedBytes = Base64.getEncoder().encode("client1:secret1".getBytes());
        String headerValue = " Bearer " + accessToken;
        logger.debug("headerValue: " + headerValue);

        return restTemplateAPI(headerName, headerValue, uri, GET);

        /*

        RestTemplate restTemplate = new RestTemplate();

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set(headerName, headerValue);

            Map<String, String> requestBody = new HashMap<>();
            //requestBody.put("client_id", "client");
            JSONObject jsonObject = new JSONObject(requestBody);

            logger.info("jsonObject: " + jsonObject);
            HttpEntity<JSONObject> entity = new HttpEntity<>(jsonObject, headers);

            ResponseEntity<String> res = restTemplate.exchange(uri, GET, entity, String.class);
            System.out.println("res.getBody(): " + res.getBody());

            return res.getBody();

        } catch (Exception ex) {
            logger.info("In catch readValueFromRS ");
            logger.error(ex.getMessage());
            return ex.getMessage();
        }

         */
    }

    String restTemplateAPI(
            String headerName,
            String headerValue,
            String uri,
            HttpMethod httpMethod){

        RestTemplate restTemplate = new RestTemplate();

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set(headerName, headerValue);

            Map<String, String> requestBody = new HashMap<>();
            //requestBody.put("client_id", "client");
            JSONObject jsonObject = new JSONObject(requestBody);
            logger.debug("jsonObject: " + jsonObject);

            HttpEntity<JSONObject> entity = new HttpEntity<>(jsonObject, headers);

            ResponseEntity<String> res = restTemplate.exchange(uri, httpMethod, entity, String.class);
            logger.debug("res.getBody(): " + res.getBody());

            return res.getBody();

        } catch (Exception ex) {
            logger.error("restTemplateAPI: ", ex.getMessage());
            return ex.getMessage();
        }
    }
}