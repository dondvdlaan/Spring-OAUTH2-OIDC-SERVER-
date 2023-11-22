package com.example.rs;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class ProjectConfig {

    private String keySetURI;

    public ProjectConfig(
            @Value("${keySetURI}") String keySetURI)
    {
        this.keySetURI = keySetURI;
    }

    @Bean
    public SecurityFilterChain securityFilterChain (HttpSecurity httpSecurity)
            throws Exception {

        httpSecurity
                // Configure server as OAuth2 RS
                .oauth2ResourceServer(
                        // use JWT tokens for Authetication
                        config -> config.jwt(
                                // retrieve key for validating tokens
                                j->j.jwkSetUri(keySetURI)));

        // Any request endpoint shall be authenticated
        httpSecurity
                .authorizeHttpRequests(
                        config -> config.anyRequest().authenticated());

        return httpSecurity.build();
    }
}
