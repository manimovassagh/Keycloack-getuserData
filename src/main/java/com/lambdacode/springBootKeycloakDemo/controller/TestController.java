package com.lambdacode.springBootKeycloakDemo.controller;

import com.fasterxml.jackson.core.JsonEncoding;
import com.fasterxml.jackson.core.JsonParser;
import com.sun.security.auth.UserPrincipal;
import io.jsonwebtoken.Jwt;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.spi.KeycloakAccount;
import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.security.RolesAllowed;
import java.awt.*;
import java.security.Principal;
import java.util.Base64;
import java.util.logging.Logger;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
@RestController
@RequestMapping("/test")

public class TestController {




    @GetMapping(value = "/user1")
    @RolesAllowed("admin")

    public String testing1(KeycloakAuthenticationToken authentication){
        SimpleKeycloakAccount account = (SimpleKeycloakAccount) authentication.getDetails();
        AccessToken token = account.getKeycloakSecurityContext().getToken();
        //Username, other way
        String first = authentication.getPrincipal().toString();
        //Email
        String email = token.getEmail();
        System.out.println(first);
        System.out.println(email);

        return token.getEmail();
    }



    @GetMapping("/user2")
    public String testing2(){
        return "success for user 2";
    }


    @GetMapping(value = "")
    public void logUsername(Authentication authentication) {
        Logger.getAnonymousLogger().info(authentication.getName());
    }

    @GetMapping(value = "/test-email")
    public AccessToken loadUserDetail(KeycloakAuthenticationToken authentication) {
        SimpleKeycloakAccount account = (SimpleKeycloakAccount) authentication.getDetails();
        AccessToken token = account.getKeycloakSecurityContext().getToken();
        //Username, other way
        Logger.getAnonymousLogger().info(authentication.getPrincipal().toString());
        //Email
        Logger.getAnonymousLogger().info(token.getEmail());
        return token;
    }


}
