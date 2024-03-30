package com.group.demojwt.controller;

import com.group.demojwt.service.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class AuthController {
    public static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);
    private final TokenService tokenService;

    public AuthController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping("/token")
    public String token(Authentication authentication) {
        LOGGER.debug("Token reqeusted for user: '{}'", authentication.getName());
        String token = tokenService.generateToken(authentication);
        LOGGER.debug("token granted '{}'", token);
        return token;
    }
}
