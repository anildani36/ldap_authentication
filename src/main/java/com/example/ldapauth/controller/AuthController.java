package com.example.ldapauth.controller;

import com.example.ldapauth.model.AuthRequest;
import com.example.ldapauth.model.AuthResponse;
import com.example.ldapauth.service.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/")
public class AuthController {

    private final AuthenticationService authService;

    public AuthController(AuthenticationService authService) {
        this.authService = authService;
    }

    /**
     * Introspect endpoint used by other microservices.
     * Accepts username & password in request body and returns structured AuthResponse.
     */
    @PostMapping("/introspect")
    public ResponseEntity<AuthResponse> introspect(@RequestBody AuthRequest request) {
        AuthResponse resp = authService.authenticate(request);
        return ResponseEntity.status(resp.getStatus()).body(resp);
    }
}
