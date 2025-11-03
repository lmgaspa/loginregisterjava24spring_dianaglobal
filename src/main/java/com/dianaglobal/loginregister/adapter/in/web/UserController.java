package com.dianaglobal.loginregister.adapter.in.web;

import com.dianaglobal.loginregister.config.ApiPaths;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(    ApiPaths.USER_BASE)
public class UserController {

    @GetMapping("/profile")
    public ResponseEntity<?> getProfile(Authentication authentication) {
        String email = authentication.getName(); // vem do JWT
        return ResponseEntity.ok("Authenticated user: " + email);
    }
}

