package com.dianaglobal.loginregister.adapter.in.web;

import com.dianaglobal.loginregister.adapter.in.dto.RegisterRequest;
import com.dianaglobal.loginregister.application.port.in.RegisterUserUseCase;
import com.dianaglobal.loginregister.application.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final RegisterUserUseCase registerService;
    private final UserService userService;

    @GetMapping("/login")
    public ResponseEntity<?> login(@RequestParam String email) {
        return userService.findByEmail(email)
                .map(user -> ResponseEntity.ok("User found: " + user.getEmail()))
                .orElse(ResponseEntity.status(404).body("User not found"));
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterRequest request) {
        registerService.register(request.name(), request.email(), request.password());
        return ResponseEntity.ok("User successfully registered");
    }
}


