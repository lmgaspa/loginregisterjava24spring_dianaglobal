package com.dianaglobal.loginregister.adapter.in.web;

import com.dianaglobal.loginregister.adapter.in.dto.JwtResponse;
import com.dianaglobal.loginregister.adapter.in.dto.LoginRequest;
import com.dianaglobal.loginregister.adapter.in.dto.RegisterRequest;
import com.dianaglobal.loginregister.application.port.in.RegisterUserUseCase;
import com.dianaglobal.loginregister.application.port.out.UserRepositoryPort;
import com.dianaglobal.loginregister.application.service.UserService;
import com.dianaglobal.loginregister.application.service.JwtService;
import com.dianaglobal.loginregister.domain.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final RegisterUserUseCase registerService;
    private final UserService userService;
    private final UserRepositoryPort userRepositoryPort;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;


    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterRequest request) {
        registerService.register(request.name(), request.email(), request.password());
        return ResponseEntity.ok("User successfully registered");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        return userRepositoryPort.findByEmail(request.email())
                .filter(user -> passwordEncoder.matches(request.password(), user.getPassword()))
                .<ResponseEntity<?>>map(user -> {
                    String token = jwtService.generateToken(user.getEmail());
                    return ResponseEntity.ok(new JwtResponse(token));
                })
                .orElse(ResponseEntity.status(401).body("Invalid credentials"));
    }

    @GetMapping("/profile")
    public ResponseEntity<User> profile(Authentication authentication) {
        String email = authentication.getName();
        return userService.findByEmail(email)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.status(404).build());
    }


    @GetMapping("/find-user")
    public ResponseEntity<?> findUser(@RequestParam String email) {
        return userService.findByEmail(email)
                .map(user -> ResponseEntity.ok("User found: " + user.getEmail()))
                .orElse(ResponseEntity.status(404).body("User not found"));
    }
}
