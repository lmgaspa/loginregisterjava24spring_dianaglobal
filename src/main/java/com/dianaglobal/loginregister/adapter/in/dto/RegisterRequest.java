// src/main/java/com/dianaglobal/loginregister/adapter/in/dto/RegisterRequest.java
package com.dianaglobal.loginregister.adapter.in.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank String name,

        @NotBlank
        @Email(message = "Invalid e-mail")
        @Pattern(
                regexp = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$",
                message = "E-mail must contain a valid domain"
        )
        String email,

        @NotBlank
        @Size(min = 8, message = "Password must be at least 8 characters long")
        @Pattern(
                // >=1 uppercase, >=1 lowercase, >=6 digits, total length validated by @Size
                regexp = "^(?=.*[A-Z])(?=.*[a-z])(?=(?:.*\\d){6,}).{8,}$",
                message = "Password must have at least 1 uppercase letter, 1 lowercase letter, and 6 digits"
        )
        String password
) {}
