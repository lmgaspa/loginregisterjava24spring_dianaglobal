package com.dianaglobal.loginregister.adapter.in.dto.password;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Usado no endpoint /api/auth/password/set-unauthenticated
 * para usuários Google que ainda não definiram senha local.
 */
public record SetPasswordUnauthenticatedRequest(

        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email format")
        String email,

        @NotBlank(message = "Password cannot be blank")
        @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
        @Pattern(
                regexp = "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d).{8,}$",
                message = "Password must include at least 1 uppercase letter, 1 lowercase letter, and 1 digit and be at least 8 characters"
        )
        String newPassword
) {}
