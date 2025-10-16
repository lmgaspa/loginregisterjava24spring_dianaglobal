package com.dianaglobal.loginregister.adapter.in.dto.password;

public record ChangePasswordRequest(
        String currentPassword,
        @jakarta.validation.constraints.Pattern(
                regexp = "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d).{8,}$",
                message = "Password must include at least 1 uppercase letter, 1 lowercase letter, and 1 digit and be at least 8 characters"
        ) String newPassword
) {}
