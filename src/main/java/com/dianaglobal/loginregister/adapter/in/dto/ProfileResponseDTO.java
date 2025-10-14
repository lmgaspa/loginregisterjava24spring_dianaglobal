package com.dianaglobal.loginregister.adapter.in.dto;

import java.util.UUID;

public record ProfileResponseDTO(
        UUID id,
        String name,
        String email,
        String authProvider,   // new field
        boolean passwordSet    // new field
) {}
