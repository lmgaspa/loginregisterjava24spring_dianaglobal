package com.dianaglobal.loginregister.adapter.out.persistence.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.UUID;

@Document("confirm_resend_throttle")
public class ConfirmResendThrottleEntity {

    @Id
    private String id;                 // userId + ":" + yyyy-MM-dd (chave do dia)
    @Indexed
    private UUID userId;
    @Indexed
    private String emailHash;          // opcional (anti-enumeração)
    private int attemptsToday;
    private Instant lastSentAt;
    private Instant createdAt;         // TTL via índice programático (TtlIndexRepair)

    public ConfirmResendThrottleEntity() {}

    // Getters/Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public UUID getUserId() { return userId; }
    public void setUserId(UUID userId) { this.userId = userId; }

    public String getEmailHash() { return emailHash; }
    public void setEmailHash(String emailHash) { this.emailHash = emailHash; }

    public int getAttemptsToday() { return attemptsToday; }
    public void setAttemptsToday(int attemptsToday) { this.attemptsToday = attemptsToday; }

    public Instant getLastSentAt() { return lastSentAt; }
    public void setLastSentAt(Instant lastSentAt) { this.lastSentAt = lastSentAt; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
