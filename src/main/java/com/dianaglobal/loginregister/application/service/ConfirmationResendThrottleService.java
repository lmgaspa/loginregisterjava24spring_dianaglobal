package com.dianaglobal.loginregister.application.service;

import com.dianaglobal.loginregister.adapter.out.persistence.ConfirmResendThrottleRepository;
import com.dianaglobal.loginregister.adapter.out.persistence.entity.ConfirmResendThrottleEntity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.*;
import java.util.UUID;

@Service
public class ConfirmationResendThrottleService {

    private final ConfirmResendThrottleRepository repo;

    @Value("${application.confirmation.cooldown-seconds:60}")
    private int cooldownSeconds;

    @Value("${application.confirmation.max-per-day:5}")
    private int maxPerDay;

    public ConfirmationResendThrottleService(ConfirmResendThrottleRepository repo) {
        this.repo = repo;
    }

    public static final class Info {
        private final boolean canResend;
        private final int cooldownSecondsRemaining;
        private final int attemptsToday;
        private final int maxPerDay;
        private final Instant nextAllowedAt;

        public Info(boolean canResend, int cooldownSecondsRemaining, int attemptsToday, int maxPerDay, Instant nextAllowedAt) {
            this.canResend = canResend;
            this.cooldownSecondsRemaining = cooldownSecondsRemaining;
            this.attemptsToday = attemptsToday;
            this.maxPerDay = maxPerDay;
            this.nextAllowedAt = nextAllowedAt;
        }
        public boolean canResend() { return canResend; }
        public int cooldownSecondsRemaining() { return cooldownSecondsRemaining; }
        public int attemptsToday() { return attemptsToday; }
        public int maxPerDay() { return maxPerDay; }
        public Instant nextAllowedAt() { return nextAllowedAt; }
    }

    private String idFor(UUID userId, LocalDate day) { return userId + ":" + day; }

    public Info preview(UUID userId, Instant now) {
        var day = LocalDate.ofInstant(now, ZoneOffset.UTC);
        var id = idFor(userId, day);
        var eOpt = repo.findById(id);
        if (eOpt.isEmpty()) {
            return new Info(true, 0, 0, maxPerDay, now);
        }
        var e = eOpt.get();

        int attempts = e.getAttemptsToday();
        boolean underDaily = attempts < maxPerDay;

        int remaining = 0;
        Instant next = now;
        if (e.getLastSentAt() != null) {
            Instant earliest = e.getLastSentAt().plusSeconds(cooldownSeconds);
            if (earliest.isAfter(now)) {
                remaining = (int) Duration.between(now, earliest).getSeconds();
                next = earliest;
            }
        }
        boolean underCooldown = remaining == 0;
        return new Info(underDaily && underCooldown, remaining, attempts, maxPerDay, next);
    }

    /** Incrementa contagem e atualiza lastSentAt, criando doc do dia se não existir. */
    public Info registerSend(UUID userId, Instant now, String emailHash) {
        var day = LocalDate.ofInstant(now, ZoneOffset.UTC);
        var id = idFor(userId, day);
        var e = repo.findById(id).orElseGet(() -> {
            var ne = new ConfirmResendThrottleEntity();
            ne.setId(id);
            ne.setUserId(userId);
            ne.setEmailHash(emailHash);
            ne.setAttemptsToday(0);
            ne.setCreatedAt(now);
            return ne;
        });

        e.setAttemptsToday(e.getAttemptsToday() + 1);
        e.setLastSentAt(now);
        repo.save(e);

        return preview(userId, now);
    }
}
