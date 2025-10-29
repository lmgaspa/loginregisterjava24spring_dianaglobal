package com.dianaglobal.loginregister.config;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class SimpleRateLimitInterceptor implements HandlerInterceptor {
    private static final int MAX_ATTEMPTS_PER_MIN = 10; // ajuste conforme necessidade
    private final ConcurrentHashMap<String, Deque<Long>> hits = new ConcurrentHashMap<>();

    private static String key(HttpServletRequest req) {
        String ip = Optional.ofNullable(req.getHeader("X-Forwarded-For"))
                .map(v -> v.split(",")[0].trim())
                .orElse(req.getRemoteAddr());
        String path = req.getRequestURI();
        return ip + "|" + path;
    }

    @Override
    public boolean preHandle(HttpServletRequest req, HttpServletResponse res, Object handler) throws Exception {
        if (!"POST".equals(req.getMethod())) return true;
        String uri = req.getRequestURI();
        if (!uri.matches("^/(api/)?auth/(login|register)$")) return true;

        long now = System.currentTimeMillis();
        Deque<Long> q = hits.computeIfAbsent(key(req), k -> new ArrayDeque<>());
        synchronized (q) {
            long cutoff = now - 60_000;
            while (!q.isEmpty() && q.peekFirst() < cutoff) q.pollFirst();
            if (q.size() >= MAX_ATTEMPTS_PER_MIN) {
                res.setStatus(429);
                res.setContentType("application/json");
                res.getWriter().write("{\"message\":\"Too many requests. Try again later.\"}");
                return false;
            }
            q.addLast(now);
        }
        return true;
    }
}
