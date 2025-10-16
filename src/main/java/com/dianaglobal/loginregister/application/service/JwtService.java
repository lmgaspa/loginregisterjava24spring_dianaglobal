// src/main/java/com/dianaglobal/loginregister/application/service/JwtService.java
package com.dianaglobal.loginregister.application.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.time.Duration;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${application.jwt.secret}")
    private String secretKeyRawBase64;

    @Value("${application.jwt.access-ttl:PT15M}")
    private Duration accessTtl;

    public String extractEmail(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /** Access Token (curto) */
    public String generateAccessToken(String email) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + accessTtl.toMillis()))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String extractedEmail = extractEmail(token);
        return extractedEmail.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claimsResolver.apply(claims);
    }

    private Key getSignKey() {
        // JWT_SECRET deve ser Base64; ex.: 64+ bytes codificados
        byte[] keyBytes = Decoders.BASE64.decode(secretKeyRawBase64);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
