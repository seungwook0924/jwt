package com.seungwook.api.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.UUID;
import java.time.Duration;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    private final RedisTemplate<String, String> redisTemplate;
    private static final String USED_TOKEN_PREFIX = "used_refresh_token:";

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.access-token-expiration}")
    private long accessTokenExpiration;

    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    private SecretKey key;

    @PostConstruct
    public void init() {
        // Base64 디코딩된 비밀키를 사용하여 SecretKey 생성
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public String createAccessToken(String uuid, String role) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + accessTokenExpiration);

        return Jwts.builder()
                .subject(uuid)
                .claim("role", role)
                .issuedAt(now)
                .claim("nbf", now.getTime() / 1000)
                .expiration(expiry)
                .signWith(key, Jwts.SIG.HS512)
                .compact();
    }

    public String createRefreshToken() {
        String jti = UUID.randomUUID().toString();
        Date now = new Date();
        Date expiry = new Date(now.getTime() + refreshTokenExpiration);

        String token = Jwts.builder()
                .id(jti)
                .issuedAt(now)
                .claim("nbf", now.getTime() / 1000)
                .expiration(expiry)
                .signWith(key, Jwts.SIG.HS512)
                .compact();

        // Redis에 리프레시 토큰 사용 상태 저장 (false = 미사용)
        redisTemplate.opsForValue().set(
                USED_TOKEN_PREFIX + jti,
                "false",
                Duration.ofMillis(refreshTokenExpiration)
        );

        return token;
    }

    public boolean isRefreshTokenUsed(String token) {
        try {
            String jti = Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getId();

            // Redis에서 토큰 사용 상태 확인
            String value = redisTemplate.opsForValue().get(USED_TOKEN_PREFIX + jti);

            // null인 경우 (존재하지 않는 경우) 또는 "true"인 경우 사용된 것으로 간주
            return value == null || "true".equals(value);
        } catch (Exception e) {
            return true;
        }
    }

    public void markRefreshTokenAsUsed(String token) {
        try {
            String jti = Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getId();

            // 토큰 남은 유효기간 계산
            long remainingTime = getTokenRemainingTimeMillis(token);

            // Redis에 사용됨으로 표시
            redisTemplate.opsForValue().set(
                    USED_TOKEN_PREFIX + jti,
                    "true",
                    Duration.ofMillis(remainingTime)
            );
        } catch (Exception ignored) {}
    }

    public String createToken(String uuid, String role) {
        return createAccessToken(uuid, role);
    }

    public String getUuid(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public String getRole(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("role", String.class);
    }

    public boolean validate(String token) {
        try {
            Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

    public long getTokenRemainingTimeMillis(String token) {
        try {
            Date expiration = Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getExpiration();

            return Math.max(0, expiration.getTime() - System.currentTimeMillis());
        } catch (Exception e) {
            return 0;
        }
    }
}