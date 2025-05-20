package com.seungwook.api.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final StringRedisTemplate redisTemplate;

    public void save(String uuid, String refreshToken, long refreshTokenValidityMs) {
        redisTemplate.opsForValue().set("refresh:" + uuid, refreshToken, Duration.ofMillis(refreshTokenValidityMs));
    }

    public String get(String uuid) {
        return redisTemplate.opsForValue().get("refresh:" + uuid);
    }

    public void delete(String uuid) {
        redisTemplate.delete("refresh:" + uuid);
    }
}
