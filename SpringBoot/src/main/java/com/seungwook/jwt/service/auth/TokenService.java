package com.seungwook.jwt.service.auth;

import com.seungwook.jwt.dto.auth.response.AuthResponse;
import com.seungwook.jwt.dto.auth.response.RefreshResponse;
import com.seungwook.jwt.enumeration.UserRole;
import com.seungwook.jwt.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService
{
    private final RedisSessionService redisSessionService;
    private final StringRedisTemplate redisTemplate;
    private final JwtTokenProvider jwtTokenProvider;

    // 토큰 저장
    public void save(String uuid, String refreshToken, long refreshTokenValidityMs)
    {
        redisTemplate.opsForValue().set("refresh:" + uuid, refreshToken, Duration.ofMillis(refreshTokenValidityMs));
    }

    // 토큰 조회
    public String get(String uuid)
    {
        return redisTemplate.opsForValue().get("refresh:" + uuid);
    }

    // 토큰 삭제
    public void delete(String uuid)
    {
        redisTemplate.delete("refresh:" + uuid);
    }

    /**
     * 액세스 토큰 생성
     */
    public String createAccessToken(String uuid, UserRole role)
    {
        return jwtTokenProvider.createAccessToken(uuid, "ROLE_" + role.name());
    }

    /**
     * 리프레시 토큰 생성
     */
    public String createRefreshToken()
    {
        return jwtTokenProvider.createRefreshToken();
    }

    /**
     * 토큰 남은 유효 시간 확인
     */
    public long getTokenRemainingTimeMillis(String token)
    {
        return jwtTokenProvider.getTokenRemainingTimeMillis(token);
    }

    /**
     * 토큰 검증
     */
    public boolean validateToken(String token)
    {
        return jwtTokenProvider.validate(token);
    }

    /**
     * 토큰에서 UUID 추출
     */
    public String getUuidFromToken(String token)
    {
        return jwtTokenProvider.getUuid(token);
    }

    /**
     * 토큰 블랙리스트 추가
     */
    public void blacklistToken(String token)
    {
        long remainingTime = jwtTokenProvider.getTokenRemainingTimeMillis(token);
        if (remainingTime > 0) redisSessionService.addToBlacklist(token, remainingTime);
    }

    /**
     * 사용자 로그아웃 처리
     */
    public boolean logout(String accessToken)
    {
        try
        {
            // 토큰 검증 및 UUID 추출
            if (!jwtTokenProvider.validate(accessToken)) return false;

            String uuid = jwtTokenProvider.getUuid(accessToken);
            if (uuid == null) return false;

            // 리프레시 토큰 삭제
            delete(uuid);

            // 액세스 토큰 블랙리스트 추가
            long remainingTime = jwtTokenProvider.getTokenRemainingTimeMillis(accessToken);
            if (remainingTime > 0) redisSessionService.addToBlacklist(accessToken, remainingTime);

            return true;
        }
        catch (Exception e)
        {
            log.error("로그아웃 처리 중 오류 발생: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * 토큰 갱신 로직 처리
     */
    public RefreshResponse refreshTokens(String accessToken, String refreshToken)
    {
        // 1. 리프레시 토큰 검증
        if (jwtTokenProvider.isRefreshTokenUsed(refreshToken))
        {
            // 보안 위협 대응 - 토큰 무효화
            invalidateTokens(accessToken);
            return RefreshResponse.failure("refresh 토큰이 유효하지 않습니다");
        }

        // 2. UUID 및 Role 추출
        String uuid = jwtTokenProvider.getUuid(accessToken);
        if (uuid == null) return RefreshResponse.failure("유효하지 않은 액세스 토큰입니다");

        String role = jwtTokenProvider.getRole(accessToken);
        if (role == null) return RefreshResponse.failure("유효하지 않은 액세스 토큰입니다");

        // 3. 토큰 갱신 처리
        jwtTokenProvider.markRefreshTokenAsUsed(refreshToken);

        // 새 토큰 발급
        String newAccessToken = jwtTokenProvider.createAccessToken(uuid, role);
        String newRefreshToken = jwtTokenProvider.createRefreshToken();

        // 4. 기존 토큰 무효화 및 새 토큰 저장
        invalidateAccessToken(accessToken);
        save(uuid, newRefreshToken, jwtTokenProvider.getTokenRemainingTimeMillis(newRefreshToken));

        // 5. 결과 반환
        return RefreshResponse.success(new AuthResponse(newAccessToken, newRefreshToken, uuid));
    }

    /**
     * 토큰 무효화 (액세스 토큰, 리프레시 토큰 모두)
     */
    private void invalidateTokens(String accessToken)
    {
        String uuid = jwtTokenProvider.getUuid(accessToken);
        if (uuid != null) delete(uuid);

        invalidateAccessToken(accessToken);
    }

    /**
     * 액세스 토큰 무효화 (블랙리스트에 추가)
     */
    private void invalidateAccessToken(String accessToken)
    {
        long remainingTime = jwtTokenProvider.getTokenRemainingTimeMillis(accessToken);
        if (remainingTime > 0) redisSessionService.addToBlacklist(accessToken, remainingTime);
    }
}