package com.seungwook.api.controller;

import com.seungwook.api.domain.User;
import com.seungwook.api.dto.*;
import com.seungwook.api.jwt.JwtTokenProvider;
import com.seungwook.api.service.RedisSessionService;
import com.seungwook.api.service.RefreshTokenService;
import com.seungwook.api.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;
    private final RedisSessionService redisSessionService;
    private final RefreshTokenService refreshTokenService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest request) {
        String rawUuid = userService.registerNewUser(request.getRole());

        // 사용자 조회
        User user = userService.findByRawUuid(rawUuid);

        // 토큰 생성
        String accessToken = jwtTokenProvider.createAccessToken(rawUuid, "ROLE_" + user.getRole().name());
        String refreshToken = jwtTokenProvider.createRefreshToken();

        // 리프레시 토큰만 저장 (액세스 토큰은 저장하지 않음)
        refreshTokenService.save(rawUuid, refreshToken, jwtTokenProvider.getTokenRemainingTimeMillis(refreshToken));

        return ResponseEntity.ok(new AuthResponse(accessToken, refreshToken, rawUuid));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {
        // 사용자 인증
        User user = userService.findByRawUuid(request.getUuid());

        // 토큰 생성
        String accessToken = jwtTokenProvider.createAccessToken(request.getUuid(), "ROLE_" + user.getRole().name());
        String refreshToken = jwtTokenProvider.createRefreshToken();

        // 리프레시 토큰만 저장 (액세스 토큰은 저장하지 않음)
        refreshTokenService.save(request.getUuid(), refreshToken, jwtTokenProvider.getTokenRemainingTimeMillis(refreshToken));

        return ResponseEntity.ok(new AuthResponse(accessToken, refreshToken, request.getUuid()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody RefreshRequest request) {

        // 액세스 토큰 추출
        String accessToken = authHeader.substring(7);
        String refreshToken = request.getRefreshToken();

        // 리프레시 토큰 검증
        if (jwtTokenProvider.isRefreshTokenUsed(refreshToken)) {
            // 리프레시 토큰 재사용 감지 - 보안 이슈 가능성
            // 토큰 블랙리스트 처리
            long remainingTime = jwtTokenProvider.getTokenRemainingTimeMillis(accessToken);
            if (remainingTime > 0) {
                redisSessionService.addToBlacklist(accessToken, remainingTime);
            }

            // 리프레시 토큰도 삭제
            String uuid = jwtTokenProvider.getUuid(accessToken);
            if (uuid != null) {
                refreshTokenService.delete(uuid);
            }

            return ResponseEntity.status(401).build();
        }

        // UUID 가져오기 (직접 JWT에서 추출)
        String uuid = jwtTokenProvider.getUuid(accessToken);
        User user = userService.findByRawUuid(uuid);

        // 기존 리프레시 토큰 사용 처리
        jwtTokenProvider.markRefreshTokenAsUsed(refreshToken);

        // 새 토큰 발급
        String newAccessToken = jwtTokenProvider.createAccessToken(uuid, "ROLE_" + user.getRole().name());
        String newRefreshToken = jwtTokenProvider.createRefreshToken();

        // 기존 액세스 토큰 블랙리스트에 추가
        long remainingTime = jwtTokenProvider.getTokenRemainingTimeMillis(accessToken);
        if (remainingTime > 0) {
            redisSessionService.addToBlacklist(accessToken, remainingTime);
        }

        // 새 리프레시 토큰만 저장
        refreshTokenService.save(uuid, newRefreshToken, jwtTokenProvider.getTokenRemainingTimeMillis(newRefreshToken));

        return ResponseEntity.ok(new AuthResponse(newAccessToken, newRefreshToken, uuid));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("Authorization") String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);

            try {
                // 토큰에서 UUID 직접 추출
                String uuid = jwtTokenProvider.getUuid(token);

                if (uuid != null) {
                    // 리프레시 토큰 삭제
                    refreshTokenService.delete(uuid);

                    // 토큰 블랙리스트에 추가
                    long remainingTime = jwtTokenProvider.getTokenRemainingTimeMillis(token);
                    if (remainingTime > 0) {
                        redisSessionService.addToBlacklist(token, remainingTime);
                    }

                    return ResponseEntity.ok().build();
                }
            } catch (Exception e) {
                log.error("로그아웃 처리 중 오류 발생: {}", e.getMessage(), e);
            }
        }

        return ResponseEntity.ok().build();
    }

    @PostMapping("/revoke-token")
    public ResponseEntity<Void> revokeToken(@RequestBody RevokeTokenRequest request) {
        // 관리자 전용 토큰 무효화 API (토큰 탈취 대응)
        String token = request.getToken();

        if (jwtTokenProvider.validate(token)) {
            // 토큰 블랙리스트에 추가
            long remainingTime = jwtTokenProvider.getTokenRemainingTimeMillis(token);
            if (remainingTime > 0) {
                redisSessionService.addToBlacklist(token, remainingTime);
            }

            // 연관된 리프레시 토큰도 삭제
            String uuid = jwtTokenProvider.getUuid(token);
            if (uuid != null) {
                refreshTokenService.delete(uuid);
            }
        }

        return ResponseEntity.ok().build();
    }
}