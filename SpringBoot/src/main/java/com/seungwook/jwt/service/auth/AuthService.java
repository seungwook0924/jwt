package com.seungwook.jwt.service.auth;

import com.seungwook.jwt.domain.User;
import com.seungwook.jwt.dto.auth.response.AuthResponse;
import com.seungwook.jwt.dto.auth.response.LoginResponse;
import com.seungwook.jwt.dto.auth.response.RefreshResponse;
import com.seungwook.jwt.dto.auth.response.RegisterAndAuthResponse;
import com.seungwook.jwt.dto.auth.response.RegisterResponse;
import com.seungwook.jwt.enumeration.UserRole;
import com.seungwook.jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/*
    AuthService는 중재자 패턴(Mediator Pattern)을 구현한 서비스 클래스로, 인증 관련 모든 비즈니스 로직을 통합 관리한다.
    세부 비즈니스 로직은 AuthService에서 처리
    세부 구현은 UserService와 TokenService에 위임
*/
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService
{
    private final UserService userService;
    private final TokenService tokenService;

    /**
     * 회원가입 및 인증 통합 처리
     */
    @Transactional
    public RegisterAndAuthResponse registerAndAuthenticate(UserRole role)
    {
        // 1. 사용자 등록
        RegisterResponse registerResult = userService.registerNewUser(role);
        String rawUuid = registerResult.getRawUuid();
        User user = registerResult.getUser();

        // 2. 토큰 생성 및 저장
        String accessToken = tokenService.createAccessToken(rawUuid, user.getRole());
        String refreshToken = tokenService.createRefreshToken();

        // 3. 리프레시 토큰 저장
        tokenService.save(rawUuid, refreshToken, tokenService.getTokenRemainingTimeMillis(refreshToken));

        // 4. 결과 생성
        AuthResponse authResponse = new AuthResponse(accessToken, refreshToken, rawUuid);
        return new RegisterAndAuthResponse(registerResult, authResponse);
    }

    /**
     * 로그인 처리
     */
    public LoginResponse login(String uuid)
    {
        // 1. 사용자 검증
        Optional<User> userOpt = userService.findByRawUuid(uuid);
        if (userOpt.isEmpty()) return LoginResponse.failure("인증에 실패했습니다");

        User user = userOpt.get();

        // 2. 토큰 생성 및 저장
        String accessToken = tokenService.createAccessToken(uuid, user.getRole());
        String refreshToken = tokenService.createRefreshToken();
        tokenService.save(uuid, refreshToken, tokenService.getTokenRemainingTimeMillis(refreshToken));

        return LoginResponse.success(new AuthResponse(accessToken, refreshToken, uuid));
    }

    /**
     * 토큰 갱신 처리
     */
    public RefreshResponse refreshTokens(String accessToken, String refreshToken)
    {
        return tokenService.refreshTokens(accessToken, refreshToken);
    }

    /**
     * 로그아웃 처리
     */
    public boolean logout(String accessToken)
    {
        return tokenService.logout(accessToken);
    }

    /**
     * 토큰 무효화 처리 (관리자용)
     */
    public boolean revokeToken(String token)
    {
        if (!tokenService.validateToken(token)) return false;

        // 토큰 블랙리스트 추가 및 리프레시 토큰 삭제
        String uuid = tokenService.getUuidFromToken(token);
        if (uuid != null) tokenService.delete(uuid);

        tokenService.blacklistToken(token);

        return true;
    }
}