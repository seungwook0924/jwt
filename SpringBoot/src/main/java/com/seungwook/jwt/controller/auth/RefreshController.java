package com.seungwook.jwt.controller.auth;

import com.seungwook.jwt.dto.Response;
import com.seungwook.jwt.dto.auth.response.AuthResponse;
import com.seungwook.jwt.dto.auth.request.RefreshRequest;
import com.seungwook.jwt.dto.auth.response.RefreshResponse;
import com.seungwook.jwt.service.auth.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
public class RefreshController
{
    private final AuthService authService;  // TokenService 대신 AuthService 사용

    @PostMapping("/refresh")
    public ResponseEntity<Response<AuthResponse>> refresh(@RequestHeader("Authorization") String authHeader, @RequestBody RefreshRequest refreshRequest)
    {
        // 헤더에서 토큰 추출
        String accessToken = authHeader.substring(7);
        String refreshToken = refreshRequest.getRefreshToken();

        // 비즈니스 로직을 AuthService에 위임
        RefreshResponse result = authService.refreshTokens(accessToken, refreshToken);

        // 결과에 따른 응답 생성
        if (result.isSuccess())
        {
            return ResponseEntity.ok(Response.<AuthResponse>builder()
                    .message("토큰이 갱신되었습니다")
                    .data(result.getAuthResponse())
                    .build());
        }
        else
        {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Response.<AuthResponse>builder()
                            .message(result.getErrorMessage())
                            .build());
        }
    }
}