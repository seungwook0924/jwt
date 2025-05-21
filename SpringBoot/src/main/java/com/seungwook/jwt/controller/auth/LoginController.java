package com.seungwook.jwt.controller.auth;

import com.seungwook.jwt.dto.Response;
import com.seungwook.jwt.dto.auth.response.AuthResponse;
import com.seungwook.jwt.dto.auth.response.LoginResponse;
import com.seungwook.jwt.dto.auth.request.LoginRequest;
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
public class LoginController {
    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<Response<AuthResponse>> login(@RequestBody LoginRequest request)
    {
        // 서비스에 비즈니스 로직 위임
        LoginResponse result = authService.login(request.getUuid());

        // 결과에 따른 응답 생성
        if (result.isSuccess())
        {
            return ResponseEntity.ok(Response.<AuthResponse>builder()
                    .message("로그인에 성공했습니다")
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

    @PostMapping("/logout")
    public ResponseEntity<Response<Void>> logout(@RequestHeader(value = "Authorization", required = false) String authHeader)
    {
        // 토큰 추출
        if (authHeader != null && authHeader.startsWith("Bearer "))
        {
            String accessToken = authHeader.substring(7);
            authService.logout(accessToken);
        }

        return ResponseEntity.ok(Response.<Void>builder()
                .message("로그아웃 되었습니다")
                .build());
    }
}