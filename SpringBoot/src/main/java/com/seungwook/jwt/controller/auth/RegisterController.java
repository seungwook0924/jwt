package com.seungwook.jwt.controller.auth;

import com.seungwook.jwt.dto.Response;
import com.seungwook.jwt.dto.auth.response.AuthResponse;
import com.seungwook.jwt.dto.auth.response.RegisterAndAuthResponse;
import com.seungwook.jwt.dto.auth.request.RegisterRequest;
import com.seungwook.jwt.service.auth.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
public class RegisterController
{
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<Response<AuthResponse>> register(@RequestBody RegisterRequest request)
    {
        // 회원가입 및 인증 로직을 서비스에 위임
        RegisterAndAuthResponse result = authService.registerAndAuthenticate(request.getRole());

        // HTTP 응답 구성
        return ResponseEntity.ok(Response.<AuthResponse>builder()
                .message("회원가입에 성공했습니다")
                .data(result.getAuthResponse())
                .build());
    }
}