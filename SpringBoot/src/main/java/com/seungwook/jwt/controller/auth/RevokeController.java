package com.seungwook.jwt.controller.auth;

import com.seungwook.jwt.dto.Response;
import com.seungwook.jwt.dto.auth.request.RevokeTokenRequest;
import com.seungwook.jwt.service.auth.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
public class RevokeController
{
    private final AuthService authService;

    // 관리자 전용 토큰 무효화 API (토큰 탈취 대응)
    @PostMapping("/revoke-token")
    public ResponseEntity<Response<Void>> revokeToken(@RequestBody RevokeTokenRequest request)
    {
        boolean success = authService.revokeToken(request.getToken());

        if (success)
        {
            return ResponseEntity.ok(Response.<Void>builder()
                    .message("토큰이 무효화되었습니다")
                    .build());
        }

        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Response.<Void>builder()
                        .message("유효하지 않은 토큰입니다")
                        .build());
    }
}