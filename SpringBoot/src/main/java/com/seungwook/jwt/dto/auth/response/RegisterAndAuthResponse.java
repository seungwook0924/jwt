package com.seungwook.jwt.dto.auth.response;

import lombok.AllArgsConstructor;
import lombok.Getter;

/*
    회원가입과 인증 프로세스의 결과를 함께 캡슐화하는 데이터 전송 객체
    회원가입 결과(RegisterResponse)와 인증 결과(AuthResponse)를 하나의 객체로 통합
*/
@Getter
@AllArgsConstructor
public class RegisterAndAuthResponse {
    private final RegisterResponse registerResponse; // 회원가입 결과 정보
    private final AuthResponse authResponse; // 인증 결과 정보(토큰)
}