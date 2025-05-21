package com.seungwook.jwt.dto.auth.response;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class LoginResponse {
    private final boolean success;
    private final AuthResponse authResponse;
    private final String errorMessage;

    public static LoginResponse success(AuthResponse authResponse) {
        return new LoginResponse(true, authResponse, null);
    }

    public static LoginResponse failure(String errorMessage) {
        return new LoginResponse(false, null, errorMessage);
    }
}