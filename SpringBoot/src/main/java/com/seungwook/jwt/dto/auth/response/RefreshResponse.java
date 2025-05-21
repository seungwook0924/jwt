package com.seungwook.jwt.dto.auth.response;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class RefreshResponse {
    private final boolean success;
    private final AuthResponse authResponse;
    private final String errorMessage;

    public static RefreshResponse success(AuthResponse authResponse) {
        return new RefreshResponse(true, authResponse, null);
    }

    public static RefreshResponse failure(String errorMessage) {
        return new RefreshResponse(false, null, errorMessage);
    }
}