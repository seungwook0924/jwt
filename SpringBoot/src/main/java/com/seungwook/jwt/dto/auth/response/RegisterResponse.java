package com.seungwook.jwt.dto.auth.response;

import com.seungwook.jwt.domain.User;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class RegisterResponse {
    private final String rawUuid;
    private final User user;
}
