package com.seungwook.jwt.dto.auth.request;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter @Setter
@NoArgsConstructor
public class RevokeTokenRequest {
    private String token;
}
