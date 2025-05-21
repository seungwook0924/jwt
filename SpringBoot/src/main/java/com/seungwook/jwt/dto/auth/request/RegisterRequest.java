package com.seungwook.jwt.dto.auth.request;

import com.seungwook.jwt.enumeration.UserRole;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.antlr.v4.runtime.misc.NotNull;

@Getter
@Setter
@NoArgsConstructor
public class RegisterRequest {
    @NotNull
    private UserRole role;
}