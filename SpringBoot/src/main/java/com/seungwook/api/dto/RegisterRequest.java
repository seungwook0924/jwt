package com.seungwook.api.dto;

import com.seungwook.api.enumeration.UserRole;
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