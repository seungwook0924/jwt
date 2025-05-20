package com.seungwook.api.dto;


import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginRequest {

    @NotBlank(message = "UUID는 필수 입력값입니다.")
    private String uuid;
}