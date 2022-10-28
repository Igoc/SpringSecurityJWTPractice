package com.example.springsecurityjwt.dto;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

@NoArgsConstructor(access = AccessLevel.PROTECTED, force = true)
@Getter
public class MemberLoginRequestDto {

    @NotBlank
    @Email
    private final String email;

    @NotBlank
    private final String password;

}