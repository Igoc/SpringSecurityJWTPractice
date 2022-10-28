package com.example.springsecurityjwt.dto;

import com.example.springsecurityjwt.domain.Member;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@NoArgsConstructor(access = AccessLevel.PROTECTED, force = true)
@Getter
public class MemberRegisterRequestDto {

    @NotBlank
    @Email
    private final String email;

    @NotBlank
    private final String password;

    @NotBlank
    @Size(max = Member.NICKNAME_MAX_LENGTH)
    private final String nickname;

    @NotNull
    private final boolean admin;

}