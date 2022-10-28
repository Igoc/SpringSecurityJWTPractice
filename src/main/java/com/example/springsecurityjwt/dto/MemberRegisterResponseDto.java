package com.example.springsecurityjwt.dto;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PROTECTED, force = true)
@Getter
public class MemberRegisterResponseDto {

    private final String nickname;

}