package com.example.springsecurityjwt.dto.member;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Builder
@Getter
@Setter
public class MemberTokenResponseDto {

    private String token;
}
