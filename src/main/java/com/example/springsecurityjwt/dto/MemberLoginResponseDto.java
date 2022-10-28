package com.example.springsecurityjwt.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Builder
@Getter
public class MemberLoginResponseDto {

    private final String accessToken;

}