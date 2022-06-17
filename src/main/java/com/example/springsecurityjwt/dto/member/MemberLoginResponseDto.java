package com.example.springsecurityjwt.dto.member;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Builder
@Getter
@Setter
public class MemberLoginResponseDto {

    private String id;
    private String name;
}
