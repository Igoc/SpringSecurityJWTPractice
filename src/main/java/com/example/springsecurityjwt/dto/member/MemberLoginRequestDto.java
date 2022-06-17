package com.example.springsecurityjwt.dto.member;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class MemberLoginRequestDto {

    private String id;
    private String password;
}
