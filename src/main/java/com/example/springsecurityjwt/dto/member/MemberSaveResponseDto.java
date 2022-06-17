package com.example.springsecurityjwt.dto.member;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Builder
@Getter
@Setter
public class MemberSaveResponseDto {

    private String id;
    private String name;
}
