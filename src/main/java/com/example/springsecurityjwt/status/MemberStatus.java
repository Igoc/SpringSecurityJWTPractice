package com.example.springsecurityjwt.status;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@RequiredArgsConstructor
@Getter
public enum MemberStatus {

    EXISTING_EMAIL(HttpStatus.CONFLICT, "must not be an existing email");

    private final HttpStatus httpStatus;
    private final String message;

}