package com.example.springsecurityjwt.exception;

import com.example.springsecurityjwt.status.MemberStatus;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public class MemberException extends RuntimeException {

    private final MemberStatus status;

}