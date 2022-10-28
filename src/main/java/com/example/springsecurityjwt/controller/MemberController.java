package com.example.springsecurityjwt.controller;

import com.example.springsecurityjwt.dto.MemberRegisterRequestDto;
import com.example.springsecurityjwt.dto.MemberRegisterResponseDto;
import com.example.springsecurityjwt.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

@RestController
@RequestMapping("/api/member")
@Validated
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;

    @RequestMapping(value = "/email/{email}", method = RequestMethod.HEAD)
    public ResponseEntity<Void> checkEmailExistence(@PathVariable @NotBlank @Email final String email) {
        return (memberService.checkEmailExistence(email)) ?
                (ResponseEntity.ok().build()) :
                (ResponseEntity.notFound().build());
    }

    @PostMapping("")
    public ResponseEntity<MemberRegisterResponseDto> register(@RequestBody @Valid final MemberRegisterRequestDto requestDto) {
        final MemberRegisterResponseDto result = memberService.register(requestDto);

        return ResponseEntity.status(HttpStatus.CREATED).body(result);
    }

}