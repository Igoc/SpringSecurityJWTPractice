package com.example.springsecurityjwt.controller;

import com.example.springsecurityjwt.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

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

}