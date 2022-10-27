package com.example.springsecurityjwt.service;

import com.example.springsecurityjwt.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;

    public boolean checkEmailExistence(final String email) {
        return memberRepository.findByEmail(email).isPresent();
    }

}