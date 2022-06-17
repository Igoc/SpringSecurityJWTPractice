package com.example.springsecurityjwt.repository;

import com.example.springsecurityjwt.domain.Member;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member, String> {
}
