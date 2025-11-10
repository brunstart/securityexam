package org.example.securityexam4.repository;

import org.example.securityexam4.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User,Long> {
    User findByUsername(String username);   // User 클래스의 username의 name도 소문자니까 이것도 맞춰줘야함
    boolean existsByUsername(String username);  // 회원가입 시 아이디 중복 검증용
}
