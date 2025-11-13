package org.example.jwtexam.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class CustomUserDetails implements UserDetails { // 기본 UserDetails 보다 추가적인 정보를 저장하기 위해 CustomUserDetails 사용
    private final String username;
    private final String password;
    private final String name;
    private final List<GrantedAuthority> authorities;
    public CustomUserDetails(String username,
                             String password,
                             String name,
                             List<String> roles) {
        this.username = username;
        this.password = password;
        this.name = name;
        this.authorities = roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_"+role))   //ROLE_USER, ROLE_ADMIN 직접 만들때는 ROLE_ 추가해줘야함, 스프링 시큐리티는 ROLE_~~으로 이름을 지어주는게 규칙임
                .collect(Collectors.toList());

    }

    public String getName() {
        return name;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}