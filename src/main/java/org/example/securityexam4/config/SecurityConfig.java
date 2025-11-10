package org.example.securityexam4.config;

import jakarta.persistence.Entity;
import lombok.RequiredArgsConstructor;
import org.example.securityexam4.security.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.HttpSessionEventPublisher;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final CustomUserDetailsService customUserDetailsService;

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, SessionRegistry sessionRegistry) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/user/regForm", "/user/userreg", "/user/welcome", "/user").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/shop/**").hasAnyRole("USER", "ADMIN")
                        .anyRequest().authenticated()
                );

        http
                .formLogin(form -> form
                        .loginPage("/user/loginform")
                        .loginProcessingUrl("/login")   // 로그인 폼 action에 이 url이 들어가야함
                        .usernameParameter("username")  // html에 있는 username의 name과 맞아야함
                        .passwordParameter("password")  // html에 있는 password의 name과 맞아야함
                        .defaultSuccessUrl("/user/welcome", true)
                        .permitAll()
                );

        http
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/user/welcome")
                );

        http
                .userDetailsService(customUserDetailsService);  // userDetailsService로 customUserDetailsService를 쓰겠다.

        http
                .sessionManagement(session -> session
                        .maximumSessions(1)                 // 동시접속 허용 수 설정
                        .maxSessionsPreventsLogin(false)    // 기본값 false -> 먼저 로그인한 사용자가 차단됨.
                        .sessionRegistry(sessionRegistry)
                );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
