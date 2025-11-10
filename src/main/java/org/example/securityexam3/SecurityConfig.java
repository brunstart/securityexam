package org.example.securityexam3;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@SpringBootApplication
@Slf4j
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/userinfo","/info", "/hello", "/img/**", "/static/**").permitAll() //  ** 는 디렉토리 내 모든것을 의미
                        // .requestMatchers("/user/**").hasRole("USER")    // USER 라는 role을 가진 객체만 user 디렉토리로 접근 가능
                        .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")    // USER 또는 ADMIN 권한이 있는 사람만 접근 가능
                        .requestMatchers("/admin/super").hasRole("SUPERUSER")   // SUPERUSER만 admin/super에 접근 가능 /admin/** 설정보다 먼저 나와야함
                        .requestMatchers("/admin/**").hasRole("ADMIN")  // ADMIN role을 가진 사람만 admin에 접근 가능
                        .anyRequest()
                        .authenticated()
                );

        http
                .formLogin(Customizer.withDefaults())
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/hello")
                );


        return http.build();    // 위에서 선언한 http를 빌드해서 반환하겠다.
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails user = User.withUsername("user")
                .password(passwordEncoder.encode("1234"))   // 비밀번호를 인코딩해서 넣어줘야함
                .roles("USER")
                .build();

        UserDetails user2 = User.withUsername("carami")
                .password(passwordEncoder.encode("1234"))
                .roles("USER", "ADMIN")
                .build();

        UserDetails user3 = User.withUsername("admin")
                .password(passwordEncoder.encode("1234"))
                .roles("ADMIN")
                .build();

        UserDetails user4 = User.withUsername("superuser")
                .password(passwordEncoder.encode("1234"))
                .roles("SUPERUSER")     // userBuilder의 roles는 String으로 들어가야함. exam4에서 Role 객체의 집합을 쓰고 있으니까 거기서 role String 값을 뽑아와서 넣어줌
                .build();

        return new InMemoryUserDetailsManager(user, user2, user3, user4);   // 유저를 등록해줘야 함
    }

    @Bean
    public PasswordEncoder passwordEncoder() {  // 인코더 지정
        return new BCryptPasswordEncoder(); // 다른 인코더를 쓴다면 BCrupt~ 부분 교체
    }
}
