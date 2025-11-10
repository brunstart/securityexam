package org.example.securityexam2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
       // http
       //         .authorizeHttpRequests(auth -> auth
       //                 .anyRequest()
       //                 .authenticated()
       //         );

       return http
               .authorizeHttpRequests(auth -> auth
                       .requestMatchers("/hi", "/hello", "/loginForm").permitAll()  // hi, hello, loginForm은 로그인없이 볼 수 있도록 설정
                       .anyRequest().authenticated()
               )
       //          ;
       // http
               .formLogin(Customizer.withDefaults())
               .rememberMe(rememberMe -> rememberMe     // 다시 들어왔을 때 기억하도록 설정할 수 있음
                       .rememberMeParameter("rememberMe")
                       .tokenValiditySeconds(60)    // 쿠키의 제한시간 설정

               )
               .build();



        // return http.build();
    }
}
