package org.example.securityexam;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AndRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // 1. 사용자가 아무것도 안했을 때 스프링부트의 시큐리티는 아래와 같은 설정으로 동작 (기본임)
        // return http
        //         .authorizeHttpRequests(auth -> auth
        //                 .anyRequest()   // 모든 요청에 대해
        //                 .authenticated()    // 인증을 요구
        //         )
        //         .formLogin(Customizer.withDefaults())
        //         .httpBasic(Customizer.withDefaults())
        //         .csrf(Customizer.withDefaults())
        //         .build();

        return http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/hi", "hello", "/test/*", "/loginForm", "/fail").permitAll()  // 특정 url만 permitAll -> 로그인 필요없이 볼 수 있게 설정
                        .anyRequest().authenticated()   // 나머지 모든 요청에 대해서는 인증을 요구하겠다.
                )
                // .formLogin(Customizer.withDefaults())    // 기본
                .formLogin(formLogin -> formLogin
                        // .loginPage("/loginForm")    // 시큐리티가 제공하는 로그인폼 페이지가 아닌 사용자가 원하는 페이지로 사용하도록 설정
                        .defaultSuccessUrl("/success", true)   // 로그인에 성공하면 어디로 갈지 결정, 두번째 파라미터 없거나 false면 /login 에서 로그인 했을때만 success로 감
                                                        // info, home을 요청하고 로그인하면 요청한 화면으로 감, 두번째 파라미터가 true면 로그인 성공했을때 무조건 success로 감
                        .loginProcessingUrl("/login_proc")  // 로그인하는 로직을 시큐리티가 갖고 있어서 짤 필요 없음, 로그인 요청을 보낼 때의 URL을 설정하는곳
                        .usernameParameter("email") // 유저네임의 name을 변경할 수 있음
                        .passwordParameter("pwd")   // password의 name을 변경할 수 있음
                        // .failureUrl("/fail")    // 실패시 연결할 url
                        .successHandler((request, response, authentication) -> {    // 인증관련 정보를 authentication에 저장
                            // 인증에 성공했을 때 내가 하고 싶은 일을 직접 구현할 수 있음
                            System.out.println("로그인 성골 " + authentication.getName());   // 콘솔에 이름 출력
                            response.sendRedirect("/info"); // 성공하면 info로 리다이렉트
                        })
                        .failureHandler((request, response, exception) -> {
                            System.out.println("로그인 실패 " + exception.getMessage());
                            response.sendRedirect("/hello");
                        })
                )
                .logout(logout -> logout
                        // .logoutUrl("/logout_carami")    // POST 전용, Get 방식이 허용하는 것을 위험하다고 판단
                        .logoutSuccessUrl("/hello")
                        .addLogoutHandler((request, response, authentication) -> {
                            // 로그아웃할 때 어떤 일을 진행해야 할지
                            System.out.println("로그아웃, 세션, 쿠키도 삭제");
                            request.getSession(false).invalidate(); // 세션삭제
                        })
                        .deleteCookies("JSESSIONID")
                )
                .build();
    }
}
