package org.example.oauthexam.config;

import lombok.RequiredArgsConstructor;
import org.example.oauthexam.security.CustomOAuth2AuthenticationSuccessHandler;
import org.example.oauthexam.service.SocialUserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final SocialUserService socialUserService;
    private final CustomOAuth2AuthenticationSuccessHandler customOAuth2AuthenticationSuccessHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, CorsConfigurationSource configurationSource) throws Exception {

        return http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/userregform").permitAll()
                        .requestMatchers("/oauth2/**", "/login/oauth2/code/github", "/registerSocialUser", "/saveSocialUser").permitAll()  // oauth2에서 인증 요청 하는건 다 OK
                        .anyRequest().authenticated()   // 나머지는 인증 받아야 됨
                )
                .csrf(csrf -> csrf.disable())
                .formLogin(form -> form
                        .loginPage("/loginform")
                        .loginProcessingUrl("/login")
                        .defaultSuccessUrl("/", true) // 로그인 성공시 "/"으로 이동, 어디에 있던지
                        .permitAll()
                )
                .cors(cors -> cors.configurationSource(configurationSource))
                .httpBasic(httpBasic -> httpBasic.disable())
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/loginform")
                        .failureUrl("/loginFailure")
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(this.oauth2UserService())
                        )
                        .successHandler(customOAuth2AuthenticationSuccessHandler)
                )
                .logout(logout -> logout
                        .logoutSuccessUrl("/")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                )


                .build();
    }

    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
        DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
        return oauth2UserRequest -> {
            OAuth2User oAuth2User = delegate.loadUser(oauth2UserRequest);

            // 소셜 로그인 됐을 때 할 일
            // 정보를 가져와서
            String provider = oauth2UserRequest.getClientRegistration().getRegistrationId();
            String socialId = String.valueOf(oAuth2User.getAttributes().get("id"));
            String username = String.valueOf(oAuth2User.getAttributes().get("login"));
            String email = String.valueOf(oAuth2User.getAttributes().get("email"));
            String avatarUrl = String.valueOf(oAuth2User.getAttributes().get("avatar_url"));

            // 저장
            socialUserService.saveOrUpdateUser(socialId, provider, username, email, avatarUrl);
            return oAuth2User;

        };
    }


    @Bean
    public CorsConfigurationSource configurationSource(){
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedOrigin("*");
        config.addAllowedHeader("*");
        config.setAllowedMethods(List.of("GET","POST","DELETE","OPTIONS"));
        source.registerCorsConfiguration("/**",config);
        return source;
    }

}
