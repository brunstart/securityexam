package org.example.oauthexam.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.oauthexam.entity.SocialLoginInfo;
import org.example.oauthexam.entity.User;
import org.example.oauthexam.service.SocialLoginInfoService;
import org.example.oauthexam.service.UserService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class CustomOAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private final UserService userService;
    private final SocialLoginInfoService socialLoginInfoService;

    private String extractProviderFromUri(String uri){
        // 현재 예제에서는 /login/oauth2/code/github/ 로 넘어왔을 것.
        if(uri == null || uri.isBlank()){
            return null;
        }
        int idx = uri.indexOf("/login/oauth2/code/");      // /login/oauth2/code/으로 시작하지 않는다면
        if (idx == -1) return null;

        String provider = uri.substring(idx + "/login/oauth2/code/".length());
        if (provider.endsWith("/")) {       // /으로 끝나면
            provider = provider.substring(0, provider.length() - 1);    // 마지막 / 제거
        }
        return provider;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // 요청정보로부터 provider를 얻어온다. - provider : 소셜 로그인을 제공 (네이버, 구글, 깃허브 등등)
        // redirect-uri : "/login/oauth2/code/{registrationid}" uri 에서 해당 값을 꺼내서 뭔지 확인, 깃허브인지 네이버인지 카카오인지 등등 (provider를 확인)

        String requestURI = request.getRequestURI();    //  "/login/oauth2/code/{registrationid}"
        String provider = extractProviderFromUri(requestURI);

        // 잘못된 요청이므로 문제 발생
        if (provider == null) {
            response.sendRedirect("/");
            return;
        }

        // Authentication으로 부터 정보를 꺼낼 수 있을것
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        DefaultOAuth2User oauthUser = (DefaultOAuth2User) token.getPrincipal();

        // 깃허브 속성에서 id, name 을 추출
        String socialId = String.valueOf(oauthUser.getAttributes().get("id"));
        String name = String.valueOf(oauthUser.getAttributes()
                .getOrDefault("name", oauthUser.getAttributes()
                        .getOrDefault("login", "user")));   // name이 비공개여서 값이 없으면 login 값을, 그것도 없으면 user라고 값을 세팅

        // 기존 회원인지 확인 -- 어플리케이션의 처음 가입한 사용자라면 추가 정보를 받아야 한다.
        Optional<User> foundUser = userService.findByProviderAndSocialId(provider, socialId);

        // 기본 사용자라면, User에 정보가 이미 있을 것.
        if (foundUser.isPresent()) {
            User user = foundUser.get();

            // 우리 서비스에 맞게 교체
            CustomUserDetails customUserDetails = new CustomUserDetails(
                    user.getUsername(),
                    user.getPassword(),
                    user.getName(),
                    user.getRoles()
                            .stream()
                            .map(role -> "ROLE_" + role.getName())
                            .collect(Collectors.toList())
            );

            // Authentication 정보를 우리 시스템에 맞게 변환
            Authentication newAuth =
                    new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(newAuth);
            response.sendRedirect("/welcome");
            return;
        }

        // 어플리케이션의 신규 사용자일 경우 최소 정보만 저장한 후 추가 정보 입력화면으로 이동
        // 추가정보 입력화면으로 가기 전에 socialLoginInfo에 저장해 놓음
        // 저장한 정보를 토대로 정해진 시간보다 늦게 요청하면 오류 발생하기 위해
        SocialLoginInfo socialLoginInfo = socialLoginInfoService.saveSocialLoginInfo(provider, socialId);

        String redirect = "/registerSocialUser?provider="+provider
                +"&socialId="+url(socialId)
                +"&name="+url(name)
                +"&uuid="+url(socialLoginInfo.getUuid());

        response.sendRedirect(redirect);
    }

    // url에 정보를 그냥 보내면 보안 문제가 있으니까 중요한 정보는 encode함
    private String url(String s) {
        return URLEncoder.encode(s==null ? "" : s, StandardCharsets.UTF_8);
    }
}
