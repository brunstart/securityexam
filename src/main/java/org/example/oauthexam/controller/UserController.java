package org.example.oauthexam.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.oauthexam.dto.SocialUserRequestDto;
import org.example.oauthexam.entity.Role;
import org.example.oauthexam.entity.SocialLoginInfo;
import org.example.oauthexam.entity.User;
import org.example.oauthexam.security.CustomUserDetails;
import org.example.oauthexam.service.SocialLoginInfoService;
import org.example.oauthexam.service.UserService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Controller
@RequiredArgsConstructor
@Slf4j
public class UserController {
    private final UserService userService;
    private final SocialLoginInfoService socialLoginInfoService;

    @GetMapping("/")
    public String home() {
        return "home";
    }

    @GetMapping("/welcome")
    public String welcome() {
        return "oauth/welcome";
    }

    @GetMapping("/loginform")
    public String loginForm() {
        return "oauth/users/loginform";
    }

    @GetMapping("/myinfo")
    public String info(@AuthenticationPrincipal Object customUserDetails, Model model) {
        model.addAttribute("user", customUserDetails);
        return "oauth/info";
    }

    @GetMapping("/registerSocialUser")
    public String registerSocialUser(@ModelAttribute SocialUserRequestDto requestDto, Model model) {
        // ?provider="+provider+"&socialId="+url(socialId)+"&name="+url(name)+"&uuid="+url(socialLoginInfo.getUuid())
        model.addAttribute("provider", requestDto.getProvider());
        model.addAttribute("socialId", requestDto.getSocialId());
        model.addAttribute("name", requestDto.getName());
        model.addAttribute("uuid", requestDto.getUuid());

        return "oauth/users/registerSocialUser";
    }

    @PostMapping("/saveSocialUser")
    public String saveSocialUser(@ModelAttribute SocialUserRequestDto requestDto) {
        Optional<SocialLoginInfo> socialLoginInfoOptional
                = socialLoginInfoService.findByProviderAndUuidAndSocialId(requestDto.getProvider(), requestDto.getUuid(), requestDto.getSocialId());

        // socialLoginInfoOptional 정보가 있는지?
        if (socialLoginInfoOptional.isPresent()) {
            SocialLoginInfo socialLoginInfo = socialLoginInfoOptional.get();
            LocalDateTime now = LocalDateTime.now();
            Duration duration = Duration.between(socialLoginInfo.getCreatedAt(), now);

            if (duration.toMinutes() > 20) {    // 시간체크
                return "redirect:/error";   // 20분 이상 경과하면 에러페이지로 redirect
            }

            // 20분 안 지났으면
            User saveUser = userService.saveUser(requestDto);   // 저장

            try {
                // 우리 시스템에 알려줘야함
                List<String> roles = saveUser.getRoles()
                        .stream()
                        .map(Role::getName)
                        .collect(Collectors.toList());

                // 시큐리티 컨텍스트 홀더에게 알맞는 정보(Authentication)를 만들어야 함
                CustomUserDetails customUserDetails = new CustomUserDetails(
                        saveUser.getUsername(),
                        saveUser.getPassword(),
                        saveUser.getName(),
                        roles
                );

                Authentication newAuth = new UsernamePasswordAuthenticationToken(
                        customUserDetails, null, customUserDetails.getAuthorities()
                );

                SecurityContextHolder.getContext().setAuthentication(newAuth);  // SecurityContextHolder에게 인증 정보를 맡겨놓음
            } catch (Exception e) {
                log.error("SecurityContext 갱신 중 오류 발생 : " + e.getMessage());
            }

            return "redirect:/";
        }else{
            return "redirect:/error";
        }
    }
}
