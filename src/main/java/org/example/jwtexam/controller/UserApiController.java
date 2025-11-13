package org.example.jwtexam.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.jwtexam.domain.RefreshToken;
import org.example.jwtexam.domain.User;
import org.example.jwtexam.dto.UserLoginResponseDto;
import org.example.jwtexam.jwt.util.JwtTokenizer;
import org.example.jwtexam.security.dto.UserLoginDto;
import org.example.jwtexam.service.RefreshTokenService;
import org.example.jwtexam.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@Slf4j
@RequiredArgsConstructor
@RequestMapping("/api")
public class UserApiController {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenizer jwtTokenizer;
    private final RefreshTokenService refreshTokenService;

    @GetMapping("/welcome")
    public String welcome() {
        return "welcome";
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Valid UserLoginDto userLoginDto,
                                   BindingResult bindingResult,
                                   HttpServletResponse response) {
        // 1. 입력값이 유효한가?
        if (bindingResult.hasErrors()) {
            // Validation에 실패했을 때 에러메시지들을 바디에 담아서 반환
            log.info("bindingResult.hasError() =============");
            return ResponseEntity.badRequest().body(bindingResult.getAllErrors());
        }

        // 2. 입력한 사용자가 우리 시스템에 있는지 비밀번호는 맞는지 확인
        User user = userService.findByUsername(userLoginDto.getUsername()).orElse(null);

        // 사용자가 null이거나 비밀번호가 맞지 않을 경우 401 반환, 패스워드 비교 로직은 직접 짤 수 없음, 비밀번호는 인코딩 해줘야함
        if(user == null || !passwordEncoder.matches(userLoginDto.getPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("아이디 또는 비밀번호가 올바르지 않습니다.");
        }

        // 3. 토큰들을 발급
        // 3-1. 토큰 생성을 위해서 Role 정보를 추출
        List<String> roles = user.getRoles().stream()
                .map(role -> role.getName())
                .collect(Collectors.toList());

        // 3-2. Access Token, Refresh Token 발급
        String accessToken = jwtTokenizer.createAccessToken(user.getId(), user.getEmail(), user.getName(), user.getUsername(), roles);
        String refreshToken = jwtTokenizer.createRefreshToken(user.getId(), user.getEmail(), user.getName(), user.getUsername(), roles);

        // 4. 리프레시 토큰 DB 저장
        RefreshToken refreshTokenEntity = new RefreshToken();
        refreshTokenEntity.setToken(refreshToken);
        refreshTokenEntity.setUserId(user.getId());

        refreshTokenService.addRefreshToken(refreshTokenEntity);

        // 토큰을 쿠키에 구울 것인지, 응답으로만 보낼 것인지 (반드시 두개 다 할 필요는 없음)

        // 쿠키에 굽는 방법
        addTokenCookie(response, "accessToken", accessToken, jwtTokenizer.getAccessTokenExpiration());
        addTokenCookie(response, "refreshToken", refreshToken, jwtTokenizer.getRefreshTokenExpiration());

        // 응답 생성하는 방법
        UserLoginResponseDto loginResponseDto = UserLoginResponseDto.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .userId(user.getId())
                .name(user.getName())
                .build();

        return ResponseEntity.ok(loginResponseDto);
    }


    @PostMapping("/refreshMapping")
    public ResponseEntity<?> refreshToken(HttpServletRequest request) {
        // 1. 쿠키에서 리프레시 토큰을 추출

        // 2. 토큰이 없다면 400에러 반환

        // 3. 토큰을 검증 및 파싱 (예외 처리)

        // 4. DB에 저장된 리프레시 토큰과 가지고 온 리프레시 토큰이 일치하는지 확인 (반드시 해야할 일이지만, 에제에서는 선택)

        // 5. 사용자 정보 추출

        // 6. 새로운 액세스 토큰 생성

        // 7. 액세스 토큰 쿠키에 설정

        // 8. 응답으로 반환

        return ResponseEntity.ok("OK");
    }

    private void addTokenCookie(HttpServletResponse response, String name, String value, Long expiration) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);   // 자바스크립트는 접근 불가
        cookie.setPath("/");
        cookie.setMaxAge(Math.toIntExact(expiration / 1000));
        response.addCookie(cookie);     // https를 사용한다고 하면 cookie.setSecure(true) 설정 반드시 필요
    }
}
