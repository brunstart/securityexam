package org.example.jwtexam.jwt.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.jwtexam.jwt.exception.JwtExceptionCode;
import org.example.jwtexam.jwt.token.JwtAuthenticationToken;
import org.example.jwtexam.jwt.util.JwtTokenizer;
import org.example.jwtexam.security.CustomUserDetails;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

// OncePerRequestFilter 이 필터는 전체 요청 중 단 한 번만 실행된다       -- 일반 필터는 forward, include, error 등 상황에 여러번 호출될 수 있다.
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter { // servlet api의 filter를 구현한 OncePerRequestFilter를 상속받음
    private final JwtTokenizer jwtTokenizer;
    // 목적은 무엇일까
    // 요청에 포함된 JWT(AccessToken)을 검증하고, 토큰이 유효하다면 -> 인증된 사용자라면
    // Spring security의 SecurityContextHolder에다가 사용자 인증정보 (Authentication)을 등록


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // 해야할 일
        // 주요목적 : JWT 토큰을 검증하고, 토큰이 유효하면 Spring security의 SecurityContextHolder에
        // 사용자의 인증정보 (Authentication) 을 등록한다.

        // 1. 토큰을 얻어온다.
        String token = getToken(request);

        // 2. 토큰을 파싱해서 필요한 정보를 찾아서 Authentication 객체로 만들어서 SecurityContextHolder에 담는일까지 수행
        if(StringUtils.hasText(token)){
            try{
                getAuthentication(token);
            }catch (ExpiredJwtException e){
                request.setAttribute("exception", JwtExceptionCode.EXPIRED_TOKEN.getCode());
                log.error("Expired Token : {}",token,e);
                throw new BadCredentialsException("Expired token exception", e);
            }catch (UnsupportedJwtException e){
                request.setAttribute("exception", JwtExceptionCode.UNSUPPORTED_TOKEN.getCode());
                log.error("Unsupported Token: {}", token, e);
                throw new BadCredentialsException("Unsupported token exception", e);
            } catch (MalformedJwtException e) {
                request.setAttribute("exception", JwtExceptionCode.INVALID_TOKEN.getCode());
                log.error("Invalid Token: {}", token, e);
                throw new BadCredentialsException("Invalid token exception", e);
            } catch (IllegalArgumentException e) {
                request.setAttribute("exception", JwtExceptionCode.NOT_FOUND_TOKEN.getCode());
                log.error("Token not found: {}", token, e);
                throw new BadCredentialsException("Token not found exception", e);
            } catch (Exception e) {
                log.error("JWT Filter - Internal Error: {}", token, e);
                throw new BadCredentialsException("JWT filter internal exception", e);
            }
        }

        // 중요
        filterChain.doFilter(request, response);
    }

    // 토큰을 파싱해서 필요한 정보를 찾아서 Authentication 객체로 만들어서 SecurityContextHolder에 담는 메소드
    private void getAuthentication(String token) {
        Claims claims = jwtTokenizer.parseAccessToken(token);
        String username = claims.getSubject();
        Long userId = claims.get("userId",Long.class);
        String name = claims.get("name",String.class);
        String email = claims.get("email",String.class);

        // 권한 정보를 시큐리티가 원하는 형식으로 바꾸기 위함.
        List<GrantedAuthority> authorities = getAuthorities(claims);

        // 위에서 얻어온 정보를 UserDetails에 담는 작업
        CustomUserDetails customUserDetails = new CustomUserDetails(username, "", name,
                authorities.stream()
                        .map(GrantedAuthority::getAuthority)
                        .map(authority -> authority.replace("ROLE_", ""))
                        .collect(Collectors.toList()));

        Authentication authentication = new JwtAuthenticationToken(authorities, customUserDetails, null);
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    // 권한 정보를 List<String>으로 받아오는데 시큐리티는 List<GrantedAuthority> 형태를 원하기 때문에 변환해야함
    private List<GrantedAuthority> getAuthorities(Claims claims){
        List<String> roles = (List<String>)claims.get("roles");
        List<GrantedAuthority> authorities = new ArrayList<>();
        for(String role : roles) {
            authorities.add(new SimpleGrantedAuthority(role));
        }
        return authorities;
    }


    // 토큰을 얻어오는 메소드
    private String getToken(HttpServletRequest request) {

        // 헤더에서 access 토큰을 찾는다. (헤더로 accessToken이 들어온 경우)
        String authorization = request.getHeader("Authorization");
        if(StringUtils.hasText(authorization) && authorization.startsWith("Bearer ")) {
            return authorization.substring(7);
        }

        // accessToken을 쿠키에서 가져온다
        Cookie[] cookies = request.getCookies();
        if(cookies != null){
            for (Cookie cookie : cookies) {
                if("accessToken".equals(cookie.getName())){
                    return cookie.getValue();
                }
            }
        }

        return null;
    }
}
