package org.example.basicjwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@Component
@Slf4j
public class JwtTokenizer {
    // 시크릿 키 -
    private final byte[] accessSecret;
    private final byte[] refreshSecret;

    public static Long ACCESS_TOKEN_EXPIRE_COUNT = 30 * 60 * 1000L; // 30분
    public static Long REFRESH_TOKEN_EXPIRE_COUNT = 7 * 24 * 60 * 60 * 1000L; // 1주일

    public JwtTokenizer(@Value("${jwt.secretKey}") String accessSecret,         // application.yml에 등록되어 있어야함
                        @Value("${jwt.refreshKey}") String refreshSecret) {     // application.yml에 등록되어 있어야함
        this.accessSecret = accessSecret.getBytes(StandardCharsets.UTF_8);
        this.refreshSecret = refreshSecret.getBytes(StandardCharsets.UTF_8);
    }

    // 이 객체가 가지고 있으면 편하게 사용할 메소드
    // ACCESS TOKEN 생성
    public String createAccessToken(Long id,
                                    String email,
                                    String name,
                                    String username,
                                    List<String> roles) {
        return createToken(id, email, name, username, roles, ACCESS_TOKEN_EXPIRE_COUNT, accessSecret);
    }

    // REFRESH TOKEN 생성
    public String createRefreshToken(Long id,
                                     String email,
                                     String name,
                                     String username,
                                     List<String> roles) {
        return createToken(id, email, name, username, roles, REFRESH_TOKEN_EXPIRE_COUNT, refreshSecret);
    }

    private String createToken(Long id,
                               String email,
                               String name,
                               String username,
                               List<String> roles,
                               Long expire,
                               byte[] secret)

    {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + expire);
        return Jwts.builder()
                .subject(username)
                .claim("email", email)
                .claim("userId", id)
                .claim("name", name)
                .claim("roles", roles)
                .issuedAt(now)
                .expiration(expiration)
                .signWith(getSigningKey(secret))
                .compact();
    }

    private SecretKey getSigningKey(byte[] secretKey){
        return Keys.hmacShaKeyFor(secretKey);
    }

    // 토큰을 파싱하는 메소드
    private Claims parseToken(String token, byte[] secret) {
        return Jwts.parser()
                .verifyWith(getSigningKey(secret))
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // AccessToken 파싱
    public Claims parseAccessToken(String accessToken){
        return parseToken(accessToken, accessSecret);
    }

    // RefreshToken 파싱
    public Claims parseRefreshToken(String refreshToken){
        return parseToken(refreshToken, refreshSecret);
    }

    // 토큰에서 id값만 빠르게 꺼내고 싶다면?
    //"Bearer 토큰값" 으로 들어오는 경우가 많아서 공백을 기준으로 나눠서 토큰값만 가져와서 쓰는게 좋음
    public Long getUserIdFromToken(String token){
        if(token.startsWith("Bearer ")){
            token = token.substring(7); // Bearer 로 시작하면 7번째부터 값을 가져옴
        }

        Claims claims = parseToken(token, accessSecret);
        return claims.get("userId", Long.class);
    }
}
