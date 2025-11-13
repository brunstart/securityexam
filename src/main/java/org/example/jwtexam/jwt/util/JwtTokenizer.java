package org.example.jwtexam.jwt.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.example.jwtexam.jwt.exception.JwtExceptionCode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

@Component
@Slf4j
public class JwtTokenizer {
    private final byte[] accessSecret;
    private final byte[] refreshSecret;

    private final Long accessTokenExpiration;
    private final Long refreshTokenExpiration;

    /*
    jwt:
      secretKey: 12345678901234567890123456789012
      refreshKey: abcdefghijklmnopqrstuvwxyz123456
      access-expiratioin-ms: 1800000    # 30 * 60 * 1000
      refresh-expiration-ms: 604800000  # 7일
     */

    public JwtTokenizer(@Value("${jwt.secretKey}") String accessSecret,
                        @Value("${jwt.refreshKey}") String refreshSecret,
                        @Value("${jwt.access-expiratioin-ms}") String accessTokenExpireCount,
                        @Value("${jwt.refresh-expiration-ms}") String refreshTokenExpireCount) {
        this.accessSecret = accessSecret.getBytes(StandardCharsets.UTF_8);
        this.refreshSecret = refreshSecret.getBytes(StandardCharsets.UTF_8);
        this.accessTokenExpiration = Long.parseLong(accessTokenExpireCount);
        this.refreshTokenExpiration = Long.parseLong(refreshTokenExpireCount);
    }


    // 이 객체가 가지고 있으면 편하게 사용할 메소드
    // ACCESS TOKEN 생성
    public String createAccessToken(Long id,
                                    String email,
                                    String name,
                                    String username,
                                    List<String> roles) {
        return createToken(id, email, name, username, roles, accessTokenExpiration, accessSecret);
    }

    // REFRESH TOKEN 생성
    public String createRefreshToken(Long id,
                                     String email,
                                     String name,
                                     String username,
                                     List<String> roles) {
        return createToken(id, email, name, username, roles, refreshTokenExpiration, refreshSecret);
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
    // "Bearer 토큰값" 으로 들어오는 경우가 많아서 공백을 기준으로 나눠서 토큰값만 가져와서 쓰는게 좋음
    public Long getUserIdFromToken(String token){
        if(token == null || !token.startsWith("Bearer ")){
            throw new IllegalArgumentException("잘못된 형식입니다. ");
        }

        try {
            String jwt = token.substring(7); // Bearer 로 시작하면 7번째부터 값을 가져옴

            Claims claims = parseToken(jwt, accessSecret);
            return claims.get("userId", Long.class);
        } catch (ExpiredJwtException e) {
            log.warn("만료된 Access 토큰 : {}", e.getMessage());
            throw new RuntimeException(JwtExceptionCode.EXPIRED_TOKEN.getMessage());
        } catch (Exception e) {
            log.warn("JWT 파싱중 발생한 알 수 없는 오류 : {}", e.getMessage());
            throw new RuntimeException(JwtExceptionCode.UNKNOWN_ERROR.getMessage());
        }
    }

    public Long getAccessTokenExpiration() {
        return accessTokenExpiration;
    }

    public Long getRefreshTokenExpiration() {
        return refreshTokenExpiration;
    }
}
