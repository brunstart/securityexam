package org.example.basicjwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

public class JwtExample {
    public static void main(String[] args) {
        // 1. 시크릿 키 (256 비트)
        // 생성 방법 1
        SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        System.out.println(secretKey);

        // 생성 방법 2 - 내가 정해준 문자열을 바탕으로 생성 (문자열만 같으면, 같은 시크릿 키를 얻어옴)
        String secret = "abcdefghijklmnopqrstuvwxzy123456";
        SecretKey secretKey2 = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));

        System.out.println(secretKey2);

        // SecretKey는 jwt 토큰을 생성할 때 사용 (서명 추가 시)

        // 2. JWT 생성
        String jwt = Jwts.builder()
                .issuer("lion-auth") //토큰을 발급한 주체
                .subject("carami") //username  토큰의 주인. 사용자ID or email
                .audience().add("lion-server").add("lion-frontserver").and()  // 이 토큰은 누구를 위한 것인가를 명시해서 의도하지 않은 곳에서 사용을 방지
                .expiration(new Date(System.currentTimeMillis() + 3600 * 1000)) //토큰만료시간  3600초 = 60분 = 1시간입니다.
                .notBefore(new Date()) // 발급한 후에 언제부터 쓸 수 있을지 정할 수 있음 (지금부터 가능하도록 설정 되어있다)
                .claim("role", "ADMIN") //커스텀데이터, 표준 클레임외에 필요한 정보를 넣을 수 있다.
                .claim("name", "kang")
                .signWith(secretKey2)  //토큰에 서명추가
                .compact(); //jwt 문자열로 변환

        System.out.println(jwt);

        // 3. jwt 파싱 및 검증
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(secretKey2)
                    .requireIssuer("lion-auth")
                    .requireAudience("lion-server2")
                    .build()
                    .parseSignedClaims(jwt)
                    .getPayload();

            // 원하는 정보를 꺼내 보세요.
            System.out.println(claims.getIssuer());
            System.out.println(claims.getSubject());
            System.out.println(claims.get("role"));
            System.out.println(claims.get("name"));
            System.out.println(claims.getExpiration());
        }catch (IncorrectClaimException i){
            System.out.println("클레임 값 불일치");
        }catch (JwtException j){
            System.out.println("토큰 검증 실패 " + j.getMessage());
        }
    }
}
