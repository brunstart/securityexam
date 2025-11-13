package org.example.jwtexam.jwt.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {
    private Object principal;   // 사용자정보 (UserDetails)
    private Object credentials; // 인증자격증명 (보통은 비밀번호 들어감, JWT 기반에서는 null)

    // 인증이 완료된 후 호출되는 생성자
    public JwtAuthenticationToken(Collection<? extends GrantedAuthority> authorities, Object principal, Object credentials) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        setAuthenticated(true);
    }

    // 인증 전 사용되는 생성자
    public JwtAuthenticationToken(String token) {
        super(null); // 권한없음
        this.principal = null;
        this.credentials = token;
        setAuthenticated(false);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }
}
