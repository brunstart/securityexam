package org.example.oauthexam.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name="social_login_info")
@Getter
@Setter
public class SocialLoginInfo {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String provider;    // 깃헙, 네이버, 구글 등 소셜 로그인을 하게 해주는 매개체
    private String socialId;
    private LocalDateTime createdAt;
    private String uuid;

    public SocialLoginInfo() {
        // 소셜 로그인 후 추가정보를 받을 수 있는 제한시간을 두는것
        // 제한시간이 지나면 추가 작업을 못하게 막음
        this.createdAt = LocalDateTime.now();   // 소셜 로그인 한 시간
        this.uuid = UUID.randomUUID().toString();   // UUID 랜덤 값
    }
}
