package org.example.oauthexam.repository;

import org.example.oauthexam.entity.SocialLoginInfo;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface SocialLoginInfoRepository extends JpaRepository<SocialLoginInfo, String> {
    Optional<SocialLoginInfo> findByProviderAndUuidAndSocialId(String provider, String uuid, String socialId);
}
