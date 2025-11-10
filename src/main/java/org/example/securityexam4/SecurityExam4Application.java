package org.example.securityexam4;

import lombok.extern.slf4j.Slf4j;
import org.example.securityexam4.domain.Role;
import org.example.securityexam4.repository.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.List;

@Slf4j
@SpringBootApplication
public class SecurityExam4Application {
    public static void main(String[] args) {
        SpringApplication.run(SecurityExam4Application.class, args);
    }

    @Bean
    public CommandLineRunner commandLineRunner(RoleRepository roleRepository) {
        return args -> {
            // 데이터베이스의 Role 테이블에 데이터가 있으면 실행하지 않고, 하나도 없다면
            // USER와 ADMIN을 추가
            if (roleRepository.count() == 0) {
                Role userRole = new Role();
                userRole.setName("USER");

                Role adminRole = new Role();
                adminRole.setName("ADMIN");

                roleRepository.saveAll(List.of(userRole,adminRole));
                log.info("USER, ADMIN 권한 추가");
            }else{
                log.info("권한 정보 존재");
            }
        };
    }
}
