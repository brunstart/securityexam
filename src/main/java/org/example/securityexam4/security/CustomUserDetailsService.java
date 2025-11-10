package org.example.securityexam4.security;

import lombok.RequiredArgsConstructor;
import org.example.securityexam4.domain.Role;
import org.example.securityexam4.domain.User;
import org.example.securityexam4.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.security.core.userdetails.User.UserBuilder;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 로그인을 시큐리티가 하는데 필요한 UserDetails 정보를 생성해야함
        // UserDetails를 넘겨주면 시큐리티는 이거를 가지고 맞는 사용자인지 확인
        // 이 메소드는 UserDetails를 만드는 메소드
        User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException(username + " 에 해당하는 사용자가 없습니다.");
        }

        UserBuilder userBuilder = org.springframework.security.core.userdetails.User.withUsername(username);    // User는 이미 만들어놓은걸 import 하고 있어서 다른걸 또 import 못함 -> 패키지명까지 전부 적음
        // UserBuilder는 import 가능
        userBuilder.password(user.getPassword());
        userBuilder.roles(
                user.getRoles() // Role의 iterable을 가져옴
                        .stream()   // Set<Role>의 role 들을 대상으로 실행
                        .map(Role::getName)
                        .toList()
                        .toArray(new String[0])
        );

        return userBuilder.build();
    }
}
