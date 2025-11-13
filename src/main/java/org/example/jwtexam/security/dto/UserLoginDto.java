package org.example.jwtexam.security.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.*;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Builder
public class UserLoginDto {
    @NotEmpty
    private String username;
    // @Pattern(regexp = "")   // 정규표현식 사용 가능
    @NotEmpty
    private String password;
}
