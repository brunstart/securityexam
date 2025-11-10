package org.example.securityexam4.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.securityexam4.dto.UserRegisterDTO;
import org.example.securityexam4.service.UserService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
@RequiredArgsConstructor
@RequestMapping("/user")
@Slf4j
public class UserController {
    private final UserService userService;

    @GetMapping("/welcome")
    public String welcome(){
        return "exam4/welcome";
    }

    @GetMapping("/regForm")
    public String regForm() {
        return "exam4/users/signup";
    }

    @PostMapping("/userreg")
    public String userreg(@ModelAttribute UserRegisterDTO userRegisterDTO) {
        System.out.println("userreg");
        // 사용자가 입력한 username이 이미 시스템에 존재하는지 체크
        if(userService.existsByUsername(userRegisterDTO.getUsername())) {
            log.info("사용중인 아이디 :: " +  userRegisterDTO.getUsername());
            return "exam4/users/userreg-error";
        }

        userService.registerUser(userRegisterDTO);
        return "redirect:/user/welcome";
    }


    // 로그인 폼 요청
    @GetMapping("/loginform")
    public String loginForm() {
        return "exam4/users/loginform";
    }

    @GetMapping("/myinfo")
    public String myinfo() {
        return "exam4/myinfo";
    }

    @GetMapping
    public String user() {
        return "exam4/home";
    }
}
