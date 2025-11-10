package org.example.securityexam4.controller;

import lombok.RequiredArgsConstructor;
import org.example.securityexam4.service.UserService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/admin")
@RequiredArgsConstructor
public class AdminController {
    private final UserService userService;

    @GetMapping("/setting")
    public String setting() {
        return "exam4/admin/settingpanel";
    }
}
