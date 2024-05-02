package com.abc.controller;

import com.abc.entity.User;
import com.abc.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.jws.soap.SOAPBinding;

/**
 * ClassName: UserController
 * Package: com.abc.controller
 * Description:
 *
 * @Author R
 * @Create 2024/5/1 22:41
 * @Version 1.0
 */
@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserService userService;
    @GetMapping("/test")
    public User test(String username) {
       return userService.findByUsername(username);
    }
}
