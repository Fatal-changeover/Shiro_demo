package com.mashibing.controller;

import io.buji.pac4j.subject.Pac4jPrincipal;
import org.apache.shiro.SecurityUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author zjw
 * @description
 */
@RestController
public class TestController {

    @GetMapping("/test")
    public String test(){
        // 获取主体
        Pac4jPrincipal pac4jPrincipal = SecurityUtils.getSubject().getPrincipals().oneByType(Pac4jPrincipal.class);
        return "Hello pac4j and CAS，user info：" + pac4jPrincipal.toString();
    }

}
