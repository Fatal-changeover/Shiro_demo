package com.abc;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.Subject;
import org.junit.jupiter.api.Test;

/**
 * ClassName: Test_IniRealm
 * Package: com.abc
 * Description:
 *
 * @Author R
 * @Create 2024/5/1 13:13
 * @Version 1.0
 */
public class Test2_IniRealm {
    @Test
    public void test1() {
        //1. 构建IniRealm   支持权限校验
        IniRealm realm = new IniRealm("classpath:shiro.ini");
        //2. 构建SecurityManager绑定Realm
        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        securityManager.setRealm(realm);
        //3. 基于SecurityUtils绑定SecurityManager并声明subject
        SecurityUtils.setSecurityManager(securityManager);
        Subject subject = SecurityUtils.getSubject();
        //4. 认证操作
        subject.login(new UsernamePasswordToken("admin","admin"));
        System.out.println(subject.hasRole("超级管理员"));
        subject.checkRole("运营");
        // 如果没有响应的权限，就抛出异常：UnauthorizedException: Subject does not have permission [user:select]
        System.out.println(subject.isPermitted("user:update"));


    }
}
