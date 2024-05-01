package com.abc;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.subject.Subject;
import org.junit.jupiter.api.Test;

/**
 * ClassName: TEST1
 * Package: com.abc
 * Description:
 *
 * @Author R
 * @Create 2024/5/1 13:06
 * @Version 1.0
 */
public class Test1 {
    @Test
    public void authen() {
        //认证的发起者(subject)，   SecurityManager，   Realm
        //1. 准备Realm（基于内存存储用户信息）
        SimpleAccountRealm realm = new SimpleAccountRealm();
        realm.addAccount("admin","admin","超级管理员","商家");
        //2. 准备SecurityManager
        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        //3. SecurityManager和Realm建立连接
        securityManager.setRealm(realm);
        //4. subject和SecurityManager建立联系
        SecurityUtils.setSecurityManager(securityManager);
        //5. 声明subject
        Subject subject = SecurityUtils.getSubject();
        //6. 发起认证
        subject.login(new UsernamePasswordToken("admin","admin"));
        // 如果认证时，用户名错误，抛出：org.apache.shiro.authc.UnknownAccountException异常
        // 如果认证时，密码错误，抛出：org.apache.shiro.authc.IncorrectCredentialsException:
        //7. 判断是否认证成功
        System.out.println(subject.isAuthenticated());
        //8. 退出登录后再判断
        //        subject.logout();
        //        System.out.println("logout方法执行后，认证的状态：" + subject.isAuthenticated());

        //9. 授权是在认证成功之后的操作！！！
        // SimpleAccountRealm只支持角色的授权
        System.out.println("是否拥有超级管理员的角色"+subject.hasRole("超级管理员"));
        // check方法校验角色时，如果没有指定角色，会抛出异常：org.apache.shiro.authz.UnauthorizedException: Subject does not have role [角色信息]
        subject.checkRole("商家");
    }
}
