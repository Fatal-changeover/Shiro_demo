package com.abc;

import com.abc.realm.CustomRealm;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.junit.jupiter.api.Test;

/**
 * ClassName: Test4_CustomRealm
 * Package: com.abc
 * Description:
 *
 * @Author R
 * @Create 2024/5/1 13:56
 * @Version 1.0
 */
public class Test4_CustomRealm {
   @Test
    public void test1() {
       CustomRealm realm = new CustomRealm();
       //2. 构建SecurityManager绑定Realm
       DefaultSecurityManager securityManager = new DefaultSecurityManager();
       securityManager.setRealm(realm);
       //3. 基于SecurityUtils绑定SecurityManager并声明subject
       SecurityUtils.setSecurityManager(securityManager);
       Subject subject = SecurityUtils.getSubject();
       //4. 认证操作
       subject.login(new UsernamePasswordToken("admin","admin"));
       System.out.println("认证成功");
       //System.out.println(new Md5Hash("admin","awfgasadqwfge",1024).toString());

       //5.授权
       System.out.println(subject.hasRole("超级管理员"));
       System.out.println(subject.isPermitted("user:add"));
   }
}
