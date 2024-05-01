package com.abc;

import com.alibaba.druid.pool.DruidDataSource;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.Subject;
import org.junit.jupiter.api.Test;

/**
 * ClassName: Test3_JdbcRealm
 * Package: com.abc
 * Description:
 *
 * @Author R
 * @Create 2024/5/1 13:33
 * @Version 1.0
 */
public class Test3_JdbcRealm {
    @Test
    public void test1() {
        //1. 构建JdbcRealm
        JdbcRealm realm = new JdbcRealm();
        DruidDataSource dataSource = new DruidDataSource();
        dataSource.setDriverClassName("com.mysql.cj.jdbc.Driver");
        dataSource.setUrl("jdbc:mysql://192.168.150.88:3306/shiro");
        dataSource.setUsername("root");
        dataSource.setPassword("123456");
        realm.setDataSource(dataSource);
        //2. 构建SecurityManager绑定Realm
        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        securityManager.setRealm(realm);
        //3. 基于SecurityUtils绑定SecurityManager并声明subject
        SecurityUtils.setSecurityManager(securityManager);
        Subject subject = SecurityUtils.getSubject();
        //4. 认证操作
        subject.login(new UsernamePasswordToken("admin","admin"));
        //5. 授权操作(角色)
        System.out.println(subject.hasRole("超级管1理员"));
        realm.setPermissionsLookupEnabled(true);
        //6. 授权操作(权限)  默认不开启
        System.out.println(subject.isPermitted("user:add"));
    }
}
