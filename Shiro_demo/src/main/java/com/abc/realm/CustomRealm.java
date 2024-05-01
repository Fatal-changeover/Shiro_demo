package com.abc.realm;

import com.abc.pojo.User;
import com.alibaba.druid.util.StringUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import java.util.HashSet;
import java.util.Set;

/**
 * ClassName: CustomRealm
 * Package: com.abc.realm
 * Description:
 *
 * @Author R
 * @Create 2024/5/1 14:00
 * @Version 1.0
 */
public class CustomRealm extends AuthorizingRealm {
    //告诉shiro密码加密了 密码加密形式
    {
        HashedCredentialsMatcher matcher = new HashedCredentialsMatcher();
        matcher.setHashAlgorithmName("MD5");
        matcher.setHashIterations(1024);
        this.setCredentialsMatcher(matcher);
    }
    //认证
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        //1. 基于Token获取用户名
        String username = (String) token.getPrincipal();
        //2. 判断用户名（非空）
        if(StringUtils.isEmpty(username)){
            // 返回null，会默认抛出一个异常，org.apache.shiro.authc.UnknownAccountException
            return null;
        }
        //3. 如果用户名不为null，基于用户名查询用户信息
        User user = this.findUserByUsername(username);
        //4. 判断user对象是否为null
        if(user == null) {
            return null;
        }
        //5. 声明AuthenticationInfo对象，并填充用户信息
        SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(user, user.getPassword(), "CustomRealm");
        //6加盐
        info.setCredentialsSalt(ByteSource.Util.bytes(user.getSalt()));
        return info;
    }
    // 模拟数据库操作
    private User findUserByUsername(String username) {
        if("admin".equals(username)){
            User user = new User();
            user.setId(1);
            user.setUsername("admin");
            user.setSalt("awfgasadqwfge");
            user.setPassword("9e98f6e7c4ead40f56d7a251ab71234f");
            return user;
        }
        return null;
    }

    //授权在认证之后的操作
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        //1. 获取认证用户的信息
        User user = (User) principals.getPrimaryPrincipal();
        //2. 基于用户信息获取当前用户拥有的角色。
        Set<String> rolesByUser = findRolesByUser();
        //3. 基于用户拥有的角色查询权限信息
        Set<String> permsByRoleSet = findPermsByRoleSet();
        //4. 声明AuthorizationInfo对象作为返回值，传入角色信息和权限信息
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        info.setRoles(rolesByUser);
        info.setStringPermissions(permsByRoleSet);
        return info;
    }

    private Set<String> findPermsByRoleSet() {
        Set<String> set = new HashSet<>();
        set.add("user:add");
        set.add("user:update");
        return set;
    }

    private Set<String> findRolesByUser() {
        Set<String> set = new HashSet<>();
        set.add("超级管理员");
        set.add("运营");
        return set;
    }


}
