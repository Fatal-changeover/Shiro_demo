package com.abc.realm;

import com.abc.entity.Permission;
import com.abc.entity.Role;
import com.abc.entity.User;
import com.abc.service.PermissionService;
import com.abc.service.RoleService;
import com.abc.service.UserService;
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
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashSet;
import java.util.Set;

/**
 * ClassName: CustomRealm
 * Package: com.abc.realm
 * Description:
 *
 * @Author R
 * @Create 2024/5/2 10:14
 * @Version 1.0
 */
public class CustomRealm extends AuthorizingRealm {

    @Autowired
    private UserService userService;

    @Autowired
    RoleService roleService;

    @Autowired
    private PermissionService permissionService;
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
        User user =userService.findByUsername(username);
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


    //授权在认证之后的操作
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        //1. 获取认证用户的信息
        User user = (User) principals.getPrimaryPrincipal();
        //2. 基于用户信息获取当前用户拥有的角色。
        Set<Role> roleSet = roleService.findRolesByUid(user.getId());
        Set<Integer> roleIdSet = new HashSet<>();
        Set<String> roleNameSet = new HashSet<>();
        for (Role role : roleSet) {
            roleIdSet.add(role.getId());
            roleNameSet.add(role.getRoleName());
        }

        //3. 基于用户拥有的角色查询权限信息
        Set<Permission> permSet = permissionService.findPermsByRoleSet(roleIdSet);
        Set<String> permNameSet = new HashSet<>();
        for (Permission permission : permSet) {
            permNameSet.add(permission.getPermName());
        }
        //4. 声明AuthorizationInfo对象作为返回值，传入角色信息和权限信息
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        info.setRoles(roleNameSet);
        info.setStringPermissions(permNameSet);
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
