package com.abc.service;



import com.abc.entity.Role;

import java.util.Set;

/**
 * @author zjw
 * @description
 */
public interface RoleService {

    /**
     * 根据用户id查询角色信息
     * @param uid
     * @return
     */
    Set<Role> findRolesByUid(Integer uid);
}
