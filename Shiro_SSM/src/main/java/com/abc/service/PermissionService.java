package com.abc.service;


import com.abc.entity.Permission;

import java.util.Set;

/**
 * @author zjw
 * @description
 */
public interface PermissionService {

    /**
     * 根据角色id，查询角色对应的权限
     * @param roleIdSet
     * @return
     */
    Set<Permission> findPermsByRoleSet(Set<Integer> roleIdSet);
}
