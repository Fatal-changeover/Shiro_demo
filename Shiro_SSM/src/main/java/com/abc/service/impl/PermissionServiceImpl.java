package com.abc.service.impl;

import com.abc.entity.Permission;
import com.abc.mapper.PermissionMapper;
import com.abc.service.PermissionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Set;

/**
 * @author zjw
 * @description
 */
@Service
public class PermissionServiceImpl implements PermissionService {

    @Autowired
    private PermissionMapper permissionMapper;


    @Override
    public Set<Permission> findPermsByRoleSet(Set<Integer> roleIdSet) {
        return permissionMapper.findPermsByRoleIdIn(roleIdSet);
    }
}
