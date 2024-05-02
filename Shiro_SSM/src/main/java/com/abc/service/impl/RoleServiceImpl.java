package com.abc.service.impl;


import com.abc.entity.Role;
import com.abc.mapper.RoleMapper;
import com.abc.service.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Set;

/**
 * @author zjw
 * @description
 */
@Service
public class RoleServiceImpl implements RoleService {

    @Autowired
    private RoleMapper roleMapper;


    @Override
    public Set<Role> findRolesByUid(Integer uid) {
        return roleMapper.findRolesByUid(uid);
    }
}
