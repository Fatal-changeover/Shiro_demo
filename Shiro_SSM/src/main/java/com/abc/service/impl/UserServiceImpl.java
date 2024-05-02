package com.abc.service.impl;

import com.abc.entity.User;
import com.abc.mapper.UserMapper;
import com.abc.service.UserService;
import org.apache.ibatis.annotations.Select;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.awt.print.PrinterAbortException;
import java.util.function.UnaryOperator;

/**
 * ClassName: UserServiceImpl
 * Package: com.abc.service.impl
 * Description:
 *
 * @Author R
 * @Create 2024/5/1 22:39
 * @Version 1.0
 */
@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserMapper userMapper;

    @Override
    public User findByUsername(String username) {
        return userMapper.findUserByUsername(username);
    }
}
