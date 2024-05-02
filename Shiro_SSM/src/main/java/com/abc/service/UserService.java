package com.abc.service;

import com.abc.entity.User;

/**
 * ClassName: UserService
 * Package: com.abc.service
 * Description:
 *
 * @Author R
 * @Create 2024/5/1 22:38
 * @Version 1.0
 */
public interface UserService {
    User findByUsername(String username);
}
