package com.abc.mapper;

import com.abc.entity.User;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

/**
 * ClassName: UserMapper
 * Package: com.abc.mapper
 * Description:
 *
 * @Author R
 * @Create 2024/5/1 22:36
 * @Version 1.0
 */
public interface UserMapper {
    @Select("select * from user where username = #{username}")
    User findUserByUsername(@Param("username") String username);
}
