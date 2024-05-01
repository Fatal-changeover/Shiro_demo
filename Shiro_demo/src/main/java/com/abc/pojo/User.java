package com.abc.pojo;

/**
 * ClassName: User
 * Package: com.abc.pojo
 * Description:
 *
 * @Author R
 * @Create 2024/5/1 14:15
 * @Version 1.0
 */
public class User {
    private Integer id;
    private String username;
    private String password;

    private String salt;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }
}
