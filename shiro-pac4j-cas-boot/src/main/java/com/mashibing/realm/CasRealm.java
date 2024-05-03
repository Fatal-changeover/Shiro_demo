package com.mashibing.realm;

import io.buji.pac4j.realm.Pac4jRealm;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.stereotype.Component;

/**
 * @author zjw
 * @description
 */
@Component
public class CasRealm extends Pac4jRealm {


    /**
     * 授权操作，需要自己编写，并且也可以基于RedisSessionDAO实现缓存……
     * @param principals
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // do something , find DB or Cache
        return null;
    }
}
