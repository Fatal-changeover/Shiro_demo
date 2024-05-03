package com.mashibing.config;

import com.mashibing.realm.CasRealm;
import io.buji.pac4j.filter.CallbackFilter;
import io.buji.pac4j.filter.LogoutFilter;
import io.buji.pac4j.filter.SecurityFilter;
import io.buji.pac4j.subject.Pac4jSubjectFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.pac4j.core.config.Config;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.DelegatingFilterProxy;

import javax.servlet.Filter;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author zjw
 * @description
 */
@Configuration
public class ShiroConfig {


    @Value("${cas.server.url:http://localhost:8080/cas}")
    private String casServerUrl;

    @Value("${cas.project.url:http://localhost:81}")
    private String casProjectUrl;

    @Value("${cas.clientName:test}")
    private String clientName;

    /**
     *  主体工厂
     * @return
     */
    @Bean
    public SubjectFactory subjectFactory(){
        return new Pac4jSubjectFactory();
    }

    /**
     * 安全管理器
     * @param casRealm
     * @param subjectFactory
     * @return
     */
    @Bean
    public SecurityManager securityManager(CasRealm casRealm,SubjectFactory subjectFactory){
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(casRealm);
        securityManager.setSubjectFactory(subjectFactory);
        return securityManager;
    }

    /**
     * 配置核心过滤器
     * @return
     */
    @Bean
    public FilterRegistrationBean filterRegistrationBean(){
        FilterRegistrationBean filterRegistration =new FilterRegistrationBean();
        filterRegistration.setFilter(new DelegatingFilterProxy("shiroFilter"));
        filterRegistration.addUrlPatterns("/*");
        return filterRegistration;
    }


    /**
     * shiroFilter核心配置
     * @return
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager, Config config){
        ShiroFilterFactoryBean factoryBean = new ShiroFilterFactoryBean();
        factoryBean.setSecurityManager(securityManager);
        putFilterChain(factoryBean);
        // 后面在声明好pac4j提供的过滤器后
        Map<String, Filter> filters = factoryBean.getFilters();
        //1. 准备SecurityFilter  代替authc 所有认证来这
        SecurityFilter securityFilter = new SecurityFilter();
        //认证需要找cas 所以要配置
        securityFilter.setConfig(config);
        securityFilter.setClients(clientName);
        filters.put("security",securityFilter);

        //2. 设置回调的拦截器    回调到自己的请求地址
        CallbackFilter callbackFilter = new CallbackFilter();
        callbackFilter.setConfig(config);
        callbackFilter.setDefaultUrl(casProjectUrl);
        filters.put("callback",callbackFilter);

        //3. 退出登录
        LogoutFilter logoutFilter = new LogoutFilter();
        logoutFilter.setConfig(config);
        logoutFilter.setCentralLogout(true);
        logoutFilter.setLocalLogout(true);
        logoutFilter.setDefaultUrl(casProjectUrl + "/callback?client_name=" + clientName);
        filters.put("logout",logoutFilter);

        return factoryBean;
    }

    private void putFilterChain(ShiroFilterFactoryBean factoryBean) {
        Map<String,String> filterChain = new LinkedHashMap<>();
        // 后面在声明好pac4j提供的过滤器后，需要重新设置！
        filterChain.put("/test","security");
        filterChain.put("/logout","logout");
        filterChain.put("/callback","callback");
        filterChain.put("/**","security");
        factoryBean.setFilterChainDefinitionMap(filterChain);
    }


}
