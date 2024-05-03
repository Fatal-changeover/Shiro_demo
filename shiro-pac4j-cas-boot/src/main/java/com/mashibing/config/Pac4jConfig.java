package com.mashibing.config;

import com.mashibing.pac4j.CasClient;
import org.pac4j.cas.config.CasConfiguration;
import org.pac4j.cas.config.CasProtocol;
import org.pac4j.core.config.Config;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author zjw
 * @description
 */
@Configuration
public class Pac4jConfig {

    @Value("${cas.server.url:http://localhost:8080/cas}")
    private String casServerUrl;

    @Value("${cas.project.url:http://localhost:81}")
    private String casProjectUrl;

    @Value("${cas.clientName:test}")
    private String clientName;

    /**
     * 核心Config
     * @param casClient
     * @return
     */
    @Bean
    public Config config(CasClient casClient){
        Config config = new Config(casClient);
        return config;
    }

    /**
     * casClient，主要设置回调
     * @param casConfiguration
     * @return
     */
    @Bean
    public CasClient casClient(CasConfiguration casConfiguration){
        CasClient casClient = new CasClient(casConfiguration);
        // 设置CAS访问后的回调地址  自己项目的地址
        casClient.setCallbackUrl(casProjectUrl + "/callback?client_name=" + clientName);
        casClient.setName(clientName);
        return casClient;
    }

    /**
     * CAS服务地址
     * @return
     */
    @Bean
    public CasConfiguration casConfiguration(){
        CasConfiguration casConfiguration = new CasConfiguration();
        // 设置CAS登录页面
        casConfiguration.setLoginUrl(casServerUrl + "/login");
        // 设置CAS协议
        casConfiguration.setProtocol(CasProtocol.CAS20);
        casConfiguration.setPrefixUrl(casServerUrl + "/");
        casConfiguration.setAcceptAnyProxy(true);
        return casConfiguration;
    }

}
