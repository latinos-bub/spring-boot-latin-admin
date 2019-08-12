package com.latin.admin.shiro;

import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;

import javax.servlet.Filter;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author: util.you.com@gmail.com
 * @date: 2019/7/29 16:20
 * @description: Shiro 配置类
 * @version: 1.0
 * @className: ShiroConfiguration
 */
@Configuration
public class ShiroConfiguration {



    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: org.apache.shiro.mgt.SecurityManager
     * @date: 2019/7/29 17:10
     * @version: 1.0
     * @description: 安全管理器
     */
    @Bean
    public DefaultWebSecurityManager securityManager(){

        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(userRealm());
        return securityManager;
    }







    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: com.latin.admin.shiro.UserRealm
     * @date: 2019/7/29 17:12
     * @version: 1.0
     * @description: 自定义 realm
     * 即指定 Shiro 验证用户登录的类为自定义的
     */
    @Bean
    public UserRealm userRealm(){

        UserRealm userRealm = new UserRealm();
        userRealm.setCredentialsMatcher(hashedCredentialsMatcher());
        return userRealm;
    }







    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: org.apache.shiro.authc.credential.HashedCredentialsMatcher
     * @date: 2019/7/29 17:20
     * @version: 1.0
     * @description: 凭证匹配器
     *  ps: 由于我们的密码校验交给 Shiro 的 SimpleAuthenticationInfo 进行处理了
     *  所以我们需要修改下 doGetAuthenticationInfo 中的代码
     *
     *  可以扩展凭证匹配器，实现 输入密码错误次数后锁定等功能
     */
    @Bean(name = "credentialsMatcher")
    public HashedCredentialsMatcher hashedCredentialsMatcher(){

        HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
        // 散列算法：这里使用 MD5 算法
        hashedCredentialsMatcher.setHashAlgorithmName("md5");
//         散列的次数，比如散列两次，相当于 MD5(MD5());
        hashedCredentialsMatcher.setHashIterations(1);
        // storedCredentialsHexEncoded 默认是 true，此时的密码用 Hex 编码；false 时用 Base64 编码
        hashedCredentialsMatcher.setStoredCredentialsHexEncoded(true);
        return hashedCredentialsMatcher;
    }







    /**
     * @author: util.you.com@gmail.com
     * @param: [securityManager]
     * @return: org.apache.shiro.spring.web.ShiroFilterFactoryBean
     * @date: 2019/7/29 17:08
     * @version: 1.0
     * @description: 设置过滤规则
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager){

        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        // Shiro 的核心安全接口，这个属性是必须的
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        shiroFilterFactoryBean.setLoginUrl("/login/auth");
        shiroFilterFactoryBean.setSuccessUrl("/");
        shiroFilterFactoryBean.setUnauthorizedUrl("/unauth");

//        Map<String, Filter> filterMap = new LinkedHashMap<>();
//        filterMap.put("authc", new AjaxPermissionsAuthorizationFilter());
//        shiroFilterFactoryBean.setFilters(filterMap);
        /**
         * 定义 shiro 过滤链 Map 结构
         * Map 中 key(xml 中是指 value 值) 的第一个 '/' 代表的路径是相对于 HttpServletRequest.getContextPath（）的值来的
         * anon: 它对应的过滤器里面是空的，什么都没做，这里 .do 和 .jsp 后面的 * 表示参数，比方说 login.jsp?main 这种
         * authc: 该过滤器下的页面必须验证后才能访问，它是 Shiro 内置的一个拦截器
         *      org.apache.shiro.web.filter.authc.FormAuthenticationFilter
         */
        Map<String, String> filterChainDefinitionMap = new LinkedHashMap<>();   // 注意此处使用的是 LinkedHashMap,是有顺序的
        /**
         * 过滤链定义，从上向下顺序执行，一般将 / ** 放在最下面
         * authc: 所有 url 都必须认证通过才可以访问;
         * anon: 所有 url 都可以匿名访问
         */
        filterChainDefinitionMap.put("/", "anon");
        filterChainDefinitionMap.put("/static/**", "anon");
        filterChainDefinitionMap.put("/login/auth", "anon");
        filterChainDefinitionMap.put("/login/logout", "anon");
        filterChainDefinitionMap.put("/error", "anon");
        filterChainDefinitionMap.put("/**", "authc");

        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return shiroFilterFactoryBean;
    }








    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: org.apache.shiro.spring.LifecycleBeanPostProcessor
     * @date: 2019/7/29 17:23
     * @version: 1.0
     * @description: Shiro 生命周期处理器
     */
    @Bean
    public LifecycleBeanPostProcessor lifecycleBeanPostProcessor(){

        return new LifecycleBeanPostProcessor();
    }







    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator
     * @date: 2019/7/29 17:26
     * @version: 1.0
     * @description:
     *  开启 Shiro 的注解（如 @RequiresRoles, @RequiresPermissions），需要
     *  借助 SpringAop 扫描使用 Shiro 注解的类，并在必要时进行安全逻辑验证。
     *  配置以下两个 bean(DefaultAdvisorAutoProxyCreator(可选) 和 AuthorizationAttributeSourceAdvisor) 即可实现此功能
     */
    @Bean
    @DependsOn("lifecycleBeanPostProcessor")
    public DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator(){

        DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
        advisorAutoProxyCreator.setProxyTargetClass(true);
        return advisorAutoProxyCreator;
    }







    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(){

        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor =
                new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager());
        return authorizationAttributeSourceAdvisor;
    }

}
