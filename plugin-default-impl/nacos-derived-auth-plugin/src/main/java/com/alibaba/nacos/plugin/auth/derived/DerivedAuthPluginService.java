package com.alibaba.nacos.plugin.auth.derived;

import com.alibaba.nacos.api.common.Constants;
import com.alibaba.nacos.common.utils.StringUtils;
import com.alibaba.nacos.core.utils.Loggers;
import com.alibaba.nacos.plugin.auth.api.IdentityContext;
import com.alibaba.nacos.plugin.auth.api.Permission;
import com.alibaba.nacos.plugin.auth.api.Resource;
import com.alibaba.nacos.plugin.auth.constant.ActionTypes;
import com.alibaba.nacos.plugin.auth.constant.Constants.Identity;
import com.alibaba.nacos.plugin.auth.derived.cache.DerivedSecretCacheService;
import com.alibaba.nacos.plugin.auth.exception.AccessException;
import com.alibaba.nacos.plugin.auth.impl.NacosAuthPluginService;
import com.alibaba.nacos.plugin.auth.impl.constant.AuthConstants;
import com.alibaba.nacos.plugin.auth.impl.persistence.User;
import com.alibaba.nacos.plugin.auth.impl.persistence.UserPersistService;
import com.alibaba.nacos.plugin.auth.impl.roles.NacosRoleServiceImpl;
import com.alibaba.nacos.plugin.auth.impl.token.TokenManagerDelegate;
import com.alibaba.nacos.plugin.auth.impl.users.NacosUser;
import com.alibaba.nacos.plugin.auth.impl.utils.PasswordEncoderUtil;
import com.alibaba.nacos.plugin.auth.spi.server.AuthPluginService;
import com.alibaba.nacos.sys.utils.ApplicationUtils;
import org.slf4j.Logger;

import java.util.Collection;
import java.util.Locale;

/**
 * Derived auth plugin service that wraps default plugin and adds local cache.
 */
public class DerivedAuthPluginService implements AuthPluginService {
    
    public static final String DERIVED_AUTH_TYPE = "derived";
    
    private static final Logger LOGGER = Loggers.AUTH;
    
    private final NacosAuthPluginService delegate = new NacosAuthPluginService();
    
    private final DerivedSecretCacheService cacheService = new DerivedSecretCacheService();
    
    @Override
    public Collection<String> identityNames() {
        return delegate.identityNames();
    }
    
    @Override
    public boolean enableAuth(ActionTypes action, String type) {
        return delegate.enableAuth(action, type);
    }
    
    @Override
    public boolean validateIdentity(IdentityContext identityContext, Resource resource) throws AccessException {
        if (!cacheService.isEnabled()) {
            return delegate.validateIdentity(identityContext, resource);
        }
        String token = resolveToken(identityContext);
        if (StringUtils.isNotBlank(token)) {
            return delegate.validateIdentity(identityContext, resource);
        }
        String username = (String) identityContext.getParameter(AuthConstants.PARAM_USERNAME);
        String password = (String) identityContext.getParameter(AuthConstants.PARAM_PASSWORD);
        if (StringUtils.isAnyBlank(username, password)) {
            return delegate.validateIdentity(identityContext, resource);
        }
        boolean cacheHit = cacheService.quickMatch(username, password);
        boolean verified = cacheHit || verifyWithBcrypt(username, password);
        if (verified) {
            if (!cacheHit) {
                cacheService.cache(username, password);
            }
            NacosUser nacosUser = buildUser(username);
            identityContext.setParameter(AuthConstants.NACOS_USER_KEY, nacosUser);
            identityContext.setParameter(Identity.IDENTITY_ID, nacosUser.getUserName());
            return true;
        }
        throw new AccessException("user not found!");
    }
    
    @Override
    public Boolean validateAuthority(IdentityContext identityContext, Permission permission) throws AccessException {
        return delegate.validateAuthority(identityContext, permission);
    }
    
    @Override
    public String getAuthServiceName() {
        return DERIVED_AUTH_TYPE;
    }
    
    @Override
    public boolean isLoginEnabled() {
        return delegate.isLoginEnabled();
    }
    
    @Override
    public boolean isAdminRequest() {
        return delegate.isAdminRequest();
    }
    
    private String resolveToken(IdentityContext identityContext) {
        String bearer = identityContext.getParameter(AuthConstants.AUTHORIZATION_HEADER, StringUtils.EMPTY);
        if (StringUtils.isNotBlank(bearer)) {
            if (bearer.startsWith(AuthConstants.TOKEN_PREFIX)) {
                return bearer.substring(AuthConstants.TOKEN_PREFIX.length());
            }
            return bearer;
        }
        return identityContext.getParameter(Constants.ACCESS_TOKEN, StringUtils.EMPTY);
    }
    
    private boolean verifyWithBcrypt(String username, String rawPassword) {
        UserPersistService userPersistService = ApplicationUtils.getBean(UserPersistService.class);
        User user = userPersistService.findUserByUsername(username);
        if (user == null) {
            LOGGER.warn("[Derived-Auth] user {} not found in DB", username);
            return false;
        }
        return PasswordEncoderUtil.matches(rawPassword, user.getPassword());
    }
    
    private NacosUser buildUser(String username) throws AccessException {
        TokenManagerDelegate tokenManager = ApplicationUtils.getBean(TokenManagerDelegate.class);
        String token = tokenManager.createToken(username);
        NacosUser nacosUser = new NacosUser(username, token);
        NacosRoleServiceImpl roleService = ApplicationUtils.getBean(NacosRoleServiceImpl.class);
        nacosUser.setGlobalAdmin(roleService.hasGlobalAdminRole(username));
        return nacosUser;
    }
}
