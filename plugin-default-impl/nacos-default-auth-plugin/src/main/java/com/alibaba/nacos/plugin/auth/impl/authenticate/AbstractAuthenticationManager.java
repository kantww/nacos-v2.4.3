/*
 * Copyright 1999-2022 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.alibaba.nacos.plugin.auth.impl.authenticate;

import com.alibaba.nacos.api.common.Constants;
import com.alibaba.nacos.common.utils.StringUtils;
import com.alibaba.nacos.core.utils.Loggers;
import com.alibaba.nacos.plugin.auth.api.Permission;
import com.alibaba.nacos.plugin.auth.exception.AccessException;
import com.alibaba.nacos.plugin.auth.impl.constant.AuthConstants;
import com.alibaba.nacos.plugin.auth.impl.cache.DerivedSecretCache;
import com.alibaba.nacos.plugin.auth.impl.roles.NacosRoleServiceImpl;
import com.alibaba.nacos.plugin.auth.impl.token.TokenManagerDelegate;
import com.alibaba.nacos.plugin.auth.impl.users.NacosUser;
import com.alibaba.nacos.plugin.auth.impl.users.NacosUserDetails;
import com.alibaba.nacos.plugin.auth.impl.users.NacosUserDetailsServiceImpl;
import com.alibaba.nacos.plugin.auth.impl.utils.PasswordEncoderUtil;
import com.alibaba.nacos.plugin.auth.impl.persistence.User;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * AbstractAuthenticationManager.
 *
 * @author Weizhan▪Yun
 * @date 2023/1/13 12:48
 */
public class AbstractAuthenticationManager implements IAuthenticationManager {
    
    protected NacosUserDetailsServiceImpl userDetailsService;
    
    protected TokenManagerDelegate jwtTokenManager;
    
    protected NacosRoleServiceImpl roleService;
    
    protected DerivedSecretCache derivedSecretCache;
     
    public AbstractAuthenticationManager(NacosUserDetailsServiceImpl userDetailsService,
            TokenManagerDelegate jwtTokenManager, NacosRoleServiceImpl roleService) {
        this(userDetailsService, jwtTokenManager, roleService, null);
    }
    
    public AbstractAuthenticationManager(NacosUserDetailsServiceImpl userDetailsService,
            TokenManagerDelegate jwtTokenManager, NacosRoleServiceImpl roleService,
            DerivedSecretCache derivedSecretCache) {
        this.userDetailsService = userDetailsService;
        this.jwtTokenManager = jwtTokenManager;
        this.roleService = roleService;
        this.derivedSecretCache = derivedSecretCache;
    }

    @Override
    public NacosUser authenticate(String username, String rawPassword) throws AccessException {
        if (StringUtils.isBlank(username) || StringUtils.isBlank(rawPassword)) {
            throw new AccessException("user not found!");
        }
        NacosUserDetails nacosUserDetails = (NacosUserDetails) userDetailsService.loadUserByUsername(username);
        if (nacosUserDetails == null) {
            throw new AccessException("user not found!");
        }
        if (!matchesDerivedFirst(nacosUserDetails, rawPassword)) {
            throw new AccessException("user not found!");
        }
        return new NacosUser(nacosUserDetails.getUsername(), jwtTokenManager.createToken(username));
    }
    
    @Override
    public NacosUser authenticate(String token) throws AccessException {
        if (StringUtils.isBlank(token)) {
            throw new AccessException("user not found!");
        }
        return jwtTokenManager.parseToken(token);
    }
    
    @Override
    public NacosUser authenticate(HttpServletRequest httpServletRequest) throws AccessException {
        String token = resolveToken(httpServletRequest);
        
        NacosUser user;
        if (StringUtils.isNotBlank(token)) {
            user = authenticate(token);
        } else {
            String userName = httpServletRequest.getParameter(AuthConstants.PARAM_USERNAME);
            String password = httpServletRequest.getParameter(AuthConstants.PARAM_PASSWORD);
            user = authenticate(userName, password);
        }
        
        return user;
    }
    
    @Override
    public void authorize(Permission permission, NacosUser nacosUser) throws AccessException {
        if (Loggers.AUTH.isDebugEnabled()) {
            Loggers.AUTH.debug("auth permission: {}, nacosUser: {}", permission, nacosUser);
        }
        if (nacosUser.isGlobalAdmin()) {
            return;
        }
        if (hasGlobalAdminRole(nacosUser)) {
            return;
        }
        
        if (!roleService.hasPermission(nacosUser, permission)) {
            throw new AccessException("authorization failed!");
        }
    }
    
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AuthConstants.AUTHORIZATION_HEADER);
        if (StringUtils.isNotBlank(bearerToken) && bearerToken.startsWith(AuthConstants.TOKEN_PREFIX)) {
            return bearerToken.substring(AuthConstants.TOKEN_PREFIX.length());
        }
        bearerToken = request.getParameter(Constants.ACCESS_TOKEN);
        
        return bearerToken;
    }
    
    @Override
    public boolean hasGlobalAdminRole(String username) {
        return roleService.hasGlobalAdminRole(username);
    }
    
    @Override
    public boolean hasGlobalAdminRole() {
        return roleService.hasGlobalAdminRole();
    }
    
    @Override
    public boolean hasGlobalAdminRole(NacosUser nacosUser) {
        if (nacosUser.isGlobalAdmin()) {
            return true;
        }
        nacosUser.setGlobalAdmin(hasGlobalAdminRole(nacosUser.getUserName()));
        return nacosUser.isGlobalAdmin();
    }
    
    private boolean matchesDerivedFirst(NacosUserDetails nacosUserDetails, String rawPassword) {
        String username = nacosUserDetails.getUsername();
        String derivedPassword = nacosUserDetails.getDerivedPassword();
        if (StringUtils.isNotBlank(derivedPassword)) {
            String computed = computeDerivedPassword(nacosUserDetails, rawPassword);
            if (!derivedPassword.equals(computed)) {
                return false;
            }
            return true;
        }
        return matchesWithCache(username, rawPassword, nacosUserDetails.getPassword(), nacosUserDetails);
    }
    
    private boolean matchesWithCache(String username, String rawPassword, String encodedPassword,
            NacosUserDetails nacosUserDetails) {
        try {
            if (derivedSecretCache == null) {
                return handleBcryptAndFillDerived(nacosUserDetails, rawPassword, encodedPassword);
            }
            return derivedSecretCache.match(username, rawPassword, encodedPassword,
                    () -> handleBcryptAndFillDerived(nacosUserDetails, rawPassword, encodedPassword));
        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            Loggers.AUTH.warn("[Derived-Cache] password match fallback for user {}", username, e);
            return handleBcryptAndFillDerived(nacosUserDetails, rawPassword, encodedPassword);
        }
    }
    
    private boolean handleBcryptAndFillDerived(NacosUserDetails nacosUserDetails, String rawPassword,
            String encodedPassword) {
        boolean matched = PasswordEncoderUtil.matches(rawPassword, encodedPassword);
        if (matched && derivedSecretCache != null) {
            String derived = computeDerivedPassword(nacosUserDetails, rawPassword);
            nacosUserDetails.setDerivedPassword(derived);
            User user = nacosUserDetails.getUser();
            if (user != null) {
                user.setDerivedPassword(derived);
            }
        }
        return matched;
    }
    
    private String computeDerivedPassword(NacosUserDetails userDetails, String rawPassword) {
        String nodeSalt = userDetails.getPassword();
        if (nodeSalt == null) {
            nodeSalt = "";
        }
        String username = userDetails.getUsername();
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(nodeSalt.getBytes(StandardCharsets.UTF_8));
            digest.update(username.getBytes(StandardCharsets.UTF_8));
            byte[] hash = digest.digest(rawPassword.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
