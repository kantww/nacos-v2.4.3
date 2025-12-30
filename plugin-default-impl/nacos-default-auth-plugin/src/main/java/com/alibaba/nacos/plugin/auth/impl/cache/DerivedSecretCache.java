/*
 * Copyright 1999-2025 Alibaba Group Holding Ltd.
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

package com.alibaba.nacos.plugin.auth.impl.cache;

import com.alibaba.nacos.auth.config.AuthConfigs;
import com.alibaba.nacos.common.cache.Cache;
import com.alibaba.nacos.common.cache.builder.CacheBuilder;
import com.alibaba.nacos.common.utils.StringUtils;
import com.alibaba.nacos.core.utils.Loggers;
import com.alibaba.nacos.plugin.auth.constant.Constants;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Cache for derived password secrets to bypass expensive bcrypt checks on cache hit.
 *
 * @author Codex
 */
public class DerivedSecretCache {
    
    private static final String LOG_PREFIX = "[Derived-Cache] ";
    
    private final AuthConfigs authConfigs;
    
    private final Object refreshLock = new Object();
    
    private final AtomicReference<CacheSettings> settingsRef = new AtomicReference<>();
    
    private volatile Cache<String, String> cache;
    
    private volatile Semaphore loadSemaphore;
    
    private volatile String generatedNodeSalt;
    
    public DerivedSecretCache(AuthConfigs authConfigs) {
        this.authConfigs = authConfigs;
        refreshIfNecessary();
    }
    
    /**
     * Match password with derived cache. On cache miss, delegate to loader (usually bcrypt) and backfill cache.
     *
     * @param username      username
     * @param rawPassword   raw password
     * @param passwordCheck loader to validate raw password against encoded one
     * @return true if password is valid
     * @throws Exception loader exception
     */
    public boolean match(String username, String rawPassword, Callable<Boolean> passwordCheck) throws Exception {
        CacheSettings settings = refreshIfNecessary();
        if (StringUtils.isBlank(username) || rawPassword == null) {
            return false;
        }
        if (!settings.enabled) {
            return passwordCheck.call();
        }
        String cacheKey = buildCacheKey(username);
        String requestDerived = derive(settings.nodeSalt, username, rawPassword);
        String cached = cache.get(cacheKey);
        if (requestDerived.equals(cached)) {
            return true;
        }
        Semaphore semaphore = loadSemaphore;
        boolean acquired = false;
        if (semaphore != null) {
            semaphore.acquire();
            acquired = true;
        }
        try {
            cached = cache.get(cacheKey);
            if (requestDerived.equals(cached)) {
                return true;
            }
            boolean matched = Boolean.TRUE.equals(passwordCheck.call());
            if (matched) {
                cache.put(cacheKey, requestDerived);
            }
            return matched;
        } finally {
            if (acquired) {
                semaphore.release();
            }
        }
    }
    
    /**
     * Invalidate cache entry for username.
     *
     * @param username target username
     */
    public void invalidate(String username) {
        if (StringUtils.isBlank(username)) {
            return;
        }
        refreshIfNecessary();
        cache.remove(buildCacheKey(username));
    }
    
    /**
     * Clear all cache entries.
     */
    public void clear() {
        Cache<String, String> current = cache;
        if (current != null) {
            current.clear();
        }
    }
    
    private CacheSettings refreshIfNecessary() {
        CacheSettings latest = buildSettings();
        CacheSettings current = settingsRef.get();
        if (!latest.equals(current) || cache == null) {
            synchronized (refreshLock) {
                current = settingsRef.get();
                if (!latest.equals(current) || cache == null) {
                    rebuild(latest);
                }
            }
        }
        return settingsRef.get();
    }
    
    private void rebuild(CacheSettings settings) {
        CacheBuilder<String, String> builder = CacheBuilder.<String, String>builder().lru(true).sync(true)
                .maximumSize(settings.maxSize).initializeCapacity(Math.min(settings.maxSize, 1024));
        if (settings.ttlSeconds > 0) {
            builder.expireNanos(settings.ttlSeconds, TimeUnit.SECONDS);
        }
        cache = builder.build();
        loadSemaphore = settings.maxParallelLoads > 0 ? new Semaphore(settings.maxParallelLoads) : null;
        settingsRef.set(settings);
        if (Loggers.AUTH.isInfoEnabled()) {
            Loggers.AUTH.info("{}enabled={}, ttlSeconds={}, maxSize={}, maxParallelLoads={}", LOG_PREFIX,
                    settings.enabled, settings.ttlSeconds, settings.maxSize, settings.maxParallelLoads);
        }
    }
    
    private CacheSettings buildSettings() {
        CacheSettings settings = new CacheSettings();
        settings.enabled = authConfigs.isDerivedSecretCacheEnabled();
        settings.ttlSeconds = authConfigs.getDerivedSecretCacheTtlSeconds();
        settings.maxSize = authConfigs.getDerivedSecretCacheMaxSize();
        settings.maxParallelLoads = authConfigs.getDerivedSecretCacheMaxParallelLoads();
        String nodeSalt = authConfigs.getDerivedSecretCacheNodeSalt();
        if (StringUtils.isBlank(nodeSalt)) {
            if (StringUtils.isBlank(generatedNodeSalt)) {
                generatedNodeSalt = UUID.randomUUID().toString();
                Loggers.AUTH.warn("{}node salt not set, generated temporary salt. Configure {} to persist it.",
                        LOG_PREFIX, Constants.Auth.NACOS_CORE_AUTH_DERIVED_CACHE_NODE_SALT);
            }
            nodeSalt = generatedNodeSalt;
        }
        settings.nodeSalt = nodeSalt;
        return settings;
    }
    
    private String buildCacheKey(String username) {
        return username;
    }
    
    private String derive(String nodeSalt, String username, String rawPassword) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(nodeSalt.getBytes(StandardCharsets.UTF_8));
            digest.update(username.getBytes(StandardCharsets.UTF_8));
            byte[] hashed = digest.digest(rawPassword.getBytes(StandardCharsets.UTF_8));
            return toHex(hashed);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
    
    private String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    private static final class CacheSettings {
        
        private boolean enabled;
        
        private long ttlSeconds;
        
        private int maxSize;
        
        private String nodeSalt;
        
        private int maxParallelLoads;
        
        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof CacheSettings)) {
                return false;
            }
            CacheSettings that = (CacheSettings) o;
            return enabled == that.enabled && ttlSeconds == that.ttlSeconds && maxSize == that.maxSize
                    && maxParallelLoads == that.maxParallelLoads && Objects.equals(nodeSalt, that.nodeSalt);
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(enabled, ttlSeconds, maxSize, nodeSalt, maxParallelLoads);
        }
    }
}
