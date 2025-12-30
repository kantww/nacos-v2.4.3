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

import com.alibaba.nacos.common.cache.Cache;
import com.alibaba.nacos.common.cache.builder.CacheBuilder;
import com.alibaba.nacos.common.utils.StringUtils;
import com.alibaba.nacos.core.utils.Loggers;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.Callable;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/**
 * Cache for derived password secrets to bypass expensive bcrypt checks on cache hit.
 *
 * @author Codex
 */
public class DerivedSecretCache {
    
    private static final String LOG_PREFIX = "[Derived-Cache] ";
    
    private static final int DEFAULT_TTL_SECONDS = 600;
    
    private static final int DEFAULT_MAX_SIZE = 10240;
    
    private static final int DEFAULT_MAX_PARALLEL_LOADS = 32;
    
    private final Cache<String, String> cache;
    
    private final Semaphore loadSemaphore;
    
    public DerivedSecretCache() {
        CacheBuilder<String, String> builder = CacheBuilder.<String, String>builder().lru(true).sync(true)
                .maximumSize(DEFAULT_MAX_SIZE).initializeCapacity(Math.min(DEFAULT_MAX_SIZE, 1024));
        if (DEFAULT_TTL_SECONDS > 0) {
            builder.expireNanos(DEFAULT_TTL_SECONDS, TimeUnit.SECONDS);
        }
        cache = builder.build();
        loadSemaphore = DEFAULT_MAX_PARALLEL_LOADS > 0 ? new Semaphore(DEFAULT_MAX_PARALLEL_LOADS) : null;
        if (Loggers.AUTH.isInfoEnabled()) {
            Loggers.AUTH.info("{}enabled=true, ttlSeconds={}, maxSize={}, maxParallelLoads={}", LOG_PREFIX,
                    DEFAULT_TTL_SECONDS, DEFAULT_MAX_SIZE, DEFAULT_MAX_PARALLEL_LOADS);
        }
    }
    
    /**
     * Match password with derived cache. On cache miss, delegate to loader (usually bcrypt) and backfill cache.
     *
     * @param username      username
     * @param rawPassword     raw password
     * @param encodedPassword encoded password used as salt to build derived one
     * @param passwordCheck   loader to validate raw password against encoded one
     * @return true if password is valid
     * @throws Exception loader exception
     */
    public boolean match(String username, String rawPassword, String encodedPassword,
            Callable<Boolean> passwordCheck) throws Exception {
        if (StringUtils.isBlank(username) || rawPassword == null) {
            return false;
        }
        String cacheKey = buildCacheKey(username);
        String requestDerived = derive(encodedPassword, username, rawPassword);
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
        cache.remove(buildCacheKey(username));
    }
    
    /**
     * Clear all cache entries.
     */
    public void clear() {
        cache.clear();
    }
    
    private String buildCacheKey(String username) {
        return username;
    }
    
    private String derive(String encodedPassword, String username, String rawPassword) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String salt = encodedPassword == null ? "" : encodedPassword;
            digest.update(salt.getBytes(StandardCharsets.UTF_8));
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
    
}
