package com.alibaba.nacos.plugin.auth.derived.cache;

import com.alibaba.nacos.common.utils.StringUtils;
import com.alibaba.nacos.core.utils.Loggers;
import com.alibaba.nacos.sys.env.EnvUtil;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.slf4j.Logger;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Cache service for derived password hashes.
 */
public class DerivedSecretCacheService {
    
    private static final Logger LOGGER = Loggers.AUTH;
    
    private static final String ENABLED_KEY = "nacos.core.auth.derived.cache.enabled";
    
    private static final String TTL_KEY = "nacos.core.auth.derived.cache.ttl-seconds";
    
    private static final String MAX_SIZE_KEY = "nacos.core.auth.derived.cache.max-size";
    
    private static final String NODE_SALT_KEY = "nacos.core.auth.derived.cache.node-salt";
    
    private static final long DEFAULT_TTL_SECONDS = 300L;
    
    private static final long DEFAULT_MAX_SIZE = 10_000L;
    
    private final boolean enabled;
    
    private final Cache<String, String> cache;
    
    private final String nodeSalt;
    
    public DerivedSecretCacheService() {
        this.enabled = EnvUtil.getProperty(ENABLED_KEY, Boolean.class, Boolean.TRUE);
        long ttlSeconds = EnvUtil.getProperty(TTL_KEY, Long.class, DEFAULT_TTL_SECONDS);
        if (ttlSeconds <= 0) {
            ttlSeconds = DEFAULT_TTL_SECONDS;
        }
        long maxSize = EnvUtil.getProperty(MAX_SIZE_KEY, Long.class, DEFAULT_MAX_SIZE);
        if (maxSize <= 0) {
            maxSize = DEFAULT_MAX_SIZE;
        }
        String configuredSalt = EnvUtil.getProperty(NODE_SALT_KEY, String.class, "");
        if (StringUtils.isBlank(configuredSalt)) {
            configuredSalt = UUID.randomUUID().toString();
            LOGGER.warn("[Derived-Cache] node-salt not configured, generated ephemeral salt {}", configuredSalt);
        }
        this.nodeSalt = configuredSalt;
        if (enabled) {
            this.cache = Caffeine.newBuilder().expireAfterWrite(ttlSeconds, TimeUnit.SECONDS).maximumSize(maxSize)
                    .recordStats().build();
            LOGGER.info("[Derived-Cache] enabled ttl={}s maxSize={} saltConfigured={}", ttlSeconds, maxSize,
                    !StringUtils.isBlank(EnvUtil.getProperty(NODE_SALT_KEY)));
        } else {
            this.cache = null;
            LOGGER.info("[Derived-Cache] disabled via property {}", ENABLED_KEY);
        }
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public boolean quickMatch(String username, String rawPassword) {
        if (!enabled) {
            return false;
        }
        String cached = cache.getIfPresent(key(username));
        if (cached == null) {
            return false;
        }
        boolean matched = cached.equals(derive(username, rawPassword));
        if (matched && LOGGER.isInfoEnabled()) {
            LOGGER.info("[Derived-Cache] cache hit, skip bcrypt for user {}", mask(username));
        }
        return matched;
    }
    
    public void cache(String username, String rawPassword) {
        if (!enabled) {
            return;
        }
        cache.put(key(username), derive(username, rawPassword));
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("[Derived-Cache] cache populated for user {}", mask(username));
        }
    }
    
    private String key(String username) {
        return username == null ? "" : username;
    }
    
    private String derive(String username, String rawPassword) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(nodeSalt.getBytes(StandardCharsets.UTF_8));
            digest.update((username == null ? "" : username).getBytes(StandardCharsets.UTF_8));
            digest.update(rawPassword.getBytes(StandardCharsets.UTF_8));
            byte[] hash = digest.digest();
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not supported", e);
        }
    }
    
    private String mask(String username) {
        if (StringUtils.isBlank(username)) {
            return "<empty>";
        }
        if (username.length() <= 2) {
            return username.charAt(0) + "*";
        }
        return username.charAt(0) + "***" + username.charAt(username.length() - 1);
    }
}
