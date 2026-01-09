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

package com.alibaba.nacos.plugin.auth.impl.utils;

import com.alibaba.nacos.common.utils.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utility to generate and verify derived password with lightweight hash.
 * Derived value is calculated from username and raw password, using stored password as the salt.
 *
 * @author lkw
 */
public final class DerivedPasswordUtil {
    
    private static final String ALGORITHM = "SHA-256";
    
    private DerivedPasswordUtil() {
    }
    
    /**
     * Generate derived password using stored password as salt.
     *
     * @param username      username
     * @param rawPassword   raw password provided by client
     * @param passwordSalt  stored password (bcrypt) used as salt
     * @return derived password hex string, null if any input blank
     * @throws IllegalStateException if digest algorithm is unavailable
     */
    public static String derive(String username, String rawPassword, String passwordSalt) throws IllegalStateException {
        if (StringUtils.isAnyBlank(username, rawPassword, passwordSalt)) {
            return null;
        }
        try {
            MessageDigest digest = MessageDigest.getInstance(ALGORITHM);
            byte[] first = digest.digest((username + ':' + rawPassword).getBytes(StandardCharsets.UTF_8));
            digest.reset();
            digest.update(passwordSalt.getBytes(StandardCharsets.UTF_8));
            byte[] finalBytes = digest.digest(first);
            return toHex(finalBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unable to derive password", e);
        }
    }
    
    /**
     * Verify raw password against derived password using stored password as salt.
     *
     * @param username         username
     * @param rawPassword      raw password provided by client
     * @param passwordSalt     stored password (bcrypt) used as salt
     * @param derivedPassword  stored derived password
     * @return true if matches
     */
    public static boolean matches(String username, String rawPassword, String passwordSalt, String derivedPassword) {
        if (StringUtils.isBlank(derivedPassword)) {
            return false;
        }
        String candidate = derive(username, rawPassword, passwordSalt);
        return StringUtils.equals(derivedPassword, candidate);
    }

    /**
     * Convert byte array to lowercase hexadecimal string.
     *
     * @param bytes bytes to convert
     * @return lowercase hex string
     */
    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            // convert to unsigned int
            int v = b & 0xFF;
            // high 4 bits to hex
            sb.append(Character.forDigit(v >>> 4, 16));
            // low 4 bits to hex
            sb.append(Character.forDigit(v & 0x0F, 16));
        }
        return sb.toString();
    }
}
