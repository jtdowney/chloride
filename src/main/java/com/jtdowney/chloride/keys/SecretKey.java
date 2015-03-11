/*
 * Copyright (c) 2015 John Downey
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.jtdowney.chloride.keys;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Secret key for encryption with {@link com.jtdowney.chloride.boxes.SecretBox}
 */
public class SecretKey {
    private byte[] key;

    /**
     * Generate a new 32 byte (256 bit) secret key
     * @return a secret key
     */
    public static SecretKey generate() {
        byte[] key = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(key);
        return new SecretKey(key);
    }

    /**
     * Create a secret key from 32 byte (256 bit) key material
     * @param key a secret key
     */
    public SecretKey(byte[] key) {
        assert key.length == 32;
        this.key = key.clone();
    }

    /**
     * Retrieve the raw key material
     * @return the 32 byte (256 bit) key material
     */
    public byte[] getBytes() {
        return key.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        SecretKey that = (SecretKey) o;

        return Arrays.equals(key, that.key);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(key);
    }
}
