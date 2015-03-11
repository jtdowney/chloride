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

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Asymmetric private key
 */
public class PrivateKey {
    private java.security.PrivateKey privateKey;

    PrivateKey(java.security.PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * Create a private key from DER encoded data
     * @param data the DER encoded data
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public PrivateKey(byte[] data) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("ECDH");
        this.privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(data));
    }

    /**
     * Retrieve underlying private key
     * @return the private key
     */
    public java.security.PrivateKey getKey() {
        return privateKey;
    }

    /**
     * Retrieve DER encoded form of the key
     * @return the DER encoded data
     */
    public byte[] getBytes() {
        return this.privateKey.getEncoded();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PrivateKey that = (PrivateKey) o;

        return privateKey.equals(that.privateKey);
    }

    @Override
    public int hashCode() {
        return privateKey.hashCode();
    }
}
