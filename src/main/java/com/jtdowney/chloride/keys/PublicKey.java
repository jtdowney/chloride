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

import com.jtdowney.chloride.ChlorideException;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * Asymmetric public key
 */
public class PublicKey {
    private java.security.PublicKey publicKey;

    PublicKey(java.security.PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * Create a public key from DER encoded data
     * @param data the DER encoded data
     * @throws ChlorideException when the private key cannot be loaded
     */
    public PublicKey(byte[] data) throws ChlorideException {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("ECDH");
            this.publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(data));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new ChlorideException(e);
        }
    }

    /**
     * Retrieve underlying public key
     * @return the public key
     */
    public java.security.PublicKey getKey() {
        return publicKey;
    }

    /**
     * Retrieve DER encoded form of the key
     * @return the DER encoded data
     */
    public byte[] getBytes() {
        return this.publicKey.getEncoded();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PublicKey that = (PublicKey) o;

        return this.publicKey.equals(that.publicKey);
    }

    @Override
    public int hashCode() {
        return publicKey.hashCode();
    }
}
