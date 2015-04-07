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

import java.security.*;
import java.security.spec.ECGenParameterSpec;

/**
 * Key pair for asymmetric encryption
 */
public class KeyPair {
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    private KeyPair(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * Generate a new asymmetric key pair
     * @return an asymmetric key pair
     * @throws ChlorideException when there is an error generating the key pair
     */
    public static KeyPair generate() throws ChlorideException {
        try {
            ECGenParameterSpec spec = new ECGenParameterSpec("prime256v1");
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
            generator.initialize(spec, new SecureRandom());
            java.security.KeyPair pair = generator.generateKeyPair();
            PrivateKey privateKey = new PrivateKey(pair.getPrivate());
            PublicKey publicKey = new PublicKey(pair.getPublic());
            return new KeyPair(privateKey, publicKey);
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new ChlorideException(e);
        }
    }

    /**
     * Retrieve the private key
     * @return the private key
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Retrieve the public key
     * @return the public key
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }
}
