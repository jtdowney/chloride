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

package com.jtdowney.chloride.boxes;

import com.jtdowney.chloride.ChlorideException;
import com.jtdowney.chloride.keys.PrivateKey;
import com.jtdowney.chloride.keys.PublicKey;
import com.jtdowney.chloride.keys.SecretKey;

import javax.crypto.KeyAgreement;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Box for asymmetric encryption
 */
public class Box {
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    /**
     * Create a new box with the given keys
     * @param privateKey the private key
     * @param publicKey the public key
     */
    public Box(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * Encrypt the given plaintext
     * @param plaintext value to encrypt
     * @return the encrypted value
     * @throws ChlorideException when an error occurs during encryption
     */
    public byte[] encrypt(byte[] plaintext) throws ChlorideException {
        try {
            return this.deriveSecretBox().encrypt(plaintext);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new ChlorideException(e);
        }
    }

    /**
     * Decrypt the given ciphertext
     * @param ciphertext value to decrypt
     * @return decrypted value
     * @throws ChlorideException when an error occurs during encryption
     */
    public byte[] decrypt(byte[] ciphertext) throws ChlorideException {
        try {
            return this.deriveSecretBox().decrypt(ciphertext);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new ChlorideException(e);
        }
    }

    private SecretBox deriveSecretBox() throws NoSuchAlgorithmException, InvalidKeyException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(this.privateKey.getKey());
        keyAgreement.doPhase(this.publicKey.getKey(), true);
        byte[] z = keyAgreement.generateSecret();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] key = digest.digest(z);
        return new SecretBox(new SecretKey(key));
    }
}
