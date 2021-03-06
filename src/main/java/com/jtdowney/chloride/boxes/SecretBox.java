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
import com.jtdowney.chloride.keys.SecretKey;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

/**
 * Box for symmetric encryption
 */
public class SecretBox {
    private final byte[] key;

    /**
     * Create a secret box using the provided secret key.
     * @param key secret key to encrypt with
     */
    public SecretBox(SecretKey key) {
        this.key = key.getBytes();
    }

    /**
     * Encrypt the given plaintext
     * @param plaintext value to encrypt
     * @return the encrypted value
     * @throws ChlorideException when an error occurs during encryption
     */
    public byte[] encrypt(byte[] plaintext) throws ChlorideException {
        try {
            byte[] nonce = new byte[12];
            SecureRandom random = SecureRandom.getInstance("NativePRNG");
            random.nextBytes(nonce);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(this.key, "AES"), new IvParameterSpec(nonce));
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            CipherOutputStream cipherStream = new CipherOutputStream(output, cipher);
            cipherStream.write(plaintext);
            cipherStream.close();

            byte[] ciphertext = output.toByteArray();
            byte[] result = new byte[nonce.length + ciphertext.length];
            System.arraycopy(nonce, 0, result, 0, nonce.length);
            System.arraycopy(ciphertext, 0, result, nonce.length, ciphertext.length);

            return result;
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | NoSuchProviderException | IOException e) {
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
            byte[] nonce = new byte[12];
            System.arraycopy(ciphertext, 0, nonce, 0, nonce.length);

            byte[] input = new byte[ciphertext.length - nonce.length];
            System.arraycopy(ciphertext, nonce.length, input, 0, input.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(this.key, "AES"), new IvParameterSpec(nonce));
            ByteArrayInputStream inputStream = new ByteArrayInputStream(input);
            CipherInputStream cipherStream = new CipherInputStream(inputStream, cipher);

            return readOutput(cipherStream);
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | NoSuchProviderException | IOException e) {
            throw new ChlorideException(e);
        }
    }

    private byte[] readOutput(InputStream inputStream) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];

        while (true) {
            int length = inputStream.read(buffer);
            if (length == -1) {
                break;
            }

            outputStream.write(buffer, 0, length);
        }

        return outputStream.toByteArray();
    }
}
