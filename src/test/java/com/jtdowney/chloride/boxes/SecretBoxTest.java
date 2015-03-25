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

import com.jtdowney.chloride.keys.SecretKey;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

public class SecretBoxTest {
    @Rule
    public final ExpectedException thrown = ExpectedException.none();

    @Test
    public void testEncryptAndDecrypt() throws Exception {
        SecretKey key = SecretKey.generate();
        SecretBox box = new SecretBox(key);
        byte[] ciphertext = box.encrypt("too many secrets".getBytes("UTF-8"));
        assertThat(box.decrypt(ciphertext), equalTo("too many secrets".getBytes("UTF-8")));
    }

    @Test
    public void testMalleabilityProtection() throws Exception {
        thrown.expectMessage("mac check in GCM failed");
        SecretBox box = new SecretBox(SecretKey.generate());
        byte[] ciphertext = box.encrypt("too many secrets".getBytes("UTF-8"));
        ciphertext[15] -= 1;
        box.decrypt(ciphertext);
    }
}
