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

import com.jtdowney.chloride.ChlorideTest;
import com.jtdowney.chloride.keys.KeyPair;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

public class BoxTest extends ChlorideTest {
    @Test
    public void testEncryptAndDecrypt() throws Exception {
        KeyPair pair1 = KeyPair.generate();
        KeyPair pair2 = KeyPair.generate();
        Box box1 = new Box(pair1.getPrivateKey(), pair2.getPublicKey());
        Box box2 = new Box(pair2.getPrivateKey(), pair1.getPublicKey());
        byte[] ciphertext = box1.encrypt("too many secrets".getBytes("UTF-8"));
        assertThat(box2.decrypt(ciphertext), equalTo("too many secrets".getBytes("UTF-8")));
    }
}
