# chloride

Chloride provides a simple API over Java's crypto functionality. It uses [Bouncy Castle](https://www.bouncycastle.org/java.html) to provide support for modern algorithms. The API is loosely modeled after [NaCl](http://nacl.cr.yp.to/) and [libsodium](https://github.com/jedisct1/libsodium).

## Algorithms

Under the hood, `chloride` uses [NSA Suite B Cryptography](http://en.wikipedia.org/wiki/NSA_Suite_B_Cryptography). This means it uses AES-256-GCM to encrypt data and for asymmetric boxes it uses ECDH with curve P-256 for key agreement.

## Requirements

1. You need to [install Bouncy Castle as a JCE provider](http://www.bouncycastle.org/wiki/display/JA1/Provider+Installation).
2. You need the [Java Crypto Unlimited Strength Policy files](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html).

## Usage

### Box (asymmetric encryption)

```java
KeyPair pair1 = KeyPair.generate();
KeyPair pair2 = KeyPair.generate();
Box box1 = new Box(pair1.getPrivateKey(), pair2.getPublicKey());
Box box2 = new Box(pair2.getPrivateKey(), pair1.getPublicKey());

byte[] ciphertext = box1.encrypt("too many secrets".getBytes("UTF-8"));
byte[] plaintext = box2.decrypt(ciphertext);
```

### Secret Box (symmetric encryption)

```java
SecretKey key = SecretKey.generate();
SecretBox box = new SecretBox(key);
byte[] ciphertext = box.encrypt("too many secrets".getBytes("UTF-8"));
byte[] plaintext = box.decrypt(ciphertext);
```
