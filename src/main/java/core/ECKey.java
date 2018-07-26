package core; /**
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

// TODO: This class is quite a mess by now. Once users are migrated away from Java serialization for the wallets,
// refactor this to have better internal layout and a more consistent API.

/**
 * <p>Represents an elliptic curve public and (optionally) private key, usable for digital signatures but not encryption.
 * Creating a new core.ECKey with the empty constructor will generate a new random keypair. Other constructors can be used
 * when you already have the public or private parts. If you create a key with only the public part, you can check
 * signatures but not create them.</p>
 *
 * <p>core.ECKey also provides access to Litecoin-Qt compatible text message signing, as accessible via the UI or JSON-RPC.
 * This is slightly different to signing raw bytes - if you want to sign your own data and it won't be exposed as
 * text to people, you don't want to use this. If in doubt, ask on the mailing list.</p>
 *
 * <p>The ECDSA algorithm supports <i>key recovery</i> in which a signature plus a couple of discriminator bits can
 * be reversed to find the public key used to calculate it. This can be convenient when you have a message and a
 * signature and want to find out who signed it, rather than requiring the user to provide the expected identity.</p>
 */
public class ECKey implements Serializable {

    private static final ECDomainParameters ecParams;

    private static final SecureRandom secureRandom;
    private static final long serialVersionUID = -728224901792295832L;

    static {
        X9ECParameters params = SECNamedCurves.getByName("secp256r1");
        ecParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
        secureRandom = new SecureRandom();
    }

    // The two parts of the key. If "priv" is set, "pub" can always be calculated. If "pub" is set but not "priv", we
    // can only verify signatures not make them.
    // TODO: Redesign this class to use consistent internals and more efficient serialization.
    private BigInteger priv;
    private byte[] pub;


    // Transient because it's calculated on demand.
    transient private byte[] pubKeyHash;

    /**
     * Generates an entirely new keypair. Point compression is used so the resulting public key will be 33 bytes
     * (32 for the co-ordinate and 1 byte to represent the y bit).
     */
    public ECKey() {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(ecParams, secureRandom);
        generator.init(keygenParams);
        AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
        ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keypair.getPrivate();
        ECPublicKeyParameters pubParams = (ECPublicKeyParameters) keypair.getPublic();
        priv = privParams.getD();
        // Unfortunately Bouncy Castle does not let us explicitly change a point to be compressed, even though it
        // could easily do so. We must re-build it here so the ECPoints withCompression flag can be set to true.
        ECPoint uncompressed = pubParams.getQ();
        ECPoint compressed = compressPoint(uncompressed);
        pub = compressed.getEncoded();

    }

    private static ECPoint compressPoint(ECPoint uncompressed) {
        return new ECPoint.Fp(ecParams.getCurve(), uncompressed.getX(), uncompressed.getY(), true);
    }

    /**
     * Construct an core.ECKey from an ASN.1 encoded private key. These are produced by OpenSSL and stored by the Litecoin
     * reference implementation in its wallet. Note that this is slow because it requires an EC point multiply.
     */
    public static ECKey fromASN1(byte[] asn1privkey) {
        return new ECKey(extractPrivateKeyFromASN1(asn1privkey));
    }

    /** Creates an core.ECKey given the private key only.  The public key is calculated from it (this is slow) */
    public ECKey(BigInteger privKey) {
        this(privKey, (byte[])null);
    }

    /** A constructor variant with BigInteger pubkey. See {@link ECKey#ECKey(BigInteger, byte[])}. */
    public ECKey(BigInteger privKey, BigInteger pubKey) {
        this(privKey, Utils.bigIntegerToBytes(pubKey, 65));
    }

    /**
     * Creates an core.ECKey given only the private key bytes. This is the same as using the BigInteger constructor, but
     * is more convenient if you are importing a key from elsewhere. The public key will be automatically derived
     * from the private key.
     */
    public ECKey(byte[] privKeyBytes, byte[] pubKey) {
        this(privKeyBytes == null ? null : new BigInteger(1, privKeyBytes), pubKey);
    }


    /**
     * Creates an core.ECKey given either the private key only, the public key only, or both. If only the private key
     * is supplied, the public key will be calculated from it (this is slow). If both are supplied, it's assumed
     * the public key already correctly matches the public key. If only the public key is supplied, this core.ECKey cannot
     * be used for signing.
     * @param compressed If set to true and pubKey is null, the derived public key will be in compressed form.
     */
    public ECKey(BigInteger privKey, byte[] pubKey, boolean compressed) {
        this.priv = privKey;
        this.pub = null;
        if (pubKey == null && privKey != null) {
            // Derive public from private.
            this.pub = publicKeyFromPrivate(privKey, compressed);
        } else if (pubKey != null) {
            // We expect the pubkey to be in regular encoded form, just as a BigInteger. Therefore the first byte is
            // a special marker byte.
            // TODO: This is probably not a useful API and may be confusing.
            this.pub = pubKey;
        }
    }

    /**
     * Creates an core.ECKey given either the private key only, the public key only, or both. If only the private key
     * is supplied, the public key will be calculated from it (this is slow). If both are supplied, it's assumed
     * the public key already correctly matches the public key. If only the public key is supplied, this core.ECKey cannot
     * be used for signing.
     */
    private ECKey(BigInteger privKey, byte[] pubKey) {
        this(privKey, pubKey, false);
    }

    /**
     * Output this core.ECKey as an ASN.1 encoded private key, as understood by OpenSSL or used by the Litecoin reference
     * implementation in its wallet storage format.
     */
    public byte[] toASN1() {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream(400);

            DERSequenceGenerator seq = new DERSequenceGenerator(baos);
            seq.addObject(new ASN1Integer(1)); // version
            seq.addObject(new DEROctetString(priv.toByteArray()));
            seq.addObject(new DERTaggedObject(0, SECNamedCurves.getByName("secp256k1").toASN1Primitive()));
            seq.addObject(new DERTaggedObject(1, new DERBitString(getPubKey())));
            seq.close();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen, writing to memory stream.
        }
    }

    /**
     * Returns public key bytes from the given private key. To convert a byte array into a BigInteger, use <tt>
     * new BigInteger(1, bytes);</tt>
     */
    public static byte[] publicKeyFromPrivate(BigInteger privKey, boolean compressed) {
        ECPoint point = ecParams.getG().multiply(privKey);
        if (compressed)
            point = compressPoint(point);
        return point.getEncoded();
    }

    /** Gets the hash160 form of the public key (as seen in addresses). */
    public byte[] getPubKeyHash() {
        if (pubKeyHash == null)
            pubKeyHash = Utils.sha256hash160(this.pub);
        return pubKeyHash;
    }

    /**
     * Gets the raw public key value. This appears in transaction scriptSigs. Note that this is <b>not</b> the same
     * as the pubKeyHash/address.
     */
    public byte[] getPubKey() {
        return pub;
    }

    /**
     * Returns whether this key is using the compressed form or not. Compressed pubkeys are only 33 bytes, not 64.
     */
    public boolean isCompressed() {
        return pub.length == 33;
    }

    public String toString() {
        StringBuilder b = new StringBuilder();
        b.append("pub:").append(Utils.bytesToHexString(pub));

        return b.toString();
    }

    /**
     * Produce a string rendering of the core.ECKey INCLUDING the private key.
     * Unless you absolutely need the private key it is better for security reasons to just use toString().
     */
    public String toStringWithPrivate() {
        StringBuilder b = new StringBuilder();
        b.append(toString());
        if (priv != null) {
            b.append(" priv:").append(Utils.bytesToHexString(priv.toByteArray()));
        }
        return b.toString();
    }


    /**
     * Clears all the core.ECKey private key contents from memory.
     * WARNING - this method irreversibly deletes the private key information.
     * It turns the ECKEy into a watch only key.
     */
    public void clearPrivateKey() {
       priv = BigInteger.ZERO;
    }

    /**
     * Groups the two components that make up a signature, and provides a way to encode to DER form, which is
     * how ECDSA signatures are represented when embedded in other data structures in the Litecoin protocol. The raw
     * components can be useful for doing further EC maths on them.
     */
    public static class ECDSASignature {
        public BigInteger r, s;

        public ECDSASignature(BigInteger r, BigInteger s) {
            this.r = r;
            this.s = s;
        }

        /**
         * What we get back from the signer are the two components of a signature, r and s. To get a flat byte stream
         * of the type used by Litecoin we have to encode them using DER encoding, which is just a way to pack the two
         * components into a structure.
         */
        public byte[] encodeToDER() {
            try {
                // Usually 70-72 bytes.
                ByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(72);
                DERSequenceGenerator seq = new DERSequenceGenerator(bos);
                seq.addObject(new DERInteger(r));
                seq.addObject(new DERInteger(s));
                seq.close();
                return bos.toByteArray();
            } catch (IOException e) {
                throw new RuntimeException(e);  // Cannot happen.
            }
        }
    }

    /**
     * Signs the given hash and returns the R and S components as BigIntegers. In the Litecoin protocol, they are
     * usually encoded using DER format, so you want {@link ECKey.ECDSASignature#toASN1()}
     * instead. However sometimes the independent components can be useful, for instance, if you're doing to do
     * further EC maths on them.
     */
    public ECDSASignature sign(Sha256Hash input){
        return sign(input, null);
    }

    /**
     * Signs the given hash and returns the R and S components as BigIntegers. In the Litecoin protocol, they are
     * usually encoded using DER format, so you want {@link ECKey.ECDSASignature#encodeToDER()}
     * instead. However sometimes the independent components can be useful, for instance, if you're doing to do further
     * EC maths on them.
     *
     * @param aesKey The AES key to use for decryption of the private key. If null then no decryption is required.
     */
    public ECDSASignature sign(Sha256Hash input, KeyParameter aesKey){
        // The private key bytes to use for signing.
        BigInteger privateKeyForSigning = priv;

        ECDSASigner signer = new ECDSASigner();
        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(privateKeyForSigning, ecParams);
        signer.init(true, privKey);
        BigInteger[] sigs = signer.generateSignature(input.getBytes());
        return new ECDSASignature(sigs[0], sigs[1]);
    }

    /**
     * Verifies the given ASN.1 encoded ECDSA signature against a hash using the public key.
     *
     * @param data      Hash of the data to verify.
     * @param signature ASN.1 encoded signature.
     * @param pub       The public key bytes to use.
     */
    public static boolean verify(byte[] data, byte[] signature, byte[] pub) {
        ECDSASigner signer = new ECDSASigner();
        ECPublicKeyParameters params = new ECPublicKeyParameters(ecParams.getCurve().decodePoint(pub), ecParams);
        signer.init(false, params);
        try {
            ASN1InputStream decoder = new ASN1InputStream(signature);
            DLSequence seq = (DLSequence) decoder.readObject();
            DERInteger r = (DERInteger) seq.getObjectAt(0);
            DERInteger s = (DERInteger) seq.getObjectAt(1);
            decoder.close();
            // OpenSSL deviates from the DER spec by interpreting these values as unsigned, though they should not be
            // Thus, we always use the positive versions.
            // See: http://r6.ca/blog/20111119T211504Z.html
            try {
                return signer.verifySignature(data, r.getPositiveValue(), s.getPositiveValue());
            } catch (NullPointerException e) {

                e.printStackTrace();
                return false;
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean neoVerify(byte[] data, byte[] signature, byte[] pub) {

        ECDSASigner signer = new ECDSASigner();
        ECPublicKeyParameters params = new ECPublicKeyParameters(ecParams.getCurve().decodePoint(pub), ecParams);
        signer.init(false, params);

        byte[] rBytes = null;
        if(signature[0] < 0) {
            rBytes = new byte[33];
            rBytes[0] = 0x00;
            System.arraycopy(signature, 0, rBytes, 1, 32);
        } else {
            rBytes = new byte[32];
            System.arraycopy(signature, 0, rBytes, 0, 32);
        }

        BigInteger r = new BigInteger(rBytes);

        byte[] sBytes = null;
        if(signature[32] < 0) {
            sBytes = new byte[33];
            sBytes[0] = 0x00;
            System.arraycopy(signature, 32, sBytes, 1, 32);
        } else {
            sBytes = new byte[32];
            System.arraycopy(signature, 32, sBytes, 0, 32);
        }

        BigInteger s = new BigInteger(sBytes);

        try {
            return signer.verifySignature(data, r, s);
        } catch (NullPointerException e) {

            e.printStackTrace();
            return false;
        }

    }

    /**
     * Verifies the given ASN.1 encoded ECDSA signature against a hash using the public key.
     *
     * @param data      Hash of the data to verify.
     * @param signature ASN.1 encoded signature.
     */
    public boolean verify(byte[] data, byte[] signature) {
        return ECKey.verify(data, signature, pub);
    }

    private static BigInteger extractPrivateKeyFromASN1(byte[] asn1privkey) {
        // To understand this code, see the definition of the ASN.1 format for EC private keys in the OpenSSL source
        // code in ec_asn1.c:

        try {
            ASN1InputStream decoder = new ASN1InputStream(asn1privkey);
            DLSequence seq = (DLSequence) decoder.readObject();
            checkArgument(seq.size() == 4, "Input does not appear to be an ASN.1 OpenSSL EC private key");
            checkArgument(((DERInteger) seq.getObjectAt(0)).getValue().equals(BigInteger.ONE),
                    "Input is of wrong version");
            Object obj = seq.getObjectAt(1);
            byte[] bits = ((ASN1OctetString) obj).getOctets();
            decoder.close();
            return new BigInteger(1, bits);
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen, reading from memory stream.
        }
    }


    /**
     * <p>Given the components of a signature and a selector value, recover and return the public key
     * that generated the signature according to the algorithm in SEC1v2 section 4.1.6.</p>
     *
     * <p>The recId is an index from 0 to 3 which indicates which of the 4 possible keys is the correct one. Because
     * the key recovery operation yields multiple potential keys, the correct key must either be stored alongside the
     * signature, or you must be willing to try each recId in turn until you find one that outputs the key you are
     * expecting.</p>
     *
     * <p>If this method returns null it means recovery was not possible and recId should be iterated.</p>
     *
     * <p>Given the above two points, a correct usage of this method is inside a for loop from 0 to 3, and if the
     * output is null OR a key that is not the one you expect, you try again with the next recId.</p>
     *
     * @param recId Which possible key to recover.
     * @param sig the R and S components of the signature, wrapped.
     * @param message Hash of the data that was signed.
     * @param compressed Whether or not the original pubkey was compressed.
     * @return An core.ECKey containing only the public part, or null if recovery wasn't possible.
     */
    public static ECKey recoverFromSignature(int recId, ECDSASignature sig, Sha256Hash message, boolean compressed) {
        checkArgument(recId >= 0, "recId must be positive");
        checkArgument(sig.r.compareTo(BigInteger.ZERO) >= 0, "r must be positive");
        checkArgument(sig.s.compareTo(BigInteger.ZERO) >= 0, "s must be positive");
        checkNotNull(message);
        // 1.0 For j from 0 to h   (h == recId here and the loop is outside this function)
        //   1.1 Let x = r + jn
        BigInteger n = ecParams.getN();  // Curve order.
        BigInteger i = BigInteger.valueOf((long) recId / 2);
        BigInteger x = sig.r.add(i.multiply(n));
        //   1.2. Convert the integer x to an octet string X of length mlen using the conversion routine
        //        specified in Section 2.3.7, where mlen = ⌈(log2 p)/8⌉ or mlen = ⌈m/8⌉.
        //   1.3. Convert the octet string (16 set binary digits)||X to an elliptic curve point R using the
        //        conversion routine specified in Section 2.3.4. If this conversion routine outputs “invalid”, then
        //        do another iteration of Step 1.
        //
        // More concisely, what these points mean is to use X as a compressed public key.
        ECCurve.Fp curve = (ECCurve.Fp) ecParams.getCurve();
        BigInteger prime = curve.getQ();  // Bouncy Castle is not consistent about the letter it uses for the prime.
        if (x.compareTo(prime) >= 0) {
            // Cannot have point co-ordinates larger than this as everything takes place modulo Q.
            return null;
        }
        // Compressed keys require you to know an extra bit of data about the y-coord as there are two possibilities.
        // So it's encoded in the recId.
        ECPoint R = decompressKey(x, (recId & 1) == 1);
        //   1.4. If nR != point at infinity, then do another iteration of Step 1 (callers responsibility).
        if (!R.multiply(n).isInfinity())
            return null;
        //   1.5. Compute e from M using Steps 2 and 3 of ECDSA signature verification.
        BigInteger e = message.toBigInteger();
        //   1.6. For k from 1 to 2 do the following.   (loop is outside this function via iterating recId)
        //   1.6.1. Compute a candidate public key as:
        //               Q = mi(r) * (sR - eG)
        //
        // Where mi(x) is the modular multiplicative inverse. We transform this into the following:
        //               Q = (mi(r) * s ** R) + (mi(r) * -e ** G)
        // Where -e is the modular additive inverse of e, that is z such that z + e = 0 (mod n). In the above equation
        // ** is point multiplication and + is point addition (the EC group operator).
        //
        // We can find the additive inverse by subtracting e from zero then taking the mod. For example the additive
        // inverse of 3 modulo 11 is 8 because 3 + 8 mod 11 = 0, and -3 mod 11 = 8.
        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
        BigInteger rInv = sig.r.modInverse(n);
        BigInteger srInv = rInv.multiply(sig.s).mod(n);
        BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
        ECPoint p1 = ecParams.getG().multiply(eInvrInv);
        ECPoint p2 = R.multiply(srInv);
        ECPoint.Fp q = (ECPoint.Fp) p2.add(p1);
        if (compressed) {
            // We have to manually recompress the point as the compressed-ness gets lost when multiply() is used.
            q = new ECPoint.Fp(curve, q.getX(), q.getY(), true);
        }
        return new ECKey((byte[])null, q.getEncoded());
    }

    /** Decompress a compressed public key (x co-ord and low-bit of y-coord). */
    private static ECPoint decompressKey(BigInteger xBN, boolean yBit) {
        // This code is adapted from Bouncy Castle ECCurve.Fp.decodePoint(), but it wasn't easily re-used.
        ECCurve.Fp curve = (ECCurve.Fp) ecParams.getCurve();
        ECFieldElement x = new ECFieldElement.Fp(curve.getQ(), xBN);
        ECFieldElement alpha = x.multiply(x.square().add(curve.getA())).add(curve.getB());
        ECFieldElement beta = alpha.sqrt();
        // If we can't find a sqrt we haven't got a point on the curve - invalid inputs.
        if (beta == null)
            throw new IllegalArgumentException("Invalid point compression");
        if (beta.toBigInteger().testBit(0) == yBit) {
            return new ECPoint.Fp(curve, x, beta, true);
        } else {
            ECFieldElement.Fp y = new ECFieldElement.Fp(curve.getQ(), curve.getQ().subtract(beta.toBigInteger()));
            return new ECPoint.Fp(curve, x, y, true);
        }
    }

    /**
     * Returns a 32 byte array containing the private key.
     */
    public byte[] getPrivKeyBytes() {
        return Utils.bigIntegerToBytes(priv, 32);
    }

    public BigInteger getPriv() {
        return priv;
    }

    /**
     * Exports the private key in the form used by Bitcoin Core's "dumpprivkey" and "importprivkey" commands. Use
     * the {@link core.DumpedPrivateKey#toString()} method to get the string.
     *
     * @param params The network this key is intended for use on.
     * @return Private key bytes as a {@link DumpedPrivateKey}.
     * @throws IllegalStateException if the private key is not available.
     */
    public DumpedPrivateKey getPrivateKeyEncoded(NetworkParameters params) {
        return new DumpedPrivateKey(params, getPrivKeyBytes(), isCompressed());
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ECKey ecKey = (ECKey) o;

        return Arrays.equals(pub, ecKey.pub);
    }

    @Override
    public int hashCode() {
        // Public keys are random already so we can just use a part of them as the hashcode. Read from the start to
        // avoid picking up the type code (compressed vs uncompressed) which is tacked on the end.
        return (pub[0] & 0xFF) | ((pub[1] & 0xFF) << 8) | ((pub[2] & 0xFF) << 16) | ((pub[3] & 0xFF) << 24);
    }

}
