package neo;

import core.*;
import org.bouncycastle.util.BigIntegers;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;

import sun.security.ec.ECPrivateKeyImpl;
import sun.security.ec.ECPublicKeyImpl;

public class Helper {
    public static byte[] getPublicKeyHashFromAddress(String encoded) {
        Address address = null;
        try {
            address = new Address(encoded);
            return address.getHash160();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] getScriptHashFromScript(byte[] script) {
        return Utils.sha256hash160(script);
    }

    public static String getAddressFromScriptHash(byte[] scriptHash) {
        Address address = new Address(new NetworkParameters(), scriptHash);
        return address.toString();
    }

    public static Address toAddress(NetworkParameters params, byte[] pubkey) {
        byte[] script = getScriptFromPublicKey(pubkey);
        byte[] hash160 = Utils.sha256hash160(script);
        return new Address(params, hash160);
    }

    public static byte[] getScriptFromPublicKey(byte[] pubkey) {
        byte[] script = new byte[35];
        script[0] = 33;
        System.arraycopy(pubkey, 0, script, 1, 33);
        script[34] = (byte)172;
        return script;
    }

    public static int ReadVarInt(ByteArrayInputStream bais) {
        try {
            VarInt varInt = new VarInt(bais);

            int length = (int) varInt.value;
            return length;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return 0;
    }

    public static byte[] sign(Sha256Hash sha256Hash, ECKey ecKey) {
        /*
        ECKey.ECDSASignature ecdsaSignature = null;
        while (true) {
            ecdsaSignature = ecKey.sign(sha256Hash);
            if(ecdsaSignature.r.compareTo(BigInteger.ZERO) >= 0 && ecdsaSignature.s.compareTo(BigInteger.ZERO) >= 0) {
                byte[] r = ecdsaSignature.r.toByteArray();
                byte[] s = ecdsaSignature.s.toByteArray();
                break;
            }
        }
        */
        ECKey.ECDSASignature ecdsaSignature = ecKey.sign(sha256Hash);

        byte[] rBytes = BigIntegers.asUnsignedByteArray(32, ecdsaSignature.r);
        byte[] sBytes = BigIntegers.asUnsignedByteArray(32, ecdsaSignature.s);

        byte[] signature = new byte[64];

        System.arraycopy(rBytes, 0, signature, 32 - rBytes.length, rBytes.length);
        System.arraycopy(sBytes, 0, signature, 64 - sBytes.length, sBytes.length);

        return signature;
    }

    public static ECPrivateKey getPrivateKey(ECKey ecKey) {

        try {
            BigInteger p = ecKey.getPriv();
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
            ECPrivateKey privateKey = new ECPrivateKeyImpl(p, ecParameterSpec);
            /*
            byte[] pubBytes = ECKey.publicKeyFromPrivate(p, false);
            byte[] sss = ECKey.publicKeyFromPrivate(p, true);

            ECPublicKey publicKey = getPublicKey(pubBytes);
            */
            return privateKey;

        }catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    public static ECPublicKey getPublicKey(byte[] publicKeyBytes) {
        // First we separate x and y of coordinates into separate variables
        byte[] x = new byte[32];
        byte[] y = new byte[32];
        System.arraycopy(publicKeyBytes, 1, x, 0, 32);
        System.arraycopy(publicKeyBytes, 33, y, 0, 32);

        try {

            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);

            //ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(new ECPoint(new BigInteger(x), new BigInteger(y)), ecParameterSpec);
            ECPublicKey ecPublicKey = new ECPublicKeyImpl(new ECPoint(new BigInteger(x), new BigInteger(y)), ecParameterSpec);

            return ecPublicKey;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] signature(byte[] content, PrivateKey privateKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(content);
        return signature.sign();
    }

    public static boolean verify(byte[] content, byte[] sign, PublicKey publicKey)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(publicKey);
        try {
            signature.update(content);
            return signature.verify(sign);
        } catch (SignatureException e) {
            e.printStackTrace();
            return false;
        }

    }

}
