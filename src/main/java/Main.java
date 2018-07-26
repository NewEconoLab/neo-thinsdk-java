import api.CreateSignParams;
import api.TxCreator;
import api.TxUtils;
import api.Utxo;
import core.DumpedPrivateKey;
import core.ECKey;
import core.NetworkParameters;
import neo.Helper;
import sun.security.ec.ECPrivateKeyImpl;
import sun.security.util.KeyUtil;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;

public class Main {

    public static void main(String[] args) {
        /*
        try {

            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec kpgparams = new ECGenParameterSpec("secp256r1");
            g.initialize(kpgparams);

            KeyPair pair = g.generateKeyPair();
            PrivateKey privateKey = pair.getPrivate();
            PublicKey publicKey = pair.getPublic();

            String str = privateKey.toString();
            byte[] a  = privateKey.getEncoded();


            DumpedPrivateKey dumpedPrivateKey = null;
            dumpedPrivateKey = new DumpedPrivateKey(new NetworkParameters(), "L4RmQvd6PVzBTgYLpYagknNjhZxsHBbJq4ky7Zd3vB7AguSM7gF1", false);

            ECKey ecKey = dumpedPrivateKey.getKey();

            Helper.getPrivateKey(ecKey);

        } catch (Exception e) {
            e.printStackTrace();
        }
        */

        //NeoTransfer();
        Nep5Transfer();
    }

    public static String NeoTransfer() {
        CreateSignParams createSignParams = new CreateSignParams();
        createSignParams.setVersion((byte)1);
        createSignParams.setPriKey("L4RmQvd6PVzBTgYLpYagknNjhZxsHBbJq4ky7Zd3vB7AguSM7gF1");
        createSignParams.setFrom("ARbjp1wPh5XJchZpSjqHzGVQnnpTxNR1x7");
        createSignParams.setTo("APxpKoFCfBk8RjkRdKwyUnsBntDRXLYAZc");
        createSignParams.setAssetId("c56f33fc6ecfcd0c225c4ab356fee59390af8560be0e930faebe74a6daff7c9b");
        createSignParams.setValue(100000000);

        List<Utxo> utxoList = new ArrayList<>();
        Utxo utxo = new Utxo();
        utxo.setHash("b80f65fc5c0cc9a24ae2d613770202aae95dfa598f6541f75987b747eb5ca830");
        utxo.setValue(10000000000L);
        utxo.setN((short) 0);
        utxoList.add(utxo);

        createSignParams.setUtxos(utxoList);

        String raw = TxCreator.createContractTransaction(createSignParams);
        return raw;
    }

    public static String Nep5Transfer() {
        CreateSignParams createSignParams = new CreateSignParams();
        createSignParams.setVersion((byte)1);
        createSignParams.setPriKey("L4RmQvd6PVzBTgYLpYagknNjhZxsHBbJq4ky7Zd3vB7AguSM7gF1");
        createSignParams.setFrom("ARbjp1wPh5XJchZpSjqHzGVQnnpTxNR1x7");
        createSignParams.setTo("ARbjp1wPh5XJchZpSjqHzGVQnnpTxNR1x7");
        createSignParams.setAssetId("602c79718b16e442de58778e148d0b1084e3b2dffd5de6b7b16cee7969282de7");
        createSignParams.setValue(0);

        BigInteger value = new BigInteger("100000000");
        byte[] data = TxUtils.makeNep5Transfer("c88acaae8a0362cdbdedddf0083c452a3a8bb7b8", "ARbjp1wPh5XJchZpSjqHzGVQnnpTxNR1x7", "APxpKoFCfBk8RjkRdKwyUnsBntDRXLYAZc", value);
        createSignParams.setData(data);

        List<Utxo> utxoList = new ArrayList<>();
        Utxo utxo = new Utxo();
        utxo.setHash("d233d677aee8164cffc5ffa0699920d9dda9d4f5a8c23ca074641777e2a00f3b");
        utxo.setValue(900000000L);
        utxo.setN((short) 0);
        utxoList.add(utxo);

        createSignParams.setUtxos(utxoList);

        String raw = TxCreator.createInvocationTransaction(createSignParams);
        return raw;
    }
}
