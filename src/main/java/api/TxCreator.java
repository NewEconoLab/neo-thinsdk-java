package api;

import core.*;
import neo.*;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.util.ArrayList;
import java.util.List;

public class TxCreator {
    public static String createContractTransaction(CreateSignParams params) {
        Transaction tx = new Transaction();
        tx.setTxtype(TransactionType.ContractTransaction);
        tx.setVersion(params.getVersion());

        long sum = 0;
        List<Utxo> utxos = params.getUtxos();

        List<TransactionInput> inputs = null;
        int size = utxos.size();
        if(size > 0) {
            inputs = new ArrayList<TransactionInput>();
            tx.setInputs(inputs);
        }

        for(int i = 0; i < size; i++) {
            TransactionInput input = new TransactionInput();
            inputs.add(input);
            Utxo utxo = utxos.get(i);
            byte[] hash = Utils.hexStringToBytes(utxo.getHash());
            hash = Utils.reverseBytes(hash);
            input.setHash(hash);

            input.setIndex(utxo.getN());
            sum += utxo.getValue();
        }

        long value = params.getValue();
        String toAddress = params.getTo();
        if(sum < value) {
            return "";
        }

        List<TransactionOutput> outputs = new ArrayList<>();
        tx.setOutputs(outputs);

        String assetId = params.getAssetId();
        TransactionOutput output = new TransactionOutput();
        outputs.add(output);
        byte[] vAssetId = Utils.hexStringToBytes(assetId);
        vAssetId = Utils.reverseBytes(vAssetId);
        output.setAssetId(vAssetId);
        Fixed8 gasvalue = new Fixed8();
        gasvalue.setValue(value);
        output.setValue(gasvalue);
        byte[] pubkeyhash = Helper.getPublicKeyHashFromAddress(toAddress);
        output.setToAddress(pubkeyhash);

        String fromAddress = params.getFrom();
        long left = sum - value;
        if(left > 0) {
            TransactionOutput output2 = new TransactionOutput();
            outputs.add(output2);

            output2.setAssetId(vAssetId);
            Fixed8 leftValue = new Fixed8();
            leftValue.setValue(left);
            output2.setValue(leftValue);
            byte[] pkh = Helper.getPublicKeyHashFromAddress(fromAddress);
            output2.setToAddress(pkh);
        }

        byte[] unsignedData = tx.getMessage();
        String privKey = params.getPriKey();
        DumpedPrivateKey dumpedPrivateKey = null;

        try {
            dumpedPrivateKey = new DumpedPrivateKey(new NetworkParameters(), privKey, false);
        } catch (Exception e) {
            e.printStackTrace();
        }

        if(dumpedPrivateKey == null) {
            return "";
        }

        ECKey ecKey = dumpedPrivateKey.getKey();

        Sha256Hash sha256Hash = Sha256Hash.create(unsignedData);

        byte[] signature = Helper.sign(sha256Hash, ecKey);
        byte[] pub = ecKey.getPubKey();
        tx.addWitness(signature, pub, fromAddress);

        /*
        ECPrivateKey ecPrivateKey = Helper.getPrivateKey(ecKey);
        byte[] signData = null;
        try {
            signData = Helper.signature(unsignedData, ecPrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }

        BigInteger p = ecKey.getPriv();
        byte[] pub = ECKey.publicKeyFromPrivate(p, false);
        byte[] compressed = ECKey.publicKeyFromPrivate(p, true);
        tx.addWitness(signData, pub, compressed, fromAddress);
        */

        byte[] rawData = tx.getRawData();
        String raw = Utils.bytesToHexString(rawData);

        return raw;
    }

    public static String createInvocationTransaction(CreateSignParams params) {
        Transaction tx = new Transaction();
        tx.setTxtype(TransactionType.InvocationTransaction);
        tx.setVersion(params.getVersion());

        long sum = 0;
        List<Utxo> utxos = params.getUtxos();

        List<TransactionInput> inputs = null;
        int size = utxos.size();
        if(size > 0) {
            inputs = new ArrayList<TransactionInput>();
            tx.setInputs(inputs);
        }

        for(int i = 0; i < size; i++) {
            TransactionInput input = new TransactionInput();
            inputs.add(input);
            Utxo utxo = utxos.get(i);
            byte[] hash = Utils.hexStringToBytes(utxo.getHash());
            hash = Utils.reverseBytes(hash);
            input.setHash(hash);

            input.setIndex(utxo.getN());
            sum += utxo.getValue();
        }

        String toAddress = params.getTo();
        if(sum <= 0) {
            return "";
        }

        List<TransactionOutput> outputs = new ArrayList<>();
        tx.setOutputs(outputs);

        String assetId = params.getAssetId();
        TransactionOutput output = new TransactionOutput();
        outputs.add(output);
        byte[] vAssetId = Utils.hexStringToBytes(assetId);
        vAssetId = Utils.reverseBytes(vAssetId);
        output.setAssetId(vAssetId);
        Fixed8 value = new Fixed8();
        value.setValue(sum);
        output.setValue(value);
        byte[] pubkeyhash = Helper.getPublicKeyHashFromAddress(toAddress);
        output.setToAddress(pubkeyhash);

        String fromAddress = params.getFrom();
        InvokeTransData invokeTransData = new InvokeTransData();
        invokeTransData.setScript(params.getData());
        Fixed8 gas = new Fixed8();
        gas.setValue(100000000);
        invokeTransData.setGas(gas);
        tx.setExtdata(invokeTransData);

        byte[] unsignedData = tx.getMessage();
        String privKey = params.getPriKey();
        DumpedPrivateKey dumpedPrivateKey = null;

        try {
            dumpedPrivateKey = new DumpedPrivateKey(new NetworkParameters(), privKey, false);
        } catch (Exception e) {
            e.printStackTrace();
        }

        if(dumpedPrivateKey == null) {
            return "";
        }

        ECKey ecKey = dumpedPrivateKey.getKey();

        Sha256Hash sha256Hash = Sha256Hash.create(unsignedData);

        byte[] signature = Helper.sign(sha256Hash, ecKey);
        byte[] pub = ecKey.getPubKey();
        tx.addWitness(signature, pub, fromAddress);

        /*
        ECPrivateKey ecPrivateKey = Helper.getPrivateKey(ecKey);
        byte[] signData = null;
        try {
            signData = Helper.signature(unsignedData, ecPrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }

        BigInteger p = ecKey.getPriv();
        byte[] pub = ECKey.publicKeyFromPrivate(p, false);
        byte[] compressed = ECKey.publicKeyFromPrivate(p, true);
        tx.addWitness(signData, pub, compressed, fromAddress);
        */

        byte[] rawData = tx.getRawData();
        String raw = Utils.bytesToHexString(rawData);
        return  raw;
    }
}
