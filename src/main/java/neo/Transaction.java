package neo;

import core.*;
import lombok.Data;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;

@Data
public class Transaction {
    private byte txtype;
    private byte version;
    private List<Attribute> attributes;
    private List<TransactionInput> inputs;
    private List<TransactionOutput> outputs;
    private List<Witness> witnesses = new ArrayList<>();
    private IExtData extdata;

    public byte[] getMessage() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        serializeUnsigned(baos);

        return baos.toByteArray();
    }

    public byte[] getRawData() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        serialize(baos);

        return baos.toByteArray();
    }

    public byte[] getHash() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        serialize(baos);

        return baos.toByteArray();
    }

    public boolean addWitness(byte[] signData, byte[] pub, byte[] compressed, String addrs) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        serializeUnsigned(baos);

        byte[] data = baos.toByteArray();

        /*
        Sha256Hash sha256Hash = Sha256Hash.create(data);

        boolean bSign = ECKey.neoVerify(sha256Hash.getBytes(), signData, pub);
        if(!bSign) {
            return false;
        }
        */
        ECPublicKey ecPublicKey = Helper.getPublicKey(pub);
        boolean bSign = false;
        try {
            bSign = Helper.verify(data, signData, ecPublicKey);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

        if(!bSign) {
            return false;
        }

        Address address = Helper.toAddress(new NetworkParameters(), compressed);
        String addr = address.toString();
        if(!addr.equals(addrs)) {
            return false;
        }
        byte[] vscript = Helper.getScriptFromPublicKey(compressed);
        ScriptBuilder scriptBuilder = new ScriptBuilder();
        scriptBuilder.EmitPushBytes(signData);
        byte[] iscript = scriptBuilder.toBytes();
        this.addWitnessScript(vscript, iscript);
        return true;
    }

    public boolean addWitness(byte[] signData, byte[] pub, String addrs) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        serializeUnsigned(baos);

        byte[] data = baos.toByteArray();


        Sha256Hash sha256Hash = Sha256Hash.create(data);

        boolean bSign = ECKey.neoVerify(sha256Hash.getBytes(), signData, pub);
        if(!bSign) {
            return false;
        }


        Address address = Helper.toAddress(new NetworkParameters(), pub);
        String addr = address.toString();
        if(!addr.equals(addrs)) {
            return false;
        }
        byte[] vscript = Helper.getScriptFromPublicKey(pub);
        ScriptBuilder scriptBuilder = new ScriptBuilder();
        scriptBuilder.EmitPushBytes(signData);
        byte[] iscript = scriptBuilder.toBytes();
        this.addWitnessScript(vscript, iscript);
        return true;
    }

    public boolean addWitnessScript(byte[] script, byte[] iscript) {
        Witness newwit = new Witness();
        newwit.setVerificationScript(script);
        newwit.setInvocationScript(iscript);

        int size = this.witnesses.size();
        for(int i = 0; i < size; i++) {
            Witness tmpwit = this.witnesses.get(i);
            String tmpAddr = tmpwit.getAddress();
            String newAddr = newwit.getAddress();
            if(tmpAddr == newAddr) {
                return false;
            }
        }
        this.witnesses.add(newwit);
        return true;
    }

    public boolean serializeUnsigned(ByteArrayOutputStream baos) {
        try {
            baos.write(this.txtype);
            baos.write(this.version);
            if(this.txtype == TransactionType.ContractTransaction) {

            } else if(this.txtype == TransactionType.InvocationTransaction) {
                this.extdata.Serialize(this, baos);
            } else {
                throw new Exception("runtime error: tx type error");
            }

            int length = 0;
            if(this.attributes != null) {
                length = this.attributes.size();
            }

            VarInt varLength = new VarInt(length);
            byte[] lenBytes = varLength.encode();
            baos.write(lenBytes);

            for(int i = 0; i < length; i++) {
                byte[] attriData = this.attributes.get(i).getData();
                byte usage = this.attributes.get(i).getUsage();

                if (usage == AttributeType.ContractHash || usage == AttributeType.Vote || (usage >= AttributeType.Hash1 && usage <= AttributeType.Hash15)) {
                    baos.write(attriData, 0, 32);
                } else if (usage == AttributeType.ECDH02 || usage == AttributeType.ECDH03) {
                    baos.write(attriData, 1, 32);
                } else if (usage == AttributeType.Script) {
                    baos.write(attriData, 0, 20);
                } else if (usage == AttributeType.DescriptionUrl) {
                    int len = attriData.length;
                    baos.write((byte)len);
                    baos.write(attriData, 0, len);
                } else if (usage == AttributeType.Description || usage >= AttributeType.Remark) {
                    int len = attriData.length;
                    VarInt varLen = new VarInt(len);
                    byte[] lenBytes2 = varLen.encode();
                    baos.write(lenBytes2);
                    baos.write(attriData, 0, len);
                } else {
                    throw new Exception("runtime error: attribute type error");
                }
            }

            int countInputs = this.inputs.size();
            VarInt varInputs = new VarInt(countInputs);
            byte[] lenInputs = varInputs.encode();
            baos.write(lenBytes);

            for(int i = 0; i < countInputs; i++) {
                TransactionInput input = this.inputs.get(i);
                baos.write(input.getHash());
                byte[] indexBytes = new byte[2];
                Utils.uint16ToByteArrayLE(input.getIndex(), indexBytes, 0);
                baos.write(indexBytes);
            }

            int countOutputs = this.outputs.size();
            VarInt varOutputs = new VarInt(countOutputs);
            byte[] lenOutputs = varOutputs.encode();
            baos.write(lenOutputs);

            for(int i = 0; i < countOutputs; i++) {
                TransactionOutput output = this.outputs.get(i);
                baos.write(output.getAssetId());
                Utils.int64ToByteStreamLE(output.getValue().getValue(), baos);
                baos.write(output.getToAddress());
            }

        }catch (Exception e) {
            e.printStackTrace();
            return false;
        }

        return true;
    }

    public boolean serialize(ByteArrayOutputStream baos) {
        this.serializeUnsigned(baos);

        try {
            int length = this.witnesses.size();
            VarInt varLength = new VarInt(length);
            byte[] lenBytes = varLength.encode();
            baos.write(lenBytes);

            for(int i = 0; i < length; i++) {
                Witness witness = this.witnesses.get(i);

                int invLength = witness.getInvocationScript().length;
                VarInt varInv = new VarInt(invLength);
                byte[] invBytes = varInv.encode();
                baos.write(invBytes);
                baos.write(witness.getInvocationScript());

                int verLength = witness.getVerificationScript().length;
                VarInt varVer = new VarInt(verLength);
                byte[] verBytes = varVer.encode();
                baos.write(verBytes);
                baos.write(witness.getVerificationScript());
            }
        }catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public boolean deserialize(ByteArrayInputStream bais) {
        this.txtype = (byte)bais.read();
        this.version = (byte)bais.read();

        try {
            if (this.txtype == TransactionType.ContractTransaction) {
                this.extdata = null;
            } else if (this.txtype == TransactionType.InvocationTransaction) {
                this.extdata = new InvokeTransData();
            } else {
                throw new Exception("runtime error: tx type error");
            }

            if(this.extdata != null) {
                this.extdata.Deserialize(this, bais);
            }

            int countAttri = Helper.ReadVarInt(bais);
            if(countAttri > 0) {
                this.attributes = new ArrayList<Attribute>();
            }

            for(int i = 0; i < countAttri; i++) {
                byte usage = (byte)bais.read();
                Attribute attribute = new Attribute();
                this.attributes.add(attribute);
                attribute.setUsage(usage);

                if(usage == AttributeType.ContractHash || usage == AttributeType.Vote || (usage >= AttributeType.Hash1 && usage <= AttributeType.Hash15)) {
                    byte[] attriData = new byte[32];
                    bais.read(attriData);
                    attribute.setData(attriData);
                } else if(usage == AttributeType.ECDH02 || usage == AttributeType.ECDH03) {
                    byte[] attriData = new byte[33];
                    attriData[0] = usage;
                    bais.read(attriData, 1, 32);
                    attribute.setData(attriData);
                } else if(usage == AttributeType.Script) {
                    byte[] attriData = new byte[20];
                    bais.read(attriData);
                    attribute.setData(attriData);
                } else if(usage == AttributeType.DescriptionUrl) {
                    byte length = (byte)bais.read();
                    byte[] attriData = new byte[length];
                    bais.read(attriData);
                    attribute.setData(attriData);
                } else if(usage == AttributeType.Description || usage >= AttributeType.Remark) {
                    byte length = (byte)Helper.ReadVarInt(bais);
                    byte[] attriData = new byte[length];
                    bais.read(attriData);
                    attribute.setData(attriData);
                } else {
                    throw new Exception("runtime error: attribute type error");
                }
            }

            int countInputs = Helper.ReadVarInt(bais);
            if(countInputs > 0) {
                this.inputs = new ArrayList<TransactionInput>();
            }

            for(int i = 0; i < countInputs; i++) {
                TransactionInput input = new TransactionInput();
                this.inputs.add(input);
                byte[] hash = new byte[32];
                bais.read(hash);
                input.setHash(hash);

                byte[] indexBytes = new byte[2];
                bais.read(indexBytes);
                short index = (short)Utils.readUint16(indexBytes, 0);
                input.setIndex(index);
            }

            int countOutputs = Helper.ReadVarInt(bais);
            if(countOutputs > 0) {
                this.outputs = new ArrayList<TransactionOutput>();
            }

            for(int i = 0; i < countOutputs; i++) {
                TransactionOutput output = new TransactionOutput();
                this.outputs.add(output);
                byte[] assetId = new byte[32];
                bais.read(assetId);
                output.setAssetId(assetId);
                byte[] valueBytes = new byte[8];
                bais.read(valueBytes);
                long value = Utils.readInt64(valueBytes, 0);
                Fixed8 num = new Fixed8();
                num.setValue(value);
                output.setValue(num);
                byte[] toAddrss = new byte[20];
                output.setToAddress(toAddrss);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return true;
    }
}
