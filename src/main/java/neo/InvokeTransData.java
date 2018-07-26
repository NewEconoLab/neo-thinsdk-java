package neo;

import core.Utils;
import core.VarInt;
import lombok.Data;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

@Data
public class InvokeTransData implements IExtData  {
    public void Serialize(Transaction tx, ByteArrayOutputStream baos) {
        int length = this.script.length;
        VarInt varLength = new VarInt(length);

        try {
            byte[] lenBytes = varLength.encode();
            baos.write(lenBytes);
            baos.write(this.script);

            if(tx.getVersion() >= 1) {
                Utils.int64ToByteStreamLE(gas.getValue(), baos);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void Deserialize(Transaction tx, ByteArrayInputStream bais) {
        VarInt varInt = null;
        try {
            varInt = new VarInt(bais);

            int length = (int) varInt.value;
            byte[] data = new byte[length];
            bais.read(data);
            this.script = data;

            if (tx.getVersion() >= 1) {
                byte[] value = new byte[8];
                bais.read(value);
                long lvalue = Utils.readUint32(value, 0) | (Utils.readUint32(value, 4) << 32);
                this.gas.setValue(lvalue);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private byte[] script;
    private Fixed8 gas;
}
