package neo;

import core.Utils;
import lombok.Data;

@Data
public class Witness {
    private byte[] InvocationScript;
    private byte[] VerificationScript;

    public String getAddress() {
        byte[] hash = Helper.getScriptHashFromScript(this.VerificationScript);
        String address = Helper.getAddressFromScriptHash(hash);
        return address;
    }

    public String getHashStr() {
        byte[] hash = Helper.getScriptHashFromScript(this.VerificationScript);
        return Utils.bytesToHexString(hash);
    }

    public boolean issSmartContract() {
        if(this.VerificationScript.length != 35) {
            return true;
        }
        if(this.VerificationScript[0] != this.VerificationScript.length - 2) {
            return true;
        }
        if(this.VerificationScript[this.VerificationScript.length - 1] != 0xac) {
            return true;
        }
        return false;
    }
}
