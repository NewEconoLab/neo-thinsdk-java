package neo;


import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import core.Utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.Set;

public class ScriptBuilder {
    private ByteArrayOutputStream baos = new ByteArrayOutputStream();

    public byte[] toBytes() {
        return baos.toByteArray();
    }

    public ScriptBuilder Emit(byte opcode, byte[] arg) {
        this.baos.write(opcode);
        if(arg != null && arg.length > 0) {
            try {
                this.baos.write(arg);
            }
            catch (IOException e) {
                e.printStackTrace();
            }
        }
        return this;
    }

    public ScriptBuilder EmitAppCall(byte[] scriptHash, boolean useTailCall) throws Exception{
        if(scriptHash.length != 20) {
            throw new Exception("runtime error: script hash length error");
        }
        byte opcode = OpCode.TAILCALL;
        if(!useTailCall) {
            opcode = OpCode.APPCALL;
        }
        this.Emit(opcode, scriptHash);
        return this;
    }

    public ScriptBuilder EmitJump(byte opcode, short offset) throws Exception {
        if(opcode != OpCode.JMP && opcode != OpCode.JMPIF && opcode != OpCode.JMPIFNOT && opcode != OpCode.CALL) {
            throw new Exception("runtime error: opcode error");
        }
        return this;
    }

    public ScriptBuilder EmitPushNumber(BigInteger number) {
        BigInteger minusOne = new BigInteger("-1");
        if(number.compareTo(minusOne) == 0) {
            this.Emit(OpCode.PUSHM1, null);
            return this;
        }

        BigInteger zero = new BigInteger("0");
        if(number.compareTo(zero) == 0) {
            this.Emit(OpCode.PUSH0, null);
            return this;
        }

        BigInteger sixteen = new BigInteger("16");
        if(number.compareTo(zero) == 1 && number.compareTo(sixteen) == -1) {
            byte opcode = (byte) (OpCode.PUSH1 - 1 + (byte)number.longValue());
            this.Emit(opcode, null);
            return this;
        }
        this.EmitPushBytes(number.toByteArray());
        return this;
    }

    public ScriptBuilder EmitPushBool(boolean b) {
        if (b) {
            this.Emit(OpCode.PUSHT, null);
        } else {
            this.Emit(OpCode.PUSHF, null);
        }
        return this;
    }

    public ScriptBuilder EmitPushBytes(byte[] bytes) {
        int length = bytes.length;

        try {
            if (length <= OpCode.PUSHBYTES75) {
                this.baos.write((byte) length);
                this.baos.write(bytes);
            } else if (length < 0x100) {
                this.Emit(OpCode.PUSHDATA1, null);
                this.baos.write((byte)length);
                this.baos.write(bytes);
            } else if (length < 0x10000) {
                this.Emit(OpCode.PUSHDATA2, null);
                byte[] lenBytes = new byte[2];
                Utils.uint16ToByteArrayLE((short)length, lenBytes, 0);
                this.baos.write(lenBytes);
                this.baos.write(bytes);
            } else {
                this.Emit(OpCode.PUSHDATA4, null);
                byte[] lenBytes = new byte[4];
                Utils.uint32ToByteArrayLE(length, lenBytes, 0);
                this.baos.write(lenBytes);
                this.baos.write(bytes);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return this;
    }

    public ScriptBuilder EmitPushString(String data) {
        this.EmitPushBytes(data.getBytes());
        return this;
    }

    public ScriptBuilder EmitSysCall(String api) throws Exception {
        byte[] hexdata = api.getBytes();
        int length = hexdata.length;
        if (length <= 0 || length > 252) {
            throw new Exception("runtime error: api length error");
        }

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        os.write((byte)length);
        os.write(hexdata);
        this.Emit(OpCode.SYSCALL, os.toByteArray());

        return this;
    }

    private boolean getParamBytes(ByteArrayOutputStream os, String str) throws Exception {
        byte[] bytes = str.getBytes();
        if(bytes[0] != '(') {
            return false;
        }
        int length = bytes.length;

        String strData = "";
        if(str.indexOf("(str)") == 0) {
            strData = str.substring(5);
            os.write(strData.getBytes());
        } else if(str.indexOf("(string)") == 0) {
            strData = str.substring(8);
            os.write(strData.getBytes());
        } else if(str.indexOf("(bytes)") == 0) {
            strData = str.substring(7);
            byte[] data = Utils.hexStringToBytes(strData);
            os.write(data);
        } else if(str.indexOf("([])") == 0) {
            strData = str.substring(4);
            byte[] data = Utils.hexStringToBytes(strData);
            os.write(data);
        } else if(str.indexOf("(address)") == 0) {
            strData = str.substring(9);
            byte[] pubHash = Helper.getPublicKeyHashFromAddress(strData);
            os.write(pubHash);
        } else if(str.indexOf("(addr)") == 0) {
            strData = str.substring(6);
            byte[] pubHash = Helper.getPublicKeyHashFromAddress(strData);
            os.write(pubHash);
        } else if(str.indexOf("(integer)") == 0) {
            strData = str.substring(9);
            BigInteger value = new BigInteger(strData);
            os.write(value.toByteArray());
        } else if(str.indexOf("(int)") == 0) {
            strData = str.substring(5);
            BigInteger value = new BigInteger(strData);
            os.write(value.toByteArray());
        } else if(str.indexOf("(hexinteger)") == 0) {
            strData = str.substring(12);
            byte[] data = Utils.hexStringToBytes(strData);
            os.write(data);
        } else if(str.indexOf("(hexint)") == 0) {
            strData = str.substring(8);
            byte[] data = Utils.hexStringToBytes(strData);
            os.write(data);
        } else if(str.indexOf("(hex)") == 0) {
            strData = str.substring(5);
            byte[] data = Utils.hexStringToBytes(strData);
            os.write(data);
        } else if(str.indexOf("(hex256)") == 0 || str.indexOf("(int256)") == 0) {
            strData = str.substring(8);
            byte[] data = Utils.hexStringToBytes(strData);
            if(data.length != 32) {
                return false;
            }
            os.write(data);
        } else if(str.indexOf("(uint256)") == 0) {
            strData = str.substring(9);
            byte[] data = Utils.hexStringToBytes(strData);
            if(data.length != 32) {
                return false;
            }
            os.write(data);
        } else if(str.indexOf("(hex160)") == 0 || str.indexOf("(int160)") == 0) {
            strData = str.substring(8);
            byte[] data = Utils.hexStringToBytes(strData);
            if(data.length != 20) {
                return false;
            }
            os.write(data);
        } else if(str.indexOf("(uint160)") == 0) {
            strData = str.substring(9);
            byte[] data = Utils.hexStringToBytes(strData);
            if(data.length != 20) {
                return false;
            }
            os.write(data);
        } else {
            return false;
        }

        return true;
    }

    public ScriptBuilder EmitParamJson(JsonElement param) {
        if(param.isJsonPrimitive()) {
            JsonPrimitive jsonPrimitive = (JsonPrimitive) param;
            if(jsonPrimitive.isBoolean()) {
                this.EmitPushBool(jsonPrimitive.getAsBoolean());
            } else if(jsonPrimitive.isNumber()) {
                this.EmitPushNumber(jsonPrimitive.getAsBigInteger());
            } else if(jsonPrimitive.isString()) {
                ByteArrayOutputStream os = new ByteArrayOutputStream();
                byte[] data = null;
                try {
                    boolean ok = getParamBytes(os, jsonPrimitive.getAsString());
                    if(ok) {
                        data = os.toByteArray();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                if(data != null) {
                    this.EmitPushBytes(data);
                }

            }
        } else if (param.isJsonArray()) {
            JsonArray jsonArray = (JsonArray)param;
            for(int i = 0; i < jsonArray.size(); i++){
                JsonElement jsonElement = jsonArray.get(i);
                this.EmitParamJson(jsonElement);
            }
        } else if (param.isJsonObject()) {
            JsonObject jsonObject = (JsonObject) param;
            Set<String> set = jsonObject.keySet();
            Iterator<String> it = set.iterator();
            while (it.hasNext()) {
                String str = it.next();
                JsonElement jsonElement = jsonObject.get(str);
                this.EmitParamJson(jsonElement);
            }
            return this;
        }
        return this;
    }
}
