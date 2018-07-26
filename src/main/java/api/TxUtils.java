package api;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import core.Utils;
import neo.ScriptBuilder;

import java.math.BigInteger;

public class TxUtils {
    public static byte[] makeNep5Transfer(String scriptAddress, String from, String to, BigInteger value) {
        byte[] assetId = Utils.hexStringToBytes(scriptAddress);
        assetId = Utils.reverseBytes(assetId);

        String fromParam = "(address)" + from;
        JsonObject fromJson = new JsonObject();
        fromJson.addProperty("from", fromParam);

        String toParam = "(address)" + to;
        JsonObject toJson = new JsonObject();
        toJson.addProperty("to", toParam);

        String numParam = "(integer)" + value.toString();
        JsonObject numJson = new JsonObject();
        numJson.addProperty("num", numParam);

        JsonArray jsonArray = new JsonArray();
        jsonArray.add(fromJson);
        jsonArray.add(toJson);
        jsonArray.add(numParam);

        ScriptBuilder scriptBuilder = new ScriptBuilder();
        scriptBuilder.EmitParamJson(jsonArray);
        scriptBuilder.EmitPushString("transfer");
        try {
            scriptBuilder.EmitAppCall(assetId, false);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return scriptBuilder.toBytes();
    }
}
