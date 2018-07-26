package api;

import lombok.Data;

import java.util.List;

@Data
public class CreateSignParams {
    private byte txType;
    private byte version;
    private String priKey;
    private String from;
    private String to;
    private String assetId;
    private long value;
    private byte[] data;
    private List<Utxo> utxos;
}
