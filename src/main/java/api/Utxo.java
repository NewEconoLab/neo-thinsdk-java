package api;

import lombok.Data;

@Data
public class Utxo {
    private String hash;
    private long value;
    private short n;
}
