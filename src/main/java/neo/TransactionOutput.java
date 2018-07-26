package neo;

import lombok.Data;

@Data
public class TransactionOutput {
    private byte[] assetId;
    private Fixed8 value;
    private byte[] toAddress;
}
