package neo;

public final class TransactionType {
    public static final byte MinerTransaction = 0x00;
    public static final byte IssueTransaction = 0x01;
    public static final byte ClaimTransaction = 0x02;
    public static final byte EnrollmentTransaction = 0x20;
    public static final byte RegisterTransaction = 0x40;
    public static final byte ContractTransaction = (byte)0x80;
    public static final byte PublishTransaction = (byte)0xd0;
    public static final byte InvocationTransaction = (byte)0xd1;
}
