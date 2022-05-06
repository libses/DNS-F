using static Medallion.Bits;


namespace DNS.DnsPacket;

public enum QR : ushort
{
    REQUEST = 0,
    RESPONSE = 0b1_000000000000000
}

[Flags]
public enum DnsHeadresBits : ushort
{
    EMPTY = 0,
    AA = QR.RESPONSE >> 5,
    TC = AA >> 1,
    RD = TC >> 1,
    RA = RD >> 1
}

public enum DnsOpcode : ushort
{
    STANDART_QUERY = 0,
    INVERSE_QUERY = QR.RESPONSE >> 4,
    SERVER_STATUS = QR.RESPONSE >> 3,
}

public enum DnsRCode : ushort
{
    NOERROR,
    FORMERROR,
    SERVFAIL,
    MXDOMAIN,
    NOTIMP,
    REFUSED,
    YXDOMAIN,
    XRRSET,
    NOTAUTH,
    NOTZONE
}

public record DnsFlags(QR Type, DnsHeadresBits Bits, DnsOpcode Opcode, DnsRCode RCode)
{
    private const ushort QRMasc = 0b1_0000_0000_000_0000;
    private const ushort OpcodeMasc = 0b0_1111_0000_000_0000;
    private const ushort FlagsMasc = 0b0_0000_1111_000_0000;
    private const ushort RCodeMasc = 0b0_0000_0000_000_1111;

    public ushort FlagsBytes => Or(Or((ushort)Bits, (ushort)Opcode), Or((ushort)Type, (ushort)RCode));

    public static DnsFlags Parse(short value)
    {
        var qr = (QR)(QRMasc & value);
        var opcode = (DnsOpcode)(value & OpcodeMasc);
        var flags = (DnsHeadresBits)(value & FlagsMasc);
        var rCode = (DnsRCode)(value & RCodeMasc);


        return new DnsFlags(qr, flags, opcode, rCode);
    }
}