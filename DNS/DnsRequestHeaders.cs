using static System.Buffers.Binary.BinaryPrimitives;

namespace DNS.DnsPacket;

public record DnsRequestHeaders(
    ushort Id,
    DnsFlags Flags,
    ushort QuestionCount,
    ushort AnswersCount,
    ushort AuthoritySectionCount,
    ushort AdditionalRecordSecCount)
{
    public static DnsRequestHeaders Parse(byte[] datagram)
    {
        var id = (ushort)ReadInt16BigEndian(new Span<byte>(datagram, 0, 2));
        var rawFlags = ReadInt16BigEndian(new Span<byte>(datagram, 2, 2));
        var flags = DnsFlags.Parse(rawFlags);
        var queryCount = (ushort)ReadInt16BigEndian(new Span<byte>(datagram, 4, 2));
        var answerCount = (ushort)ReadInt16BigEndian(new Span<byte>(datagram, 6, 2));
        var authSecCount = (ushort)ReadInt16BigEndian(new Span<byte>(datagram, 8, 2));
        var additRecSecCount = (ushort)ReadInt16BigEndian(new Span<byte>(datagram, 10, 2));

        return new DnsRequestHeaders(id, flags,
            queryCount, answerCount,
            authSecCount, additRecSecCount);
    }

    public byte[] GetBytes()
    {
        return Id.GetBytes()
            .Concat(Flags.FlagsBytes.GetBytes())
            .Concat(QuestionCount.GetBytes())
            .Concat(AnswersCount.GetBytes())
            .Concat(AuthoritySectionCount.GetBytes())
            .Concat(AdditionalRecordSecCount.GetBytes()).ToArray();
    }
}