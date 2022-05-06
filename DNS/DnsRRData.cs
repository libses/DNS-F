using static System.Buffers.Binary.BinaryPrimitives;

namespace DNS.DnsPacket;

// ReSharper disable InconsistentNaming
public record DnsRRData(
    IReadOnlyList<string> Name,
    Query Type,
    ushort Class,
    int TTL,
    ushort RDLength,
    byte[] RData,
    DateTime Created,
    int ReadBytes)
{
    public bool IsValidData => Created + TimeSpan.FromSeconds(TTL) > DateTime.Now;

    public static unsafe DnsRRData Parse(byte* pointer, byte* startDatagram)
    {
        var name = ByteExtensions.ParseName(pointer, startDatagram);
        pointer += name.readLen;
        var type = (Query)ReadInt16BigEndian(new Span<byte>(pointer, 2));
        pointer += 2;
        var cls = (ushort)ReadInt16BigEndian(new Span<byte>(pointer, 2));
        pointer += 2;
        var ttl = ReadInt32BigEndian(new Span<byte>(pointer, 4));
        pointer += 4;
        var dataLen = (ushort)ReadInt16BigEndian(new Span<byte>(pointer, 2));
        pointer += 2;
        var data = new Span<byte>(pointer, dataLen);

        return new DnsRRData(name.name, type, cls, ttl, dataLen, data.ToArray(), DateTime.Now,
            10 + name.readLen + dataLen);
    }

    public byte[] GetBytes()
    {
        var ttl = new byte[4];
        WriteInt32BigEndian(ttl, TTL);
        return Name.SelectMany(x => x.ToCharArray().Select(x => (byte)x).Prepend((byte)x.Length)).Append((byte)0)
            .Concat(((ushort)Type).GetBytes())
            .Concat(Class.GetBytes())
            .Concat(ttl)
            .Concat(RDLength.GetBytes())
            .Concat(RData)
            .ToArray();
    }
}