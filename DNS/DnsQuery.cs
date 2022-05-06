namespace DNS.DnsPacket;

using static System.Buffers.Binary.BinaryPrimitives;

public record DnsQuery(IReadOnlyList<string> Name, Query Type, ushort Class, int ReadBytes)
{
    public static unsafe DnsQuery Parse(byte* pointer, byte* startDatagram)
    {
        var name = ByteExtensions.ParseName(pointer, startDatagram);
        pointer += name.readLen;
        var type = (Query)ReadInt16BigEndian(new Span<byte>(pointer, 2));
        pointer += 2;
        var cls = (ushort)ReadInt16BigEndian(new Span<byte>(pointer, 2));

        return new DnsQuery(name.name, type, cls, 4 + name.readLen);
    }

    public byte[] GetBytes()
    {
        return Name.SelectMany(x => x.ToCharArray().Select(x => (byte)x).Prepend((byte)x.Length)).Append((byte)0)
            .Concat(((ushort)Type).GetBytes()).Concat(Class.GetBytes()).ToArray();
    }
}

public enum Query : ushort
{
    A = 1,
    AAAA = 28,
    NS = 2,
    PTR = 12,
}