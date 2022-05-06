using System.Text;
using static System.Buffers.Binary.BinaryPrimitives;

namespace DNS.DnsPacket;

public static unsafe class ByteExtensions
{
    private const byte MarkTypeMask = 0b11000000;
    private const byte LinkMask = 0b00111111;

    public static (IReadOnlyList<string> name, int readLen) ParseName(byte* pt, byte* startDatagram)
    {
        var res = new List<string>();
        var rl = 1;
        while (true)
        {
            var mark = *pt & MarkTypeMask;
            if (mark == 0)
            {
                var ct = *pt;
                if (ct == 0) return (res.ToArray(), rl);
                res.Add(Encoding.ASCII.GetString(++pt, ct));
                rl += 1 + ct;
                pt += ct;
                continue;
            }
            else if (mark == 192)
            {
                var offset = (ushort)ReadInt16BigEndian(new[] { (byte)(*pt & LinkMask), *++pt });
                rl++;
                var ptr = startDatagram + offset;
                var (name, readLen) = ParseName(ptr, startDatagram);
                res.AddRange(name);
                return (res, rl);
            }
            else
            {
                throw new ArgumentException();
            }
        }
    }

    public static byte[] GetBytes(this ushort n)
    {
        return BitConverter.IsLittleEndian ? BitConverter.GetBytes(n).Reverse().ToArray() : BitConverter.GetBytes(n).ToArray();
    }
}