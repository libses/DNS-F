using DNS.Server;

namespace DNS;

internal static class Program
{
    public static void Main()
    {
        new DnsServer().Enable();
    }
}