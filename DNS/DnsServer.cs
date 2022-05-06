using DNS.Cache;
using DNS.DnsPacket;
using System.Net;
using System.Net.Sockets;
using Timer = System.Timers.Timer;

namespace DNS.Server;

public class DnsServer : IDisposable
{
    private const int Port = 53;
    private const int SocketBufferSize = 512;
    private static readonly IPAddress Ip = new(new byte[] { 127, 0, 0, 1 });
    private static readonly IPEndPoint ThirdPartyDNS = new(new IPAddress(new byte[] { 8, 8, 8, 8 }), 53);
    private readonly Socket server = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    private readonly Socket client = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    private readonly DnsCache cache = DnsCache.Load();
    private readonly Timer cacheTimer = new(60000);
    private bool isDisposed;

    public DnsServer()
    {
        server.Bind(new IPEndPoint(Ip, Port));
        cacheTimer.Elapsed += (_, _) =>
        {
            Task.Run(cache.Clean);
        };
        cacheTimer.Start();
        cacheTimer.AutoReset = true;
    }

    public void Enable()
    {
        Task.Run(() =>
        {
            while (!isDisposed)
            {
                var data = new byte[SocketBufferSize];
                EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
                server.ReceiveFrom(data, ref remoteEndPoint);
                HandleRequest(data, remoteEndPoint);
            }
        });
        Console.WriteLine("run");
        while (Console.ReadLine()?.ToLower() is not "exit")
        {
        }

        Dispose();
    }

    public void Dispose()
    {
        if (isDisposed) return;
        Console.WriteLine("close");
        isDisposed = true;
        server.Dispose();
        client.Dispose();
        cache.Dispose();
        cacheTimer.Close();
    }

    private void HandleRequest(byte[] datagram, EndPoint remoteEndPoint)
    {
        var request = DnsRequest.Parse(datagram);

        if (request.Type == QR.REQUEST)
        {
            if (cache.Contains(request.Queries[0].Name, request.Queries[0].Type))
            {
                SendFromCache(remoteEndPoint, request);
                return;
            }

            client.SendTo(datagram, ThirdPartyDNS);
            var buffer = new byte[SocketBufferSize];
            client.Receive(buffer);
            var ma = DnsRequest.Parse(buffer);
            cache.AddData(ma.Queries[0].Name, ma.RData);
            server.SendTo(ma.GetBytes(), remoteEndPoint);
        }
    }

    private void SendFromCache(EndPoint remoteEndPoint, DnsRequest m)
    {
        var rr = cache.Get(m.Queries[0].Name, m.Queries[0].Type);
        var answers = rr.Where(x => x.Type is Query.A or Query.AAAA);
        var aus = rr.Where(x => x.Type is Query.NS);
        var ars = rr.Where(x => x.Type is Query.PTR);
        var arr = answers.Concat(aus).Concat(ars);

        var mes = new DnsRequest(m.Headers with
        {
            Flags = m.Headers.Flags with
            {
                Type = QR.RESPONSE,
                Bits = DnsHeadresBits.RA | m.Headers.Flags.Bits
            },
            AnswersCount = (ushort)answers.Count(),
            AuthoritySectionCount = (ushort)aus.Count(),
            AdditionalRecordSecCount = (ushort)ars.Count()
        }, m.Queries, arr.ToArray());
        server.SendTo(mes.GetBytes(), remoteEndPoint);
    }
}
