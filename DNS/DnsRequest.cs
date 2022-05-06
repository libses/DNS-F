namespace DNS.DnsPacket;

public class DnsRequest
{
    public readonly DnsRequestHeaders Headers;
    public readonly IReadOnlyList<DnsQuery> Queries;
    public readonly IReadOnlyList<DnsRRData> RData;

    public QR Type => Headers.Flags.Type;

    public DnsRequest(DnsRequestHeaders headers, IReadOnlyList<DnsQuery> queries, IReadOnlyList<DnsRRData> rData)
    {
        Headers = headers;
        Queries = queries;
        RData = rData;
    }

    public static unsafe DnsRequest Parse(byte[] datagram)
    {
        var headers = DnsRequestHeaders.Parse(datagram);
        var index = 12;
        var queries = new List<DnsQuery>();
        var answers = new List<DnsRRData>();
        fixed (byte* start = datagram)
        {
            var ptr = start + index;
            for (var i = 0; i < headers.QuestionCount; i++)
            {
                var query = DnsQuery.Parse(ptr, start);
                ptr += query.ReadBytes;
                queries.Add(query);
            }

            var rrCount = headers.AnswersCount + headers.AuthoritySectionCount + headers.AdditionalRecordSecCount;

            for (var i = 0; i < rrCount; i++)
            {
                var rr = DnsRRData.Parse(ptr, start);
                ptr += rr.ReadBytes;
                answers.Add(rr);
            }
        }

        return new DnsRequest(headers, queries, answers);
    }

    public byte[] GetBytes()
    {
        return Headers.GetBytes().Concat(Queries.SelectMany(x => x.GetBytes())).Concat(RData.SelectMany(x => x.GetBytes())).ToArray();
    }
}