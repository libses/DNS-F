using System.Collections.Concurrent;
using DNS.DnsPacket;
using Newtonsoft.Json;

namespace DNS.Cache;

[JsonObject(MemberSerialization.OptIn)]
public class DnsCache : IDisposable
{
    [JsonProperty] private readonly ConcurrentDictionary<string, DnsCacheEntry> dictionary = new ConcurrentDictionary<string, DnsCacheEntry>();
    [JsonIgnore] private bool isDisposed;

    public static DnsCache Load()
    {
        var ser = new JsonSerializer();
        using var fileStream = File.Open("cache.json", FileMode.OpenOrCreate);
        using var jsonStream = new JsonTextReader(new StreamReader(fileStream));
        var result = ser.Deserialize<DnsCache>(jsonStream);
        result?.Clean();
        return result ?? new DnsCache();
    }

    public void AddData(IReadOnlyList<string> name, DnsRRData data)
    {
        var key = string.Concat(name);
        if (!dictionary.ContainsKey(key))
        {
            dictionary[key] = new DnsCacheEntry(DateTime.Now, name, new HashSet<DnsRRData>());
        }

        dictionary[key].RRRecords.Add(data);
    }

    public void AddData(IReadOnlyList<string> name, IEnumerable<DnsRRData> data)
    {
        var key = string.Concat(name);
        if (!dictionary.ContainsKey(key))
        {
            dictionary[key] = new DnsCacheEntry(DateTime.Now, name, new HashSet<DnsRRData>());
        }

        dictionary[key].RRRecords.UnionWith(data);
    }


    public bool Contains(IReadOnlyList<string> name, Query queryType)
    {
        var key = string.Concat(name);
        return dictionary.ContainsKey(key) && dictionary[key].RRRecords.Any(x => x.Type == queryType);
    }

    public IReadOnlyList<DnsRRData> Get(IReadOnlyList<string> name, Query queryType) =>
        dictionary[string.Concat(name)].RRRecords.Where(x => x.Type == queryType).ToArray();

    public void Dispose()
    {
        if (isDisposed) return;
        isDisposed = true;
        using var fileStream = File.Open("./cache.json", FileMode.OpenOrCreate);
        using var textWriter = new StreamWriter(fileStream);
        using var jsonWriter = new JsonTextWriter(textWriter);
        new JsonSerializer().Serialize(jsonWriter, this);
    }

    public void Clean()
    {
        foreach (var pair in dictionary)
        {
            pair.Value.RRRecords.RemoveWhere(x => !x.IsValidData);
            if (pair.Value.RRRecords.Count == 0) dictionary.TryRemove(pair.Key, out var a);
        }
    }
}

public record DnsCacheEntry(DateTime Created, IReadOnlyList<string> Name, HashSet<DnsRRData> RRRecords);