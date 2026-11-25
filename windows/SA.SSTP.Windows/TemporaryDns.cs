using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace SaSstp;

internal sealed class TemporaryDns : IDisposable
{
    static readonly string Hosts = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"System32","drivers","etc","hosts");
    static string OwnerTag()
    {
        using var id=WindowsIdentity.GetCurrent();
        var sid=id.User?.Value??throw new InvalidOperationException("Windows user SID unavailable");
        return "SA-SSTP-TEMP-"+Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sid))).Substring(0,16)+"-";
    }
    [DllImport("dnsapi.dll",SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    static extern bool DnsFlushResolverCache();
    static void Flush()
    {
        if(!DnsFlushResolverCache())throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(),"تعذر تحديث ذاكرة DNS");
    }
    public static bool IsAdmin()
    {
        using var id=WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }
    static string HostName(string value)
    {
        if(value.Length>253||!Regex.IsMatch(value,@"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"))
            throw new ArgumentException("اسم DNS غير صالح للربط المؤقت.");
        return value.ToLowerInvariant();
    }
    static IPAddress Address(string value)
    {
        if(!IPAddress.TryParse(value,out var ip)||value.Contains('%')||IPAddress.IsLoopback(ip)||ip.Equals(IPAddress.Any)||ip.Equals(IPAddress.IPv6Any))
            throw new ArgumentException("عنوان IP للربط المؤقت غير صالح.");
        return ip;
    }
    static async Task<IPAddress[]> Resolve(string host)
    {
        try{return await Dns.GetHostAddressesAsync(host).WaitAsync(TimeSpan.FromSeconds(8));}
        catch(SocketException){return Array.Empty<IPAddress>();}
        catch(TimeoutException){return Array.Empty<IPAddress>();}
    }
    public static async Task<bool> NeedsMapping(Profile p)
    {
        var resolved=await Resolve(p.Host);
        if(string.IsNullOrWhiteSpace(p.Ip))
        {
            if(resolved.Length==0)throw new InvalidOperationException("تعذر DNS ولا يوجد عنوان IP محفوظ لهذا السيرفر.");
            return false;
        }
        var wanted=Address(p.Ip);
        return resolved.Length==0||resolved.Any(ip=>!ip.Equals(wanted));
    }
    static byte[] Read(FileStream f)
    {
        if(f.Length>4_000_000)throw new IOException("ملف hosts كبير بشكل غير متوقع.");
        f.Position=0;using var ms=new MemoryStream();f.CopyTo(ms);return ms.ToArray();
    }
    static FileStream Open(string path)=>new FileStream(path,FileMode.Open,FileAccess.ReadWrite,FileShare.Read);
    static void Write(FileStream f,byte[] b){f.Position=0;f.Write(b);f.SetLength(b.Length);f.Flush(true);}
    static bool ExistingConflict(string text,string host,IPAddress ip)
    {
        foreach(var line in text.Split('\n'))
        {
            var parts=line.Split('#',2)[0].Split((char[]?)null,StringSplitOptions.RemoveEmptyEntries);
            if(parts.Length<2||!parts.Skip(1).Any(x=>x.Equals(host,StringComparison.OrdinalIgnoreCase)))continue;
            if(!IPAddress.TryParse(parts[0],out var existing)||!existing.Equals(ip))return true;
        }
        return false;
    }
    // Latin-1 gives a reversible byte-to-character mapping. Existing bytes are preserved.
    static byte[] RemoveMarker(byte[] bytes,string tag,bool prefix)
    {
        var s=Encoding.Latin1.GetString(bytes);
        var marker=Regex.Escape(tag)+(prefix?"[A-F0-9]{32}":"");
        var pattern=@"(?m)^[ \t]*[0-9A-Fa-f:.]+[ \t]+[A-Za-z0-9.-]+[ \t]+#[ \t]*"+marker+@"[ \t]*(?:\r?\n|$)";
        return Encoding.Latin1.GetBytes(Regex.Replace(s,pattern,""));
    }
    readonly string marker;
    readonly byte[] suffix;
    bool disposed;
    TemporaryDns(string tag,byte[] added){marker=tag;suffix=added;}
    public static async Task<TemporaryDns> Create(Profile p)
    {
        if(!IsAdmin())throw new UnauthorizedAccessException("الربط المؤقت يحتاج صلاحيات المسؤول.");
        string host=HostName(p.Host);
        var ip=Address(p.Ip);
        string marker=OwnerTag()+Guid.NewGuid().ToString("N").ToUpperInvariant();
        byte[] added;
        using(var f=Open(Hosts))
        {
            var original=Read(f);
            // Refuse UTF-16 or binary hosts files rather than corrupt them.
            if(original.Contains((byte)0))throw new IOException("ترميز ملف hosts غير مدعوم.");
            if(ExistingConflict(Encoding.Latin1.GetString(original),host,ip))
                throw new IOException("يوجد ربط مختلف لهذا النطاق في hosts. لن يغيّر البرنامج سطرًا موجودًا مسبقاً.");
            string prefix=original.Length>0&&original[^1]!=(byte)'\n'?"\r\n":"";
            added=Encoding.ASCII.GetBytes(prefix+ip+"\t"+host+" # "+marker+"\r\n");
            f.Position=f.Length;
            f.Write(added);f.Flush(true);
        }
        var scope=new TemporaryDns(marker,added);
        try
        {
            Flush();
            var result=await Resolve(host);
            if(result.Length==0||result.Any(x=>!x.Equals(ip)))throw new IOException("لم يؤكد Windows ربط اسم السيرفر بعنوان IP المطلوب.");
            return scope;
        }
        catch{scope.Dispose();throw;}
    }
    public void Dispose()
    {
        if(disposed)return;
        using(var f=Open(Hosts))
        {
            var old=Read(f);
            // Restore exact original bytes if the appended suffix is still at the end.
            // Otherwise remove only our uniquely marked line, preserving unrelated edits.
            byte[] next=old.AsSpan().EndsWith(suffix)?old[..(old.Length-suffix.Length)]:RemoveMarker(old,marker,false);
            if(!old.AsSpan().SequenceEqual(next))Write(f,next);
        }
        disposed=true;Flush();
    }
    public static void Recover()
    {
        // Program's per-user mutex is held: this removes only stale lines from this account.
        bool changed=false;
        using(var f=Open(Hosts))
        {
            var old=Read(f);
            if(old.Contains((byte)0))return;
            var next=RemoveMarker(old,OwnerTag(),true);
            if(!old.AsSpan().SequenceEqual(next)){Write(f,next);changed=true;}
        }
        if(changed)Flush();
    }
    public static int SelfTest()
    {
        try
        {
            const string tag="SA-SSTP-TEMP-1234567890ABCDEF-0123456789ABCDEF0123456789ABCDEF";
            byte[] before=Encoding.Latin1.GetBytes("# original\r\n127.0.0.1 localhost\r\n");
            byte[] line=Encoding.ASCII.GetBytes("192.0.2.4\ttest.example.com # "+tag+"\r\n");
            byte[] after=before.Concat(line).Concat(Encoding.ASCII.GetBytes("192.0.2.5 other.example.com\r\n")).ToArray();
            var expected=before.Concat(Encoding.ASCII.GetBytes("192.0.2.5 other.example.com\r\n")).ToArray();
            if(!RemoveMarker(after,tag,false).SequenceEqual(expected))return 2;
            if(!RemoveMarker(after,"SA-SSTP-TEMP-1234567890ABCDEF-",true).SequenceEqual(expected))return 3;
            if(!ExistingConflict("192.0.2.1 test.example.com # custom","test.example.com",IPAddress.Parse("192.0.2.4")))return 4;
            if(ExistingConflict("192.0.2.4 test.example.com","test.example.com",IPAddress.Parse("192.0.2.4")))return 5;
            try{HostName("test.example.com\r\nbad");return 6;}catch(ArgumentException){}
            return 0;
        }catch{return 7;}
    }
}
