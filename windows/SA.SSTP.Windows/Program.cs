using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Net;

namespace SaSstp;

internal sealed class Profile
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = "";
    public string Host { get; set; } = "";
    public string Ip { get; set; } = "";
    public int Port { get; set; } = 443;
    public string Region { get; set; } = "SA";
    public string Auth { get; set; } = "PAP";
    public bool Custom { get; set; }
    public bool Remember { get; set; } = true;
    public bool Reconnect { get; set; }
    public string Entry => "SA-SSTP-" + Id;
    public string Endpoint => Port == 443 ? Host : Host + ":" + Port;
    public override string ToString() => Name + "  |  " + Host + ":" + Port;
    public void Check()
    {
        if (!Regex.IsMatch(Id, @"^[A-Za-z0-9-]{1,64}$") || string.IsNullOrWhiteSpace(Name) || Name.Length > 80)
            throw new ArgumentException("اسم السيرفر أو معرّفه غير صالح.");
        if (Host.Length > 240 || Uri.CheckHostName(Host) != UriHostNameType.Dns || Host.Contains(':'))
            throw new ArgumentException("أدخل اسم نطاق DNS مطابق لشهادة السيرفر، دون رابط أو منفذ.");
        if (Ip.Length != 0 && !IPAddress.TryParse(Ip, out _)) throw new ArgumentException("عنوان IP المرجعي غير صالح.");
        if (Port is < 1 or > 65535 || Region is not ("SA" or "AE" or "OTHER") || Auth is not ("PAP" or "CHAP" or "MSChapv2"))
            throw new ArgumentException("المنفذ أو الدولة أو طريقة المصادقة غير صالحة.");
    }
}
internal sealed class Settings
{
    public string Selected { get; set; } = "SA46";
    public List<Profile> Profiles { get; set; } = new();
}
internal static class Store
{
    public static readonly string Dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"SA SSTP");
    public static readonly string PathName = Path.Combine(Dir,"profiles.json");
    public static readonly JsonSerializerOptions Json = new() { WriteIndented = true, PropertyNameCaseInsensitive = true };
    public static List<Profile> Catalog()
    {
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("SaSstp.Catalog") ?? throw new InvalidDataException("Missing catalog");
        var result = JsonSerializer.Deserialize<List<Profile>>(s, Json) ?? throw new InvalidDataException("Empty catalog");
        if (result.Count < 40 || result.Select(x=>x.Id).Distinct().Count()!=result.Count) throw new InvalidDataException("Invalid catalog");
        foreach(var p in result) p.Check();
        return result;
    }
    public static Settings Load(string path)
    {
        var st = File.Exists(path) ? JsonSerializer.Deserialize<Settings>(File.ReadAllText(path),Json) ?? throw new InvalidDataException("Invalid settings") : new Settings();
        if(st.Profiles==null || st.Profiles.Select(x=>x.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count()!=st.Profiles.Count) throw new InvalidDataException("Duplicate or invalid profiles");
        foreach(var p in st.Profiles) p.Check();
        var ids = st.Profiles.Select(x=>x.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach(var p in Catalog()) if(ids.Add(p.Id)) st.Profiles.Add(p);
        return st;
    }
    public static void Save(Settings st,string? path=null)
    {
        path ??= PathName;
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
        var tmp=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        try { File.WriteAllText(tmp,JsonSerializer.Serialize(st,Json),new UTF8Encoding(false)); File.Move(tmp,path,true); }
        finally { if(File.Exists(tmp)) File.Delete(tmp); }
    }
}
internal sealed record Login(string User,string Password);
internal static class Vault
{
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    private struct Credential
    {
        public uint Flags,Type;
        [MarshalAs(UnmanagedType.LPWStr)] public string? Target;
        [MarshalAs(UnmanagedType.LPWStr)] public string? Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint Size;
        public IntPtr Blob;
        public uint Persist,AttributeCount;
        public IntPtr Attributes;
        [MarshalAs(UnmanagedType.LPWStr)] public string? Alias;
        [MarshalAs(UnmanagedType.LPWStr)] public string? User;
    }
    [DllImport("advapi32.dll",EntryPoint="CredWriteW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool Write(ref Credential c,uint flags);
    [DllImport("advapi32.dll",EntryPoint="CredReadW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool Read(string name,uint type,uint flags,out IntPtr c);
    [DllImport("advapi32.dll",EntryPoint="CredDeleteW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool Delete(string name,uint type,uint flags);
    [DllImport("advapi32.dll")] static extern void CredFree(IntPtr p);
    static string Key(string id)=>"SA SSTP Windows/"+id;
    public static void Put(string id,Login login)
    {
        var bytes=Encoding.Unicode.GetBytes(login.Password);
        if(bytes.Length>512 || login.User.Length>256) throw new ArgumentException("بيانات الدخول تتجاوز الحد المسموح.");
        var p=Marshal.AllocCoTaskMem(bytes.Length);
        try { Marshal.Copy(bytes,0,p,bytes.Length); var c=new Credential{Type=1,Target=Key(id),User=login.User,Size=(uint)bytes.Length,Blob=p,Persist=2,Comment="SA SSTP per-server credentials"};
            if(!Write(ref c,0)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()); }
        finally { Array.Clear(bytes); for(int i=0;i<bytes.Length;i++) Marshal.WriteByte(p,i,0); Marshal.FreeCoTaskMem(p); }
    }
    public static Login? Get(string id)
    {
        if(!Read(Key(id),1,0,out var p)){int e=Marshal.GetLastWin32Error();if(e==1168)return null;throw new System.ComponentModel.Win32Exception(e);}
        try{var c=Marshal.PtrToStructure<Credential>(p);return new Login(c.User??"",Marshal.PtrToStringUni(c.Blob,(int)c.Size/2)??"");}finally{CredFree(p);}
    }
    public static void Erase(string id)
    {
        if(!Delete(Key(id),1,0)){int e=Marshal.GetLastWin32Error();if(e!=1168)throw new System.ComponentModel.Win32Exception(e);}
    }
}
internal static class Vpn
{
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode,Pack=4)]
    private struct DialParams
    {
        public uint Size;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst=257)] public string Entry;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst=129)] public string Phone;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst=129)] public string Callback;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst=257)] public string User;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst=257)] public string Password;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst=16)] public string Domain;
        public uint SubEntry;
        public UIntPtr CallbackId;
        public uint IfIndex;
        public IntPtr EncPassword;
    }
    [DllImport("rasapi32.dll",EntryPoint="RasDialW",CharSet=CharSet.Unicode)] static extern uint RasDial(IntPtr ex,string? book,ref DialParams par,uint type,IntPtr notifier,out IntPtr connection);
    [DllImport("rasapi32.dll",EntryPoint="RasHangUpW")] static extern uint RasHangUp(IntPtr connection);
    [DllImport("rasapi32.dll",EntryPoint="RasGetErrorStringW",CharSet=CharSet.Unicode)] static extern uint RasGetErrorString(uint error,StringBuilder text,uint size);
    static string Q(string s)=>"'"+s.Replace("'","''")+"'";
    static async Task<string> Run(string exe, IEnumerable<string> args,int timeout=30)
    {
        var info=new ProcessStartInfo(exe){CreateNoWindow=true,UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};
        foreach(var a in args)info.ArgumentList.Add(a);
        using var p=Process.Start(info)??throw new InvalidOperationException("تعذر تشغيل أداة Windows.");
        var stdout=p.StandardOutput.ReadToEndAsync();var stderr=p.StandardError.ReadToEndAsync();
        using var cts=new CancellationTokenSource(TimeSpan.FromSeconds(timeout));
        try{await p.WaitForExitAsync(cts.Token);}catch(OperationCanceledException){try{p.Kill(true);}catch{}throw new TimeoutException("انتهت مهلة خدمة VPN في Windows.");}
        string output=await stdout,err=await stderr;
        if(p.ExitCode!=0)throw new InvalidOperationException(string.IsNullOrWhiteSpace(err)?output.Trim():err.Trim());
        return output;
    }
    static Task<string> PS(string code)=>Run("powershell.exe",new[]{"-NoLogo","-NoProfile","-NonInteractive","-EncodedCommand",Convert.ToBase64String(Encoding.Unicode.GetBytes("$ErrorActionPreference='Stop'; "+code))});
    public static async Task Prepare(Profile p)
    {
        p.Check();string name=Q(p.Entry),endpoint=Q(p.Endpoint);
        string options="-Name "+name+" -ServerAddress "+endpoint+" -TunnelType Sstp -AuthenticationMethod "+p.Auth+" -EncryptionLevel "+(p.Auth=="PAP"?"Optional":"Required")+" -SplitTunneling $false -RememberCredential $false -Force";
        await PS("if(Get-VpnConnection -Name "+name+" -ErrorAction SilentlyContinue){Set-VpnConnection "+options+" | Out-Null}else{Add-VpnConnection "+options+" | Out-Null}");
    }
    public static async Task<HashSet<string>> Active()
    {
        string result=await PS("Get-VpnConnection | Where-Object {$_.Name -like 'SA-SSTP-*' -and $_.ConnectionStatus -eq 'Connected'} | ForEach-Object {$_.Name}");
        return result.Split(new[]{'\r','\n'},StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries).ToHashSet(StringComparer.OrdinalIgnoreCase);
    }
    public static async Task Remove(Profile p){p.Check();string n=Q(p.Entry);await PS("if(Get-VpnConnection -Name "+n+" -ErrorAction SilentlyContinue){Remove-VpnConnection -Name "+n+" -Force}");}
    public static void Connect(Profile p,Login login)
    {
        if(login.User.Length>256||login.Password.Length>256||login.User.Length==0||login.Password.Length==0)throw new ArgumentException("تحقق من اسم المستخدم وكلمة المرور.");
        var d=new DialParams{Size=(uint)Marshal.SizeOf<DialParams>(),Entry=p.Entry,Phone="",Callback="",User=login.User,Password=login.Password,Domain="",SubEntry=1};
        uint e=RasDial(IntPtr.Zero,null,ref d,0,IntPtr.Zero,out var h);
        d.Password="";d.User="";
        if(e!=0){if(h!=IntPtr.Zero)RasHangUp(h);var b=new StringBuilder(512);RasGetErrorString(e,b,512);throw new InvalidOperationException("RAS "+e+": "+b);}
    }
    public static async Task Disconnect(Profile p)
    {
        await Run("rasdial.exe",new[]{p.Entry,"/disconnect"});
        for(int i=0;i<5;i++){if(!(await Active()).Contains(p.Entry))return;await Task.Delay(1000);}
        throw new InvalidOperationException("لم يؤكد Windows فصل الاتصال.");
    }
}
internal sealed class Window:Form
{
    readonly Settings data;
    readonly ListBox list=new(){Dock=DockStyle.Fill,IntegralHeight=false};
    readonly TextBox search=new(){PlaceholderText="ابحث بالاسم أو النطاق أو IP",Dock=DockStyle.Top};
    readonly ComboBox filter=new(){DropDownStyle=ComboBoxStyle.DropDownList,Dock=DockStyle.Top};
    readonly TextBox user=new(){Dock=DockStyle.Top,RightToLeft=RightToLeft.No};
    readonly TextBox pass=new(){Dock=DockStyle.Top,UseSystemPasswordChar=true,RightToLeft=RightToLeft.No};
    readonly ComboBox auth=new(){Dock=DockStyle.Top,DropDownStyle=ComboBoxStyle.DropDownList};
    readonly CheckBox remember=new(){Text="تذكر حساب هذا السيرفر",AutoSize=true};
    readonly CheckBox reconnect=new(){Text="إعادة الاتصال عند الانقطاع (3 محاولات)",AutoSize=true};
    readonly Label endpoint=new(){AutoSize=true,ForeColor=Color.FromArgb(12,95,120)};
    readonly Label status=new(){AutoSize=true,Font=new Font("Segoe UI",13,FontStyle.Bold),ForeColor=Color.DimGray};
    readonly Label detail=new(){AutoSize=true,MaximumSize=new Size(490,0),ForeColor=Color.DimGray};
    readonly Button connect=Btn("اتصال",true),save=Btn("حفظ الحساب"),forget=Btn("مسح الحساب"),add=Btn("إضافة سيرفر"),edit=Btn("تعديل"),remove=Btn("حذف"),export=Btn("تصدير"),import=Btn("استيراد");
    readonly System.Windows.Forms.Timer timer=new(){Interval=4000};
    readonly NotifyIcon tray=new(){Icon=SystemIcons.Shield,Text="SA SSTP",Visible=true};
    Profile? selected,active;
    Login? sessionLogin;
    DateTimeOffset? since;
    bool busy,loading,closing,manualDisconnect;
    int retries;
    DateTimeOffset nextRetry;
    static Button Btn(string s,bool primary=false)=>new(){Text=s,AutoSize=true,MinimumSize=new Size(92,38),FlatStyle=FlatStyle.Flat,BackColor=primary?Color.FromArgb(0,112,116):Color.White,ForeColor=primary?Color.White:Color.FromArgb(27,47,64),Margin=new Padding(3)};
    static Label LabelOf(string s)=>new(){Text=s,AutoSize=true,Font=new Font("Segoe UI",10,FontStyle.Bold)};
    public Window(Settings state)
    {
        data=state;Text="SA SSTP | Windows 1.0.0";Icon=SystemIcons.Shield;Font=new Font("Segoe UI",10);StartPosition=FormStartPosition.CenterScreen;Size=new Size(1080,780);MinimumSize=new Size(850,630);RightToLeft=RightToLeft.Yes;RightToLeftLayout=true;BackColor=Color.FromArgb(243,247,248);
        var layout=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=2,RowCount=2,Padding=new Padding(14)};
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,44));layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,56));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,82));layout.RowStyles.Add(new RowStyle(SizeType.Percent,100));
        var title=new Label{Text="SA SSTP   |   اتصال آمن وإدارة السيرفرات",Font=new Font("Segoe UI",19,FontStyle.Bold),ForeColor=Color.White,BackColor=Color.FromArgb(18,50,66),Dock=DockStyle.Fill,TextAlign=ContentAlignment.MiddleCenter};layout.Controls.Add(title,0,0);layout.SetColumnSpan(title,2);
        var left=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=6,Padding=new Padding(9),BackColor=Color.White};
        left.RowStyles.Add(new RowStyle(SizeType.Absolute,30));left.RowStyles.Add(new RowStyle(SizeType.Absolute,35));left.RowStyles.Add(new RowStyle(SizeType.Absolute,35));left.RowStyles.Add(new RowStyle(SizeType.Percent,100));left.RowStyles.Add(new RowStyle(SizeType.Absolute,52));left.RowStyles.Add(new RowStyle(SizeType.Absolute,52));
        filter.Items.AddRange(new object[]{"كل السيرفرات","السعودية","الإمارات","المضافة يدوياً"});filter.SelectedIndex=0;
        left.Controls.Add(LabelOf("السيرفرات"),0,0);left.Controls.Add(filter,0,1);left.Controls.Add(search,0,2);left.Controls.Add(list,0,3);left.Controls.Add(Flow(add,edit,remove),0,4);left.Controls.Add(Flow(export,import),0,5);
        layout.Controls.Add(left,0,1);
        var right=new TableLayoutPanel{Dock=DockStyle.Top,AutoSize=true,ColumnCount=1,Padding=new Padding(18),BackColor=Color.White};
        right.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        void Row(Control c){c.Margin=new Padding(3,4,3,8);right.Controls.Add(c);}
        auth.Items.AddRange(new object[]{"PAP","CHAP","MSChapv2"});
        Row(LabelOf("السيرفر المختار"));Row(endpoint);Row(LabelOf("اسم المستخدم"));Row(user);Row(LabelOf("كلمة المرور"));Row(pass);
        var show=new CheckBox{Text="إظهار كلمة المرور",AutoSize=true};show.CheckedChanged+=(_,_)=>pass.UseSystemPasswordChar=!show.Checked;Row(show);
        Row(LabelOf("مصادقة PPP"));Row(auth);Row(remember);Row(reconnect);Row(Flow(save,forget));Row(LabelOf("حالة اتصال Windows"));Row(status);Row(detail);connect.MinimumSize=new Size(190,48);Row(connect);
        Row(new Label{Text="TLS: التحقق من الشهادة مفعل. اتصال Windows يعتمد على DNS للنطاق؛ IP في القائمة مرجعي. لا تُرسل كلمات المرور في سطر الأوامر.",AutoSize=true,MaximumSize=new Size(490,0),ForeColor=Color.DimGray});
        var panel=new Panel{Dock=DockStyle.Fill,AutoScroll=true,Padding=new Padding(10,0,0,0)};panel.Controls.Add(right);layout.Controls.Add(panel,1,1);Controls.Add(layout);
        filter.SelectedIndexChanged+=(_,_)=>RefreshList();search.TextChanged+=(_,_)=>RefreshList();list.SelectedIndexChanged+=(_,_)=>SelectProfile();
        add.Click+=(_,_)=>Guard(()=>EditProfile(null));edit.Click+=(_,_)=>Guard(()=>EditProfile(selected));remove.Click+=async(_,_)=>await Work(DeleteProfile);
        save.Click+=(_,_)=>Guard(()=>SaveLogin(true));forget.Click+=(_,_)=>Guard(()=>{if(selected==null)return;Vault.Erase(selected.Id);user.Clear();pass.Clear();});
        remember.CheckedChanged+=(_,_)=>Guard(()=>{if(loading||selected==null)return;if(!remember.Checked)Vault.Erase(selected.Id);selected.Remember=remember.Checked;Store.Save(data);});
        reconnect.CheckedChanged+=(_,_)=>Guard(()=>{if(loading||selected==null)return;selected.Reconnect=reconnect.Checked;Store.Save(data);});
        auth.SelectedIndexChanged+=(_,_)=>Guard(()=>{if(!loading&&selected!=null&&auth.SelectedItem is string a){selected.Auth=a;Store.Save(data);}});
        connect.Click+=async(_,_)=>await Work(Toggle);export.Click+=(_,_)=>Guard(Export);import.Click+=(_,_)=>Guard(Import);
        tray.DoubleClick+=(_,_)=>{Show();WindowState=FormWindowState.Normal;Activate();};
        var menu=new ContextMenuStrip();menu.Items.Add("فتح التطبيق",null,(_,_)=>{Show();WindowState=FormWindowState.Normal;Activate();});menu.Items.Add("فصل الاتصال",null,async(_,_)=>await Work(async()=>{if(active!=null)await Stop();}));menu.Items.Add("إغلاق التطبيق",null,(_,_)=>{closing=true;Close();});tray.ContextMenuStrip=menu;
        Resize+=(_,_)=>{if(WindowState==FormWindowState.Minimized)Hide();};
        FormClosing+=(_,e)=>{if(busy){e.Cancel=true;closing=false;return;}if(!closing&&e.CloseReason==CloseReason.UserClosing){e.Cancel=true;Hide();return;}timer.Stop();tray.Visible=false;tray.Dispose();};
        timer.Tick+=async(_,_)=>{if(!busy)await Poll();};Shown+=async(_,_)=>{await Poll();timer.Start();};
        RefreshList();if(list.Items.Count>0&&selected==null)list.SelectedIndex=0;ControlsState();
    }
    static FlowLayoutPanel Flow(params Control[] c){var f=new FlowLayoutPanel{Dock=DockStyle.Fill,AutoSize=true,WrapContents=false,AutoScroll=true};f.Controls.AddRange(c);return f;}
    void Guard(Action a){try{a();}catch(Exception e){Error(e);}}
    void Error(Exception e)=>MessageBox.Show(this,e.Message,"SA SSTP",MessageBoxButtons.OK,MessageBoxIcon.Warning);
    void RefreshList()
    {
        if(loading)return;string id=selected?.Id??data.Selected;string q=search.Text.Trim();
        loading=true;list.BeginUpdate();try{list.Items.Clear();foreach(var p in data.Profiles.Where(p=>(filter.SelectedIndex switch{1=>p.Region=="SA",2=>p.Region=="AE",3=>p.Custom,_=>true})&&(q.Length==0||p.Name.Contains(q,StringComparison.OrdinalIgnoreCase)||p.Host.Contains(q,StringComparison.OrdinalIgnoreCase)||p.Ip.Contains(q,StringComparison.OrdinalIgnoreCase))))list.Items.Add(p);
        var match=list.Items.Cast<Profile>().FirstOrDefault(p=>p.Id==id);if(match!=null)list.SelectedItem=match;else if(list.Items.Count>0)list.SelectedIndex=0;}finally{list.EndUpdate();loading=false;}
        SelectProfile();
    }
    void SelectProfile()
    {
        if(loading)return;selected=list.SelectedItem as Profile;loading=true;
        try{user.Clear();pass.Clear();if(selected==null){endpoint.Text="اختر سيرفرًا";return;}
            var p=selected;data.Selected=p.Id;endpoint.Text=p.Name+"  |  "+p.Endpoint+"  |  "+p.Region;auth.SelectedItem=p.Auth;remember.Checked=p.Remember;reconnect.Checked=p.Reconnect;
            if(p.Remember){var l=Vault.Get(p.Id);if(l!=null){user.Text=l.User;pass.Text=l.Password;}}
            Store.Save(data);
        }catch(Exception e){Error(e);}finally{loading=false;ControlsState();}
    }
    Login CurrentLogin(){if(string.IsNullOrWhiteSpace(user.Text)||string.IsNullOrEmpty(pass.Text))throw new ArgumentException("أدخل اسم المستخدم وكلمة المرور.");return new Login(user.Text.Trim(),pass.Text);}
    void SaveLogin(bool notify){if(selected==null)return;if(!remember.Checked)throw new InvalidOperationException("فعّل تذكر الحساب أولاً.");Vault.Put(selected.Id,CurrentLogin());Store.Save(data);if(notify)detail.Text="تم حفظ الحساب لهذا السيرفر في Windows Credential Manager.";}
    void ControlsState(){foreach(var c in new Control[]{list,filter,search,add,export,import})c.Enabled=!busy;foreach(var c in new Control[]{user,pass,remember,reconnect,auth,save,forget})c.Enabled=!busy&&selected!=null&&active?.Id!=selected.Id;edit.Enabled=remove.Enabled=!busy&&selected?.Custom==true&&selected.Id!=active?.Id;connect.Enabled=!busy&&(selected!=null||active!=null);connect.Text=active==null?"اتصال SSTP":"فصل الاتصال";}
    async Task Work(Func<Task> task){if(busy)return;busy=true;ControlsState();try{await task();}catch(Exception e){detail.Text=e.Message;Error(e);}finally{busy=false;ControlsState();}}
    async Task Toggle(){if(active!=null){await Stop();return;}if(selected==null)return;var p=selected;var login=CurrentLogin();if(p.Remember)SaveLogin(false);manualDisconnect=false;retries=0;await Start(p,login);}
    async Task Start(Profile p,Login login){status.Text="جاري الاتصال...";status.ForeColor=Color.DarkOrange;detail.Text=p.Endpoint;try{await Vpn.Prepare(p);await Task.Run(()=>Vpn.Connect(p,login));active=p;sessionLogin=login;since=DateTimeOffset.Now;status.Text="متصل: "+p.Name;status.ForeColor=Color.SeaGreen;detail.Text="تم إنشاء نفق SSTP بواسطة Windows.";}catch{status.Text="غير متصل";status.ForeColor=Color.Firebrick;throw;}}
    async Task Stop(){if(active==null)return;manualDisconnect=true;var p=active;await Vpn.Disconnect(p);active=null;sessionLogin=null;since=null;retries=0;status.Text="غير متصل";status.ForeColor=Color.DimGray;detail.Text="تم فصل الاتصال.";}
    async Task Poll()
    {
        if(busy)return;busy=true;ControlsState();try
        {
            var connected=await Vpn.Active();var found=data.Profiles.FirstOrDefault(p=>connected.Contains(p.Entry));
            if(found!=null){if(active?.Id!=found.Id){active=found;since=DateTimeOffset.Now;sessionLogin=found.Remember?Vault.Get(found.Id):null;retries=0;}status.Text="متصل: "+found.Name+"  "+(DateTimeOffset.Now-(since??DateTimeOffset.Now)).ToString(@"hh\:mm\:ss");status.ForeColor=Color.SeaGreen;return;}
            if(active!=null){var p=active;active=null;since=null;status.Text="انقطع الاتصال";status.ForeColor=Color.Firebrick;if(!manualDisconnect&&p.Reconnect&&sessionLogin!=null){retryProfile=p;nextRetry=DateTimeOffset.Now.AddSeconds(5);retries=0;}else sessionLogin=null;}
            if(retryProfile!=null&&!manualDisconnect&&sessionLogin!=null&&DateTimeOffset.Now>=nextRetry&&retries<3){var p=retryProfile;var l=sessionLogin;retries++;try{await Start(p,l);retryProfile=null;}catch(Exception e){detail.Text="إعادة الاتصال "+retries+"/3: "+e.Message;nextRetry=DateTimeOffset.Now.AddSeconds(15*retries);if(retries>=3){retryProfile=null;sessionLogin=null;}}}
            else if(active==null&&retryProfile==null){status.Text="غير متصل";status.ForeColor=Color.DimGray;}
        }catch(Exception e){status.Text="تعذر التحقق من حالة Windows";status.ForeColor=Color.DarkOrange;detail.Text=e.Message;}finally{busy=false;ControlsState();}
    }
    Profile? retryProfile;
    void EditProfile(Profile? p)
    {
        if(p!=null&&(!p.Custom||p.Id==active?.Id))return;
        using var dlg=new Form{Text=p==null?"إضافة سيرفر":"تعديل السيرفر",StartPosition=FormStartPosition.CenterParent,FormBorderStyle=FormBorderStyle.FixedDialog,MaximizeBox=false,MinimizeBox=false,ClientSize=new Size(520,365),RightToLeft=RightToLeft.Yes,RightToLeftLayout=true,Font=Font};
        var grid=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=2,RowCount=6,Padding=new Padding(16)};grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,130));grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        var n=new TextBox{Text=p?.Name??"",Dock=DockStyle.Fill};var h=new TextBox{Text=p?.Host??"",Dock=DockStyle.Fill,RightToLeft=RightToLeft.No};var ip=new TextBox{Text=p?.Ip??"",Dock=DockStyle.Fill,RightToLeft=RightToLeft.No};var port=new NumericUpDown{Minimum=1,Maximum=65535,Value=p?.Port??443,Dock=DockStyle.Fill};var r=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList,Dock=DockStyle.Fill};r.Items.AddRange(new object[]{"SA","AE","OTHER"});r.SelectedItem=p?.Region??"OTHER";
        int i=0;foreach(var pair in new (string,Control)[]{("اسم السيرفر",n),("DNS / SNI",h),("IP مرجعي",ip),("TCP Port",port),("الدولة",r)}){grid.RowStyles.Add(new RowStyle(SizeType.Absolute,49));grid.Controls.Add(LabelOf(pair.Item1),0,i);grid.Controls.Add(pair.Item2,1,i++);}
        var ok=Btn("حفظ",true);var cancel=Btn("إلغاء");cancel.DialogResult=DialogResult.Cancel;grid.Controls.Add(Flow(ok,cancel),1,5);dlg.Controls.Add(grid);dlg.CancelButton=cancel;
        ok.Click+=(_,_)=>{try{var value=new Profile{Id=p?.Id??Guid.NewGuid().ToString("N"),Name=n.Text.Trim(),Host=h.Text.Trim(),Ip=ip.Text.Trim(),Port=(int)port.Value,Region=r.Text,Auth=p?.Auth??"PAP",Remember=p?.Remember??true,Reconnect=p?.Reconnect??false,Custom=true};value.Check();if(data.Profiles.Any(x=>x.Id!=value.Id&&x.Host.Equals(value.Host,StringComparison.OrdinalIgnoreCase)&&x.Port==value.Port))throw new ArgumentException("هذا السيرفر موجود بالفعل.");if(p==null)data.Profiles.Add(value);else data.Profiles[data.Profiles.IndexOf(p)]=value;Store.Save(data);selected=value;data.Selected=value.Id;filter.SelectedIndex=0;search.Clear();RefreshList();dlg.DialogResult=DialogResult.OK;}catch(Exception e){MessageBox.Show(dlg,e.Message,"التحقق",MessageBoxButtons.OK,MessageBoxIcon.Warning);}};
        dlg.ShowDialog(this);
    }
    async Task DeleteProfile(){if(selected is not {Custom:true} p||p.Id==active?.Id)return;if(MessageBox.Show(this,"حذف السيرفر وحسابه المحفوظ؟","تأكيد",MessageBoxButtons.YesNo)!=DialogResult.Yes)return;await Vpn.Remove(p);Vault.Erase(p.Id);data.Profiles.Remove(p);selected=null;Store.Save(data);RefreshList();}
    void Export(){using var d=new SaveFileDialog{Filter="JSON (*.json)|*.json",FileName="SA_SSTP_servers.json"};if(d.ShowDialog(this)!=DialogResult.OK)return;File.WriteAllText(d.FileName,JsonSerializer.Serialize(data.Profiles.Where(x=>x.Custom).Select(p=>new Profile{Name=p.Name,Host=p.Host,Ip=p.Ip,Port=p.Port,Region=p.Region,Auth=p.Auth,Custom=true,Remember=true}).ToList(),Store.Json));detail.Text="تم تصدير السيرفرات اليدوية دون كلمات المرور.";}
    void Import(){using var d=new OpenFileDialog{Filter="JSON (*.json)|*.json"};if(d.ShowDialog(this)!=DialogResult.OK)return;if(new FileInfo(d.FileName).Length>2_000_000)throw new InvalidDataException("ملف الاستيراد كبير.");var input=JsonSerializer.Deserialize<List<Profile>>(File.ReadAllText(d.FileName),Store.Json)??throw new InvalidDataException("ملف غير صالح.");if(input.Count>2000)throw new InvalidDataException("عدد السيرفرات كبير.");var addList=new List<Profile>();foreach(var p in input){p.Id=Guid.NewGuid().ToString("N");p.Custom=true;p.Remember=true;p.Reconnect=false;p.Check();if(!data.Profiles.Concat(addList).Any(x=>x.Host.Equals(p.Host,StringComparison.OrdinalIgnoreCase)&&x.Port==p.Port))addList.Add(p);}data.Profiles.AddRange(addList);Store.Save(data);RefreshList();detail.Text="تم استيراد "+addList.Count+" سيرفر.";}
}
internal static class Program
{
    [STAThread] static int Main(string[] args)
    {
        if(args.Contains("--self-test"))return SelfTest();
        using var mutex=new Mutex(true,"Local\\SA_SSTP_Windows",out bool first);
        if(!first){MessageBox.Show("SA SSTP يعمل بالفعل بجوار الساعة.");return 0;}
        ApplicationConfiguration.Initialize();
        try{var st=Store.Load(Store.PathName);Store.Save(st);Application.Run(new Window(st));return 0;}catch(Exception e){MessageBox.Show("تعذر تشغيل التطبيق. لم تُحذف الإعدادات الأصلية.\n"+e.Message,"SA SSTP",MessageBoxButtons.OK,MessageBoxIcon.Error);return 1;}
    }
    static int SelfTest()
    {
        string root=Path.Combine(Path.GetTempPath(),"SA-SSTP-test-"+Guid.NewGuid().ToString("N"));
        string path=Path.Combine(root,"profiles.json");
        try{var s=Store.Load(path);if(s.Profiles.Count<40)return 2;var a=new Profile{Name="Test A",Host="test.example.com",Port=1194,Custom=true};var b=new Profile{Name="Test B",Host="test2.example.com",Port=443,Custom=true};a.Check();b.Check();s.Profiles.AddRange(new[]{a,b});s.Selected=b.Id;Store.Save(s,path);var r=Store.Load(path);if(r.Selected!=b.Id||!r.Profiles.Any(x=>x.Id==a.Id)||!r.Profiles.Any(x=>x.Id==b.Id)||a.Endpoint!="test.example.com:1194")return 3;try{new Profile{Name="Bad",Host="https://bad.example",Port=443}.Check();return 4;}catch(ArgumentException){}return 0;}catch{return 5;}finally{if(Directory.Exists(root))Directory.Delete(root,true);}
    }
}
