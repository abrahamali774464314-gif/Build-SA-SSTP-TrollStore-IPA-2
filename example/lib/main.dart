import 'package:flutter/material.dart';
import 'package:sstp_flutter/android_configuration_sstp.dart';
import 'package:sstp_flutter/ios_configuration_sstp.dart';
import 'package:sstp_flutter/server.dart';
import 'package:sstp_flutter/sstp_flutter.dart';
import 'server_catalog.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const SaSstpApp());
}

class SaSstpApp extends StatelessWidget {
  const SaSstpApp({super.key});

  @override
  Widget build(BuildContext context) {
    const seed = Color(0xFF087E72);
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'SA SSTP',
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(seedColor: seed),
        scaffoldBackgroundColor: const Color(0xFFF4F7F7),
        appBarTheme: const AppBarTheme(
          backgroundColor: Color(0xFFF4F7F7),
          centerTitle: false,
        ),
      ),
      home: const Directionality(
        textDirection: TextDirection.rtl,
        child: SaSstpHomePage(),
      ),
    );
  }
}

class _ServerChoice {
  final String id;
  final String host;
  final String ip;
  final String region;
  final int port;
  final bool papPreviouslyConnected;
  final bool custom;

  const _ServerChoice({
    required this.id,
    required this.host,
    required this.ip,
    required this.region,
    this.port = 1194,
    this.papPreviouslyConnected = false,
    this.custom = false,
  });

  factory _ServerChoice.fromCatalog(SstpServerEntry entry) {
    return _ServerChoice(
      id: entry.id,
      host: entry.host,
      ip: entry.ip,
      region: entry.region,
      port: entry.port,
      papPreviouslyConnected: entry.papPreviouslyConnected,
    );
  }
}

class SaSstpHomePage extends StatefulWidget {
  const SaSstpHomePage({super.key});

  @override
  State<SaSstpHomePage> createState() => _SaSstpHomePageState();
}

class _SaSstpHomePageState extends State<SaSstpHomePage> {
  final SstpFlutter _vpn = SstpFlutter();
  final TextEditingController _username = TextEditingController();
  final TextEditingController _password = TextEditingController();
  final TextEditingController _search = TextEditingController();

  late final List<_ServerChoice> _servers =
      bundledServers.map(_ServerChoice.fromCatalog).toList();

  _ServerChoice? _selected;
  String _region = 'SA';
  String _status = 'Disconnected';
  String _statusText = 'غير متصل';
  String _lastError = '';
  Duration _connectedFor = Duration.zero;
  bool _busy = false;
  bool _hidePassword = true;
  String _authMethod = 'PAP';

  @override
  void initState() {
    super.initState();
    _selected = _servers.firstWhere((s) => s.id == 'SA46');
    _search.addListener(() => setState(() {}));
    _registerCallbacks();
    _loadLastStatus();
  }

  Future<void> _registerCallbacks() async {
    await _vpn.onResult(
      onConnectedResult: (traffic, duration) {
        if (!mounted) return;
        setState(() {
          _status = 'Connected';
          _statusText = 'متصل';
          _connectedFor = duration;
          _busy = false;
          _lastError = '';
        });
      },
      onConnectingResult: () {
        if (!mounted) return;
        setState(() {
          _status = 'Connecting';
          _statusText = 'جارٍ الاتصال';
          _busy = true;
          _lastError = '';
        });
      },
      onDisconnectedResult: () {
        if (!mounted) return;
        setState(() {
          _status = 'Disconnected';
          _statusText = 'غير متصل';
          _connectedFor = Duration.zero;
          _busy = false;
        });
      },
      onError: () {
        if (!mounted) return;
        setState(() {
          _lastError = 'انقطع الاتصال أو رفض الخادم المصادقة';
          _busy = false;
        });
      },
    );
  }

  Future<void> _loadLastStatus() async {
    try {
      final status = await _vpn.checkLastConnectionStatus();
      if (!mounted) return;
      setState(() {
        _status = status;
        _statusText = status == 'Connected'
            ? 'متصل'
            : status == 'Connecting'
                ? 'جارٍ الاتصال'
                : 'غير متصل';
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _status = 'Disconnected';
        _statusText = 'غير متصل';
      });
    }
  }

  List<_ServerChoice> get _visibleServers {
    final query = _search.text.trim().toLowerCase();
    return _servers.where((server) {
      if (server.region != _region) return false;
      if (query.isEmpty) return true;
      return server.id.toLowerCase().contains(query) ||
          server.host.toLowerCase().contains(query) ||
          server.ip.contains(query);
    }).toList();
  }

  Future<void> _connect() async {
    final server = _selected;
    final username = _username.text.trim();
    final password = _password.text;

    if (server == null) {
      _showMessage('اختر سيرفراً أولاً');
      return;
    }
    if (username.isEmpty || password.isEmpty) {
      _showMessage('أدخل اسم المستخدم وكلمة المرور');
      return;
    }
    if (_busy || _status == 'Connected') return;

    setState(() {
      _busy = true;
      _status = 'Connecting';
      _statusText = 'جارٍ الاتصال';
      _lastError = '';
    });

    try {
      final config = SSTPServer(
        // The IP is used for the TCP connection; serverName is the TLS SNI.
        host: server.ip,
        serverName: server.host,
        port: server.port,
        username: username,
        password: password,
        androidConfiguration: SSTPAndroidConfiguration(),
        iosConfiguration: SSTPIOSConfiguration(
          enableTLS: false, // In this plugin this means allowInsecure=false.
          enablePAP: _authMethod == 'PAP',
          enableCHAP: _authMethod == 'CHAP',
          enableMSCHAP2: _authMethod == 'MS-CHAPv2',
        ),
      );

      await _vpn.saveServerData(server: config);
      // This waits for the native VPN profile to be saved and reloaded.
      await _vpn.takePermission();
      await _vpn.connectVpn();

      if (!mounted) return;
      setState(() {
        _statusText = 'تم إرسال طلب الاتصال';
      });
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _status = 'Disconnected';
        _statusText = 'تعذر بدء الاتصال';
        _lastError = error.toString();
      });
      _showMessage('تعذر بدء اتصال VPN. راجع رسالة الخطأ.');
    }
  }

  Future<void> _disconnect() async {
    try {
      await _vpn.disconnect();
      if (!mounted) return;
      setState(() {
        _busy = false;
        _status = 'Disconnected';
        _statusText = 'غير متصل';
        _connectedFor = Duration.zero;
      });
    } catch (error) {
      _showMessage('تعذر قطع الاتصال: $error');
    }
  }

  Future<void> _addCustomServer() async {
    final hostController = TextEditingController();
    final ipController = TextEditingController();
    final portController = TextEditingController(text: '1194');

    final result = await showDialog<_ServerChoice>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('إضافة سيرفر يدوي'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: hostController,
                decoration: const InputDecoration(
                  labelText: 'اسم السيرفر / SNI',
                  hintText: 'sa46.giamping.com',
                ),
                textDirection: TextDirection.ltr,
              ),
              const SizedBox(height: 10),
              TextField(
                controller: ipController,
                decoration: const InputDecoration(
                  labelText: 'عنوان IP للاتصال',
                  hintText: '193.122.94.3',
                ),
                textDirection: TextDirection.ltr,
              ),
              const SizedBox(height: 10),
              TextField(
                controller: portController,
                keyboardType: TextInputType.number,
                decoration: const InputDecoration(labelText: 'المنفذ'),
                textDirection: TextDirection.ltr,
              ),
              const SizedBox(height: 8),
              const Text(
                'اكتب اسم الشهادة في خانة SNI وعنوان IP في خانة الاتصال. '
                'لا نعطّل التحقق من شهادة TLS.',
                style: TextStyle(fontSize: 12, color: Colors.black54),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext),
            child: const Text('إلغاء'),
          ),
          FilledButton(
            onPressed: () {
              final host = hostController.text.trim();
              final ip = ipController.text.trim();
              final port = int.tryParse(portController.text.trim());
              if (host.isEmpty || ip.isEmpty || port == null ||
                  port < 1 || port > 65535) {
                return;
              }
              Navigator.pop(
                dialogContext,
                _ServerChoice(
                  id: 'CUSTOM',
                  host: host,
                  ip: ip,
                  region: _region,
                  port: port,
                  custom: true,
                ),
              );
            },
            child: const Text('إضافة'),
          ),
        ],
      ),
    );

    hostController.dispose();
    ipController.dispose();
    portController.dispose();

    if (result == null || !mounted) return;
    setState(() {
      _selected = result;
      _region = result.region;
    });
  }

  void _showMessage(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message), behavior: SnackBarBehavior.floating),
    );
  }

  String _durationText(Duration duration) {
    String two(int value) => value.toString().padLeft(2, '0');
    final hours = two(duration.inHours);
    final minutes = two(duration.inMinutes.remainder(60));
    final seconds = two(duration.inSeconds.remainder(60));
    return '$hours:$minutes:$seconds';
  }

  @override
  void dispose() {
    _username.dispose();
    _password.dispose();
    _search.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final selected = _selected;
    final connected = _status == 'Connected';

    return Scaffold(
      appBar: AppBar(
        title: const Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('SA SSTP', style: TextStyle(fontWeight: FontWeight.w800)),
            Text(
              'اتصال SSTP للسعودية والإمارات',
              style: TextStyle(fontSize: 12, color: Colors.black54),
            ),
          ],
        ),
        actions: [
          IconButton(
            tooltip: 'إضافة سيرفر',
            onPressed: _addCustomServer,
            icon: const Icon(Icons.add_circle_outline),
          ),
        ],
      ),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
          children: [
            _connectionCard(connected),
            const SizedBox(height: 16),
            const Text(
              'اختر السيرفر',
              style: TextStyle(fontSize: 17, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 10),
            SegmentedButton<String>(
              segments: const [
                ButtonSegment(
                  value: 'SA',
                  label: Text('السعودية'),
                  icon: Icon(Icons.flag_circle_outlined),
                ),
                ButtonSegment(
                  value: 'AE',
                  label: Text('الإمارات'),
                  icon: Icon(Icons.location_city_outlined),
                ),
              ],
              selected: {_region},
              onSelectionChanged: (selection) {
                _search.clear();
                setState(() {
                  _region = selection.first;
                  final nextServers = _servers
                      .where((server) => server.region == _region)
                      .toList();
                  _selected = nextServers.isNotEmpty ? nextServers.first : null;
                });
              },
            ),
            const SizedBox(height: 10),
            TextField(
              controller: _search,
              decoration: InputDecoration(
                hintText: 'ابحث برقم السيرفر أو IP أو الاسم',
                prefixIcon: const Icon(Icons.search),
                suffixIcon: _search.text.isEmpty
                    ? null
                    : IconButton(
                        onPressed: _search.clear,
                        icon: const Icon(Icons.close),
                      ),
                filled: true,
                fillColor: Colors.white,
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(14),
                  borderSide: BorderSide.none,
                ),
              ),
            ),
            const SizedBox(height: 8),
            Text(
              '${_visibleServers.length} سيرفر متاح ضمن نتائج فحص TCP/TLS',
              style: const TextStyle(color: Colors.black54, fontSize: 12),
            ),
            const SizedBox(height: 8),
            if (_visibleServers.isEmpty)
              const Padding(
                padding: EdgeInsets.all(24),
                child: Text('لا توجد نتائج مطابقة'),
              )
            else
              ..._visibleServers.map((server) => _serverChoiceTile(server, _selected?.id == server.id)),
            if (selected != null && selected.custom) ...[
              const SizedBox(height: 8),
              Card(
                elevation: 0,
                color: const Color(0xFFE5F4F1),
                child: ListTile(
                  title: Text(selected.host, textDirection: TextDirection.ltr),
                  subtitle: Text(
                    '${selected.ip}:${selected.port}',
                    textDirection: TextDirection.ltr,
                  ),
                  trailing: IconButton(
                    onPressed: _addCustomServer,
                    icon: const Icon(Icons.edit_outlined),
                    tooltip: 'تعديل',
                  ),
                ),
              ),
            ],
            const SizedBox(height: 18),
            const Text(
              'بيانات الحساب',
              style: TextStyle(fontSize: 17, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 10),
            TextField(
              controller: _username,
              autocorrect: false,
              decoration: const InputDecoration(
                labelText: 'اسم المستخدم',
                prefixIcon: Icon(Icons.person_outline),
                filled: true,
                fillColor: Colors.white,
                border: OutlineInputBorder(),
              ),
              textDirection: TextDirection.ltr,
            ),
            const SizedBox(height: 10),
            TextField(
              controller: _password,
              obscureText: _hidePassword,
              autocorrect: false,
              decoration: InputDecoration(
                labelText: 'كلمة المرور',
                prefixIcon: const Icon(Icons.lock_outline),
                suffixIcon: IconButton(
                  onPressed: () => setState(() => _hidePassword = !_hidePassword),
                  icon: Icon(_hidePassword ? Icons.visibility : Icons.visibility_off),
                ),
                filled: true,
                fillColor: Colors.white,
                border: const OutlineInputBorder(),
              ),
              textDirection: TextDirection.ltr,
            ),
            const SizedBox(height: 10),
            DropdownButtonFormField<String>(
              value: _authMethod,
              decoration: const InputDecoration(
                labelText: 'طريقة المصادقة PPP',
                prefixIcon: Icon(Icons.verified_user_outlined),
                filled: true,
                fillColor: Colors.white,
                border: OutlineInputBorder(),
              ),
              items: const [
                DropdownMenuItem(value: 'PAP', child: Text('PAP')),
                DropdownMenuItem(value: 'CHAP', child: Text('CHAP')),
                DropdownMenuItem(value: 'MS-CHAPv2', child: Text('MS-CHAPv2')),
              ],
              onChanged: (value) {
                if (value != null) setState(() => _authMethod = value);
              },
            ),
            const SizedBox(height: 16),
            SizedBox(
              height: 52,
              child: FilledButton.icon(
                onPressed: _busy || connected ? null : _connect,
                icon: _busy
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.vpn_lock),
                label: Text(_busy ? 'جارٍ الاتصال...' : 'اتصال'),
              ),
            ),
            const SizedBox(height: 8),
            OutlinedButton.icon(
              onPressed: connected || _busy ? _disconnect : null,
              icon: const Icon(Icons.link_off),
              label: const Text('قطع الاتصال'),
            ),
            const SizedBox(height: 12),
            const Text(
              'ملاحظة: نجاح TCP/TLS لا يثبت نجاح مصادقة PPP. '
              'السيرفرات التي لم نختبر عليها بيانات الحساب ستُختبر عند الاتصال. '
              'بيانات الحساب لا تُحفظ في قائمة السيرفرات.',
              style: TextStyle(fontSize: 12, color: Colors.black54, height: 1.5),
            ),
          ],
        ),
      ),
    );
  }

  Widget _connectionCard(bool connected) {
    final color = connected ? const Color(0xFF16845D) : const Color(0xFF64748B);
    return Card(
      elevation: 0,
      color: Colors.white,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            CircleAvatar(
              radius: 24,
              backgroundColor: color.withOpacity(.12),
              child: Icon(
                connected ? Icons.shield : Icons.shield_outlined,
                color: color,
                size: 26,
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    _statusText,
                    style: TextStyle(
                      fontSize: 17,
                      fontWeight: FontWeight.bold,
                      color: color,
                    ),
                  ),
                  Text(
                    connected
                        ? 'مدة الاتصال ${_durationText(_connectedFor)}'
                        : 'المصادقة: $_authMethod',
                    style: const TextStyle(color: Colors.black54, fontSize: 12),
                  ),
                  if (_lastError.isNotEmpty)
                    Padding(
                      padding: const EdgeInsets.only(top: 5),
                      child: Text(
                        _lastError,
                        style: const TextStyle(color: Colors.red, fontSize: 11),
                      ),
                    ),
                ],
              ),
            ),
            if (connected)
              const Icon(Icons.check_circle, color: Color(0xFF16845D)),
          ],
        ),
      ),
    );
  }

  Widget _serverTile(SstpServerEntry entry) {
    final server = _ServerChoice.fromCatalog(entry);
    final isSelected = _selected?.id == server.id;
    return _serverChoiceTile(server, isSelected);
  }

  Widget _serverChoiceTile(_ServerChoice server, bool isSelected) {
    final previouslyConnected = server.papPreviouslyConnected;
    return Card(
      elevation: 0,
      color: isSelected ? const Color(0xFFE5F4F1) : Colors.white,
      margin: const EdgeInsets.only(bottom: 7),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(14),
        side: BorderSide(
          color: isSelected ? const Color(0xFF087E72) : Colors.transparent,
          width: 1.2,
        ),
      ),
      child: InkWell(
        borderRadius: BorderRadius.circular(14),
        onTap: () => setState(() => _selected = server),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 11),
          child: Row(
            children: [
              CircleAvatar(
                radius: 19,
                backgroundColor: const Color(0xFF087E72).withOpacity(.10),
                child: Text(
                  server.id,
                  style: const TextStyle(
                    color: Color(0xFF087E72),
                    fontSize: 10,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      server.host,
                      textDirection: TextDirection.ltr,
                      style: const TextStyle(fontWeight: FontWeight.w600),
                    ),
                    const SizedBox(height: 3),
                    Text(
                      '${server.ip}  •  ${server.port}',
                      textDirection: TextDirection.ltr,
                      style: const TextStyle(fontSize: 11, color: Colors.black54),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      previouslyConnected
                          ? 'نجح اتصال PAP سابقاً على هذا السيرفر'
                          : 'فحص TCP/TLS ناجح — مصادقة PPP غير مؤكدة',
                      style: TextStyle(
                        fontSize: 10,
                        color: previouslyConnected
                            ? const Color(0xFF16845D)
                            : Colors.black54,
                      ),
                    ),
                  ],
                ),
              ),
              Icon(
                isSelected ? Icons.radio_button_checked : Icons.radio_button_off,
                color: isSelected ? const Color(0xFF087E72) : Colors.black26,
              ),
            ],
          ),
        ),
      ),
    );
  }
}
