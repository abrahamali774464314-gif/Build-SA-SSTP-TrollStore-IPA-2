class SstpServerEntry {
  final String id;
  final String host;
  final String ip;
  final String region;
  final int port;
  final bool papPreviouslyConnected;

  const SstpServerEntry({
    required this.id,
    required this.host,
    required this.ip,
    required this.region,
    this.port = 1194,
    this.papPreviouslyConnected = false,
  });

  String get title => region == 'SA' ? 'السعودية' : 'الإمارات';
}

const List<SstpServerEntry> bundledServers = [
  SstpServerEntry(id: 'SA10', host: 'sa10.giamping.com', ip: '80.238.225.70', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA11', host: 'sa11.giamping.com', ip: '154.205.134.120', region: 'SA', papPreviouslyConnected: true),
  SstpServerEntry(id: 'SA12', host: 'sa12.giamping.com', ip: '156.244.11.4', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA13', host: 'sa13.giamping.com', ip: '156.244.12.180', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA14', host: 'sa14.giamping.com', ip: '101.46.56.31', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA15', host: 'sa15.giamping.com', ip: '101.46.55.162', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA16', host: 'sa16.giamping.com', ip: '101.46.59.82', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA17', host: 'sa17.giamping.com', ip: '80.238.226.10', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA18', host: 'sa18.giamping.com', ip: '149.104.105.110', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA19', host: 'sa19.giamping.com', ip: '149.104.71.236', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA20', host: 'sa20.giamping.com', ip: '149.104.94.36', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA21', host: 'sa21.giamping.com', ip: '149.104.94.147', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA22', host: 'sa22.giamping.com', ip: '38.54.61.132', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA23', host: 'sa23.giamping.com', ip: '80.238.214.104', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA24', host: 'sa24.giamping.com', ip: '101.46.58.2', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA25', host: 'sa25.giamping.com', ip: '101.46.54.220', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA26', host: 'sa26.giamping.com', ip: '80.238.234.183', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA27', host: 'sa27.giamping.com', ip: '80.238.216.94', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA28', host: 'sa28.giamping.com', ip: '80.238.196.176', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA29', host: 'sa29.giamping.com', ip: '80.238.232.121', region: 'SA', papPreviouslyConnected: true),
  SstpServerEntry(id: 'SA30', host: 'sa30.giamping.com', ip: '80.238.229.106', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA31', host: 'sa31.giamping.com', ip: '80.238.234.109', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA32', host: 'sa32.giamping.com', ip: '80.238.232.255', region: 'SA', papPreviouslyConnected: true),
  SstpServerEntry(id: 'SA33', host: 'sa33.giamping.com', ip: '101.46.57.252', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA34', host: 'sa34.giamping.com', ip: '101.46.58.165', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA35', host: 'sa35.giamping.com', ip: '149.104.105.238', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA36', host: 'sa36.giamping.com', ip: '130.94.57.132', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA37', host: 'sa37.giamping.com', ip: '149.104.105.131', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA38', host: 'sa38.giamping.com', ip: '149.104.105.50', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA39', host: 'sa39.giamping.com', ip: '130.94.57.70', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA40', host: 'sa40.giamping.com', ip: '130.94.57.155', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA41', host: 'sa41.giamping.com', ip: '84.8.97.28', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA42', host: 'sa42.giamping.com', ip: '130.110.117.81', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA43', host: 'sa43.giamping.com', ip: '145.241.104.234', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA44', host: 'sa44.giamping.com', ip: '158.101.240.238', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA45', host: 'sa45.giamping.com', ip: '84.8.115.190', region: 'SA', papPreviouslyConnected: false),
  SstpServerEntry(id: 'SA46', host: 'sa46.giamping.com', ip: '193.122.94.3', region: 'SA', papPreviouslyConnected: true),
  SstpServerEntry(id: 'AE02', host: 'ae02.giamping.com', ip: '154.90.55.30', region: 'AE', papPreviouslyConnected: false),
  SstpServerEntry(id: 'AE03', host: 'ae03.giamping.com', ip: '38.60.202.125', region: 'AE', papPreviouslyConnected: false),
  SstpServerEntry(id: 'AE04', host: 'ae04.giamping.com', ip: '38.54.8.147', region: 'AE', papPreviouslyConnected: false),
  SstpServerEntry(id: 'AE05', host: 'ae05.giamping.com', ip: '95.174.68.201', region: 'AE', papPreviouslyConnected: false),
  SstpServerEntry(id: 'AE06', host: 'ae06.giamping.com', ip: '217.195.200.95', region: 'AE', papPreviouslyConnected: false),
  SstpServerEntry(id: 'AE07', host: 'ae07.giamping.com', ip: '109.61.42.220', region: 'AE', papPreviouslyConnected: false),
  SstpServerEntry(id: 'AE08', host: 'ae08.giamping.com', ip: '130.94.45.232', region: 'AE', papPreviouslyConnected: false),
  SstpServerEntry(id: 'AE09', host: 'ae09.giamping.com', ip: '38.54.76.238', region: 'AE', papPreviouslyConnected: false),
  SstpServerEntry(id: 'AE10', host: 'ae10.giamping.com', ip: '38.60.236.184', region: 'AE', papPreviouslyConnected: false),
  SstpServerEntry(id: 'AE11', host: 'ae11.giamping.com', ip: '109.61.18.152', region: 'AE', papPreviouslyConnected: false),
  SstpServerEntry(id: 'AE12', host: 'ae12.giamping.com', ip: '85.234.73.110', region: 'AE', papPreviouslyConnected: false),
  SstpServerEntry(id: 'AE13', host: 'ae13.giamping.com', ip: '109.61.18.10', region: 'AE', papPreviouslyConnected: false),
];
