import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Local-only settings. Custom servers are not secret; credentials are stored
/// separately using the operating system's protected credential storage.
class SstpSavedState {
  final List<Map<String, dynamic>> customServers;
  final String? selectedId;
  final String region;
  final String authMethod;
  final bool rememberLogin;
  final String username;
  final String password;
  final bool credentialsUnavailable;

  const SstpSavedState({
    required this.customServers,
    required this.selectedId,
    required this.region,
    required this.authMethod,
    required this.rememberLogin,
    required this.username,
    required this.password,
    required this.credentialsUnavailable,
  });
}

class SstpLocalStore {
  static const _customKey = 'sa_sstp_custom_servers_v1';
  static const _selectedKey = 'sa_sstp_selected_server_v1';
  static const _regionKey = 'sa_sstp_region_v1';
  static const _authKey = 'sa_sstp_auth_v1';
  static const _rememberKey = 'sa_sstp_remember_login_v1';
  static const _usernameKey = 'sa_sstp_saved_username_v1';
  static const _passwordKey = 'sa_sstp_saved_password_v1';

  final FlutterSecureStorage _secure = const FlutterSecureStorage();

  Future<SstpSavedState> load() async {
    final prefs = await SharedPreferences.getInstance();
    final custom = <Map<String, dynamic>>[];
    for (final raw in prefs.getStringList(_customKey) ?? <String>[]) {
      try {
        final decoded = jsonDecode(raw);
        if (decoded is Map<String, dynamic>) custom.add(decoded);
      } catch (_) {
        // Skip a damaged record without losing the rest of the list.
      }
    }

    final remember = prefs.getBool(_rememberKey) ?? true;
    var user = '';
    var password = '';
    var unavailable = false;
    if (remember) {
      try {
        user = await _secure.read(key: _usernameKey) ?? '';
        password = await _secure.read(key: _passwordKey) ?? '';
      } catch (_) {
        unavailable = true;
      }
    }

    return SstpSavedState(
      customServers: custom,
      selectedId: prefs.getString(_selectedKey),
      region: prefs.getString(_regionKey) ?? 'SA',
      authMethod: prefs.getString(_authKey) ?? 'PAP',
      rememberLogin: remember,
      username: user,
      password: password,
      credentialsUnavailable: unavailable,
    );
  }

  Future<void> saveCustomServers(List<Map<String, dynamic>> servers) async {
    final prefs = await SharedPreferences.getInstance();
    final success = await prefs.setStringList(
      _customKey,
      servers.map(jsonEncode).toList(),
    );
    if (!success) throw StateError('Could not save custom servers');
  }

  Future<void> saveSelection(String id, String region) async {
    final prefs = await SharedPreferences.getInstance();
    final savedId = await prefs.setString(_selectedKey, id);
    final savedRegion = await prefs.setString(_regionKey, region);
    if (!savedId || !savedRegion) {
      throw StateError('Could not save selection');
    }
  }

  Future<void> saveAuth(String method) async {
    final prefs = await SharedPreferences.getInstance();
    if (!await prefs.setString(_authKey, method)) {
      throw StateError('Could not save authentication method');
    }
  }

  Future<void> setRememberLogin(bool value) async {
    final prefs = await SharedPreferences.getInstance();
    if (!await prefs.setBool(_rememberKey, value)) {
      throw StateError('Could not update remember setting');
    }
    if (!value) await deleteCredentials();
  }

  Future<void> saveCredentials(String username, String password) async {
    await _secure.write(key: _usernameKey, value: username);
    await _secure.write(key: _passwordKey, value: password);
  }

  Future<void> deleteCredentials() async {
    await _secure.delete(key: _usernameKey);
    await _secure.delete(key: _passwordKey);
  }
}
