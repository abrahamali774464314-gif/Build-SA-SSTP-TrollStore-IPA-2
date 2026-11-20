//
//  SstpFlutterPlugin.m
//  SA SSTP iOS host application
//

#import "SstpFlutterPlugin.h"
#import <NetworkExtension/NetworkExtension.h>
#import <UIKit/UIKit.h>
#import <ExtParser/PDVPNManager.h>
#import <ExtParser/PDBase64.h>
#import <vpn_adapter_ios/NodeModel.h>

static NSString * const kSAAppGroupIdentifier = @"group.com.example.sstpFlutterExample";
static NSString * const kSAExtensionBundleIdentifier =
    @"com.example.sstpFlutterExample.sstp-extension0";
static NSString * const kSAProfileDescription = @"SA SSTP";

@interface SstpFlutterPlugin ()

@property (nonatomic, strong) NodeModel *modal;
@property (nonatomic, strong) NETunnelProviderManager *vpnManager;

@end

@implementation SstpFlutterPlugin {
    FlutterMethodChannel *_iOSToFlutterChannel;
}

+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar> *)registrar {
    // The Packet Tunnel extension reads its shared files from this App Group.
    [PDVPNManager setGroupID:kSAAppGroupIdentifier];

    SstpFlutterPlugin *instance = [[SstpFlutterPlugin alloc] init];
    instance->_iOSToFlutterChannel =
        [FlutterMethodChannel methodChannelWithName:@"responseReceiver"
                                    binaryMessenger:[registrar messenger]];

    FlutterMethodChannel *channel =
        [FlutterMethodChannel methodChannelWithName:@"sstp_flutter"
                                    binaryMessenger:[registrar messenger]];
    [registrar addMethodCallDelegate:instance channel:channel];
}

- (void)handleMethodCall:(FlutterMethodCall *)call result:(FlutterResult)result {
    if ([@"getPlatformVersion" isEqualToString:call.method]) {
        result([@"iOS " stringByAppendingString:[[UIDevice currentDevice] systemVersion]]);
        return;
    }

    if ([@"saveServer" isEqualToString:call.method]) {
        self.modal = [[NodeModel alloc] init];
        self.modal.nodeName = @"SSTP";
        self.modal.TLS = [call.arguments[@"enableTLS"] boolValue];
        self.modal.CHAP = [call.arguments[@"enableCHAP"] boolValue];
        self.modal.MSCHAP2 = [call.arguments[@"enableMSCHAP2"] boolValue];
        self.modal.PAP = [call.arguments[@"enablePAP"] boolValue];
        self.modal.server = [NSString stringWithFormat:@"%@", call.arguments[@"hostName"] ?: @""];
        self.modal.serverName = [NSString stringWithFormat:@"%@", call.arguments[@"serverName"] ?: call.arguments[@"hostName"] ?: @""];
        self.modal.port = [NSString stringWithFormat:@"%@", call.arguments[@"sslPort"] ?: @"1194"];
        self.modal.username = [NSString stringWithFormat:@"%@", call.arguments[@"userName"] ?: @""];
        self.modal.password = [NSString stringWithFormat:@"%@", call.arguments[@"password"] ?: @""];
        [NodeModel shareInstance].selectNode = self.modal;
        result(@(YES));
        return;
    }

    if ([@"takePermission" isEqualToString:call.method]) {
        [self ensureVPNConfigurationWithCompletion:^(NSError *error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (error) {
                    result([FlutterError errorWithCode:@"VPN_PERMISSION_OR_PROFILE_FAILED"
                                               message:error.localizedDescription
                                               details:@(error.code)]);
                } else {
                    result(@(YES));
                }
            });
        }];
        return;
    }

    if ([@"connect" isEqualToString:call.method]) {
        if (self.modal == nil || self.modal.server.length == 0 ||
            self.modal.username.length == 0 || self.modal.password.length == 0) {
            result([FlutterError errorWithCode:@"INVALID_SSTP_PROFILE"
                                       message:@"Missing SSTP server or credentials"
                                       details:nil]);
            return;
        }

        NSString *sni = self.modal.serverName.length > 0
            ? self.modal.serverName : self.modal.server;

        // The PacketTunnelProvider parser accepts Base64("username:password")
        // in the URL user field. Do not place the raw password in the URI.
        NSString *credentials = [NSString stringWithFormat:@"%@:%@",
                                 self.modal.username, self.modal.password];

        NSURLComponents *components = [NSURLComponents new];
        components.scheme = @"sstp";
        components.host = self.modal.server; // TCP destination: IP address
        components.port = @([self.modal.port intValue]);
        components.user = [PDBase64 encode:credentials];
        components.password = nil;
        components.queryItems = @[
            [NSURLQueryItem queryItemWithName:@"domain" value:sni], // TLS SNI / certificate name
            [NSURLQueryItem queryItemWithName:@"pap_enable" value:(self.modal.PAP ? @"1" : @"0")],
            [NSURLQueryItem queryItemWithName:@"chap_enable" value:(self.modal.CHAP ? @"1" : @"0")],
            [NSURLQueryItem queryItemWithName:@"mschap2_enable" value:(self.modal.MSCHAP2 ? @"1" : @"0")],
            [NSURLQueryItem queryItemWithName:@"allowInsecure" value:@"0"]
        ];

        NSString *uri = components.URL.absoluteString;
        if (uri.length == 0) {
            result([FlutterError errorWithCode:@"INVALID_SSTP_URI"
                                       message:@"Could not construct SSTP connection URI"
                                       details:nil]);
            return;
        }

        if (self.vpnManager != nil) {
            [self startTunnelURI:uri result:result];
        } else {
            [self ensureVPNConfigurationWithCompletion:^(NSError *error) {
                if (error) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        result([FlutterError errorWithCode:@"VPN_PROFILE_NOT_READY"
                                                   message:error.localizedDescription
                                                   details:@(error.code)]);
                    });
                    return;
                }
                [self startTunnelURI:uri result:result];
            }];
        }
        return;
    }

    if ([@"disconnect" isEqualToString:call.method]) {
        [self.vpnManager.connection stopVPNTunnel];
        result(@(YES));
        return;
    }

    if ([@"checkLastConnectionStatus" isEqualToString:call.method]) {
        if (self.vpnManager != nil) {
            result([self statusStringForVPNStatus:self.vpnManager.connection.status]);
            return;
        }

        [NETunnelProviderManager loadAllFromPreferencesWithCompletionHandler:
         ^(NSArray<NETunnelProviderManager *> *managers, NSError *error) {
            if (error) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    result(@"Disconnected");
                });
                return;
            }

            for (NETunnelProviderManager *candidate in managers) {
                NEVPNProtocol *configuration = candidate.protocolConfiguration;
                if ([configuration isKindOfClass:[NETunnelProviderProtocol class]]) {
                    NETunnelProviderProtocol *provider = (NETunnelProviderProtocol *)configuration;
                    if ([provider.providerBundleIdentifier isEqualToString:kSAExtensionBundleIdentifier]) {
                        self.vpnManager = candidate;
                        [self registerVPNStatusObserver];
                        break;
                    }
                }
            }

            NSString *status = [self statusStringForVPNStatus:self.vpnManager.connection.status];
            dispatch_async(dispatch_get_main_queue(), ^{
                result(status);
            });
        }];
        return;
    }

    result(FlutterMethodNotImplemented);
}

- (void)startTunnelURI:(NSString *)uri result:(FlutterResult)result {
    NSError *startError = nil;
    @try {
        [self.vpnManager.connection startVPNTunnelWithOptions:@{ @"uri" : uri }
                                                       error:&startError];
    } @catch (NSException *exception) {
        startError = [NSError errorWithDomain:@"SA_SSTP"
                                         code:1
                                     userInfo:@{NSLocalizedDescriptionKey: exception.reason ?: @"VPN start exception"}];
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        if (startError) {
            result([FlutterError errorWithCode:@"VPN_START_FAILED"
                                       message:startError.localizedDescription
                                       details:@(startError.code)]);
        } else {
            result(@(YES));
        }
    });
}

- (void)ensureVPNConfigurationWithCompletion:(void (^)(NSError *error))completion {
    __weak typeof(self) weakSelf = self;

    [NETunnelProviderManager loadAllFromPreferencesWithCompletionHandler:
     ^(NSArray<NETunnelProviderManager *> *managers, NSError *loadError) {
        if (loadError) {
            completion(loadError);
            return;
        }

        NETunnelProviderManager *manager = nil;
        for (NETunnelProviderManager *candidate in managers) {
            NEVPNProtocol *configuration = candidate.protocolConfiguration;
            if ([configuration isKindOfClass:[NETunnelProviderProtocol class]]) {
                NETunnelProviderProtocol *provider = (NETunnelProviderProtocol *)configuration;
                if ([provider.providerBundleIdentifier isEqualToString:kSAExtensionBundleIdentifier]) {
                    manager = candidate;
                    break;
                }
            }
        }

        if (manager == nil) {
            manager = [[NETunnelProviderManager alloc] init];
        }

        NETunnelProviderProtocol *provider = [[NETunnelProviderProtocol alloc] init];
        provider.providerBundleIdentifier = kSAExtensionBundleIdentifier;
        provider.serverAddress = weakSelf.modal.serverName.length > 0
            ? weakSelf.modal.serverName
            : (weakSelf.modal.server.length > 0 ? weakSelf.modal.server : kSAProfileDescription);
        provider.providerConfiguration = @{ @"protocol" : @"sstp" };

        manager.protocolConfiguration = provider;
        manager.localizedDescription = kSAProfileDescription;
        manager.enabled = YES;

        [manager saveToPreferencesWithCompletionHandler:^(NSError *saveError) {
            if (saveError) {
                completion(saveError);
                return;
            }

            [manager loadFromPreferencesWithCompletionHandler:^(NSError *reloadError) {
                if (reloadError) {
                    completion(reloadError);
                    return;
                }

                weakSelf.vpnManager = manager;
                [weakSelf registerVPNStatusObserver];
                completion(nil);
            }];
        }];
    }];
}

- (void)registerVPNStatusObserver {
    if (self.vpnManager == nil) return;

    [[NSNotificationCenter defaultCenter] removeObserver:self
                                                    name:NEVPNStatusDidChangeNotification
                                                  object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(vpnConnectionStatusDidChange:)
                                                 name:NEVPNStatusDidChangeNotification
                                               object:self.vpnManager.connection];
}

- (NSString *)statusStringForVPNStatus:(NEVPNStatus)status {
    switch (status) {
        case NEVPNStatusConnected:
            return @"Connected";
        case NEVPNStatusConnecting:
        case NEVPNStatusReasserting:
            return @"Connecting";
        case NEVPNStatusDisconnecting:
            return @"Disconnecting";
        case NEVPNStatusDisconnected:
        case NEVPNStatusInvalid:
        default:
            return @"Disconnected";
    }
}

- (void)vpnConnectionStatusDidChange:(NSNotification *)notification {
    if (self.vpnManager == nil) return;

    NSString *status = [self statusStringForVPNStatus:self.vpnManager.connection.status];
    [[NSUserDefaults standardUserDefaults] setObject:status forKey:@"lastConnectionStatus"];

    NSDictionary *data = @{ @"status" : status };
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self->_iOSToFlutterChannel) {
            [self->_iOSToFlutterChannel invokeMethod:@"connectResponse" arguments:data];
        }
    });
}

@end
