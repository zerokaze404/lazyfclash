// ignore_for_file: constant_identifier_names

import 'dart:math';
import 'dart:ui';

import 'package:collection/collection.dart';
import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:material_ui/material_ui.dart';

const appName = 'FlClash';
const appHelperService = 'FlClashHelperService';
const coreManifestName = 'manifest.json';
const coreName = 'clash.meta';
const browserUa =
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
const packageName = 'com.follow.clash';
final unixSocketPath = '/tmp/FlClashSocket_${Random().nextInt(10000)}.sock';
final windowsPipeName = '\\\\.\\pipe\\FlClashCore_${_randomPipeId()}';
const helperPort = 47890;
const helperSocketPath = '/run/flclash/helper.sock';
const helperProtocolVersionHeader = 'x-flclash-helper-protocol';
const helperProtocolVersion = '6';
const maxTextScale = 1.4;
const minTextScale = 0.8;
final baseInfoEdgeInsets = EdgeInsets.symmetric(
  vertical: 16.mAp,
  horizontal: 16.mAp,
);
final listHeaderPadding = EdgeInsets.only(
  left: 16.mAp,
  right: 8.mAp,
  top: 24.mAp,
  bottom: 8.mAp,
);
const sheetAppBarHeight = 68.0;

const watchExecution = false;

String _randomPipeId() {
  final random = Random.secure();
  return List.generate(
    16,
    (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0'),
  ).join();
}

final defaultTextScaleFactor =
    WidgetsBinding.instance.platformDispatcher.textScaleFactor;

/// How long the Core may spend on one delay test. It spends this twice in the
/// worst case - once queueing for a slot, once on the probe itself - so the
/// guard below has to outlast twice this value.
const delayTestTimeoutDuration = Duration(seconds: 8);

const delayTestGuardDuration = Duration(seconds: 30);

const coreConnectionWaitDuration = Duration(seconds: 10);

/// Keep at or below the Core's delay-test concurrency (`delayTestConcurrency`
/// in core/common.go).
const maxConcurrentDelayTests = 16;
const animateDuration = Duration(milliseconds: 100);
const midDuration = Duration(milliseconds: 200);
const commonDuration = Duration(milliseconds: 300);
const defaultUpdateDuration = Duration(days: 1);
const MMDB = 'GEOIP.metadb';
const ASN = 'ASN.mmdb';
const GEOIP = 'GEOIP.dat';
const GEOSITE = 'GEOSITE.dat';
final double kHeaderHeight = getWindowHeaderHeight(
  isDesktop: system.isDesktop,
  isMacOS: system.isMacOS,
);
const profilesDirectoryName = 'profiles';
const providersDirectoryName = 'providers';
const proxiesProviderDirectoryName = 'proxies';
const rulesProviderDirectoryName = 'rules';
const localhost = '127.0.0.1';
const clashConfigKey = 'clash_config';
const configKey = 'config';
const systemDnsRecordKey = 'system_dns_record';
const bootRecordKey = 'boot_record';
const defaultSystemDnsFallback = '223.5.5.5';
const double dialogCommonWidth = 300;
const repository = 'chen08209/FlClash';
const maxMobileWidth = 600;
const maxLaptopWidth = 840;
const defaultTestUrl = 'https://www.gstatic.com/generate_204';
final commonFilter = ImageFilter.blur(
  sigmaX: 5,
  sigmaY: 5,
  tileMode: TileMode.clamp,
);

const stringListEquality = ListEquality<String>();
const intListEquality = ListEquality<int>();
const ruleListEquality = ListEquality<Rule>();
const scriptListEquality = ListEquality<Script>();
const profileListEquality = ListEquality<Profile>();
const proxyGroupsEquality = ListEquality<ProxyGroup>();
const hotKeyActionListEquality = ListEquality<HotKeyAction>();
const stringAndStringMapEntryListEquality =
    ListEquality<MapEntry<String, String>>();
const keyboardModifierListEquality = SetEquality<KeyboardModifier>();

const proxiesListStoreKey = PageStorageKey<String>('proxies_list');
const toolsStoreKey = PageStorageKey<String>('tools');
const profilesStoreKey = PageStorageKey<String>('profiles');

const defaultPrimaryColor = 0XFFD8C0C3;

double getWidgetHeight(num lines) {
  final space = 14.mAp;
  return max(lines * (80.ap + space) - space, 0);
}

const maxLogsLength = 5000;
const maxRequestsLength = 2000;
const pausedMaxLogsLength = maxLogsLength * 2;
const pausedMaxRequestsLength = maxRequestsLength * 2;

const trafficSampleLength = 30;

const defaultPrimaryColors = [
  0xFF795548,
  0xFF03A9F4,
  0xFFFFFF00,
  0XFFBBC9CC,
  0XFFABD397,
  defaultPrimaryColor,
  0XFF665390,
];

const scriptTemplate = '''
const main = (config) => {
  return config;
}''';

const defaultProfileScriptId = -2026091901;
const defaultProfileScriptLabel = '懒猫微服共存规则';

const defaultProfileScript = r'''
function main(config) {
  if (!config.sniffer) config.sniffer = {};

  const snifferSkipDomains = ["+heiyu.space", "+lazycat.cloud"];
  if (!Array.isArray(config.sniffer["skip-domain"])) {
    config.sniffer["skip-domain"] = [];
  }
  for (const domain of snifferSkipDomains) {
    if (!config.sniffer["skip-domain"].includes(domain)) {
      config.sniffer["skip-domain"].push(domain);
    }
  }

  const skipAddresses = [
    "6.6.6.6/32",
    "2000::6666/128",
    "fc03:1136:3800::/40",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "169.254.0.0/16",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "fd00::/8",
    "fe80::/10",
    "::1/128",
  ];
  for (const key of ["skip-src-address", "skip-dst-address"]) {
    if (!Array.isArray(config.sniffer[key])) config.sniffer[key] = [];
    for (const address of skipAddresses) {
      if (!config.sniffer[key].includes(address)) {
        config.sniffer[key].push(address);
      }
    }
  }

  if (!config.tun) config.tun = {};
  const tunExclude = [
    "6.6.6.6/32",
    "2000::6666/128",
    "fc03:1136:3800::/40",
    "127.0.0.0/8",
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "fd00::/8",
    "fe80::/10",
    "::1/128",
  ];
  if (!Array.isArray(config.tun["route-exclude-address"])) {
    config.tun["route-exclude-address"] = [];
  }
  for (const address of tunExclude) {
    if (!config.tun["route-exclude-address"].includes(address)) {
      config.tun["route-exclude-address"].push(address);
    }
  }

  if (!config.dns) config.dns = {};
  config.dns["fake-ip-filter-mode"] = "blacklist";
  if (!Array.isArray(config.dns["fake-ip-filter"])) {
    config.dns["fake-ip-filter"] = [];
  }
  for (const domain of ["+heiyu.space", "+lazycat.cloud"]) {
    if (!config.dns["fake-ip-filter"].includes(domain)) {
      config.dns["fake-ip-filter"].push(domain);
    }
  }

  const proxyName = "懒猫微服";
  const groupName = "懒猫微服策略";
  const proxy = {
    name: proxyName,
    type: "http",
    server: "127.0.0.1",
    port: 31085,
  };
  if (!Array.isArray(config.proxies)) config.proxies = [];
  const proxyIndex = config.proxies.findIndex((item) => item.name === proxyName);
  if (proxyIndex === -1) {
    config.proxies.push(proxy);
  } else {
    config.proxies[proxyIndex] = {...config.proxies[proxyIndex], ...proxy};
  }

  if (!Array.isArray(config["proxy-groups"])) config["proxy-groups"] = [];
  const group = {name: groupName, type: "select", proxies: ["DIRECT", proxyName]};
  const groupIndex = config["proxy-groups"].findIndex(
    (item) => item.name === groupName,
  );
  if (groupIndex === -1) {
    config["proxy-groups"].unshift(group);
  } else {
    const existing = config["proxy-groups"][groupIndex];
    existing.type = "select";
    if (!Array.isArray(existing.proxies)) existing.proxies = [];
    for (const item of group.proxies) {
      if (!existing.proxies.includes(item)) existing.proxies.push(item);
    }
  }

  const rules = [
    "PROCESS-NAME,懒猫微服,DIRECT",
    "PROCESS-NAME,lzc-core.darwin,DIRECT",
    "DOMAIN,appstore.api.lazycat.cloud,DIRECT",
    "DOMAIN,dl.lazycat.cloud,DIRECT",
    `DOMAIN-SUFFIX,heiyu.space,${groupName}`,
    `DOMAIN-SUFFIX,lazycat.cloud,${groupName}`,
  ];
  if (!Array.isArray(config.rules)) config.rules = [];
  config.rules = config.rules.filter((rule) => !rules.includes(rule));
  config.rules = [...rules, ...config.rules];
  return config;
}''';

const backupDatabaseName = 'database.sqlite';
const configJsonName = 'config.json';
