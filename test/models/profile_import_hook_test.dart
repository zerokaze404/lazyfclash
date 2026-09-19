import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('applies the bundled script to imported profiles', () {
    final profile = Profile.normal(label: 'imported');

    final hooked = applyDefaultProfileImportHook(profile);

    expect(hooked.overwriteType, OverwriteType.script);
    expect(hooked.scriptId, defaultProfileScriptId);
    expect(hooked.label, profile.label);
    expect(hooked.url, profile.url);
  });
}
