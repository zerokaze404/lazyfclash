import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/enum/enum.dart';

import 'profile.dart';

Profile applyDefaultProfileImportHook(Profile profile) {
  return profile.copyWith(
    overwriteType: OverwriteType.script,
    scriptId: defaultProfileScriptId,
  );
}
