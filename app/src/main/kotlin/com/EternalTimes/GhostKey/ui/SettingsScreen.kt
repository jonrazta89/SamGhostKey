package com.EternalTimes.GhostKey.ui

import android.content.Context
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.EternalTimes.GhostKey.R
import com.EternalTimes.GhostKey.ui.theme.CvePalette
import com.EternalTimes.GhostKey.viewmodel.ExploitViewModel
import com.EternalTimes.GhostKey.viewmodel.ManagerOption

/**
 * 设置页：内核 Profile 选择 / 导入（IMG·JSON·HOCON）/ 导出（文件名含版本号）/
 * 已导入管理 / Root 管理器检测 / 运行日志入口。
 *
 * 颜色与风格完全沿用 CvePalette 与 MaterialTheme，与主页保持一致。
 */
@Composable
fun SettingsScreen(
    viewModel: ExploitViewModel,
    onBack: () -> Unit,
    onOpenLogs: () -> Unit,
) {
    val uiState by viewModel.uiState.collectAsState()
    val context = LocalContext.current
    var showProfilePicker by remember { mutableStateOf(false) }
    var showManagerPicker by remember { mutableStateOf(false) }
    var pendingExport by remember { mutableStateOf("") }

    // Extract string resources at Composable scope
    val exportedToDownloadStr = stringResource(R.string.exported_to_download)
    val exportFailedStr = stringResource(R.string.export_failed)

    val imgPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) viewModel.importImageFromUri(uri, queryDisplayName(context, uri))
    }
    val textPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) viewModel.importTextFromUri(uri, queryDisplayName(context, uri))
    }
    val createDoc = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
        if (uri != null) {
            runCatching {
                context.contentResolver.openOutputStream(uri)?.use {
                    it.write(pendingExport.toByteArray(Charsets.UTF_8))
                }
            }.onSuccess {
                Toast.makeText(context, exportedToDownloadStr.replace("%s", queryDisplayName(context, uri)), Toast.LENGTH_SHORT).show()
            }.onFailure {
                Toast.makeText(context, exportFailedStr.replace("%s", it.message.orEmpty()), Toast.LENGTH_SHORT).show()
            }
        }
    }

    val stored = viewModel.storedProfiles()
    val selected = uiState.selectedProfileRelease

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(CvePalette.Backdrop)
            .statusBarsPadding(),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            TextButton(onClick = onBack) {
                Text(stringResource(R.string.back), color = CvePalette.Accent, style = MaterialTheme.typography.labelLarge)
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.settings_title), style = MaterialTheme.typography.titleLarge, color = CvePalette.TextPrimary)
                Text(
                    stringResource(R.string.kernel_profiles_subtitle),
                    style = MaterialTheme.typography.labelSmall,
                    color = CvePalette.TextMuted,
                )
            }
        }
        HorizontalDivider(color = CvePalette.Outline, thickness = 1.dp)

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            SettingsCard(title = stringResource(R.string.kernel_profiles)) {
                Text(
                    stringResource(R.string.current_profile) + (selected ?: stringResource(R.string.auto_adapt_current)),
                    color = CvePalette.TextPrimary,
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    stringResource(R.string.device_kernel, uiState.kernelRelease),
                    color = CvePalette.TextSecondary,
                    style = MaterialTheme.typography.bodySmall,
                )
                Text(
                    stringResource(R.string.matched_profile, uiState.matchedProfile),
                    color = CvePalette.TextSecondary,
                    style = MaterialTheme.typography.bodySmall,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { showProfilePicker = true }) {
                        Text(stringResource(R.string.select_kernel))
                    }
                    OutlinedButton(onClick = {
                        pendingExport = viewModel.buildExportText()
                        createDoc.launch(viewModel.exportFileName())
                    }) {
                        Text(stringResource(R.string.export_current_profile))
                    }
                }
                Text(
                    stringResource(R.string.export_filename_version, appVersion(context)),
                    color = CvePalette.TextMuted,
                    style = MaterialTheme.typography.labelSmall,
                )
            }

            SettingsCard(title = stringResource(R.string.import_profile)) {
                Text(
                    stringResource(R.string.import_description),
                    color = CvePalette.TextMuted,
                    style = MaterialTheme.typography.bodySmall,
                )
                Button(onClick = { imgPicker.launch(arrayOf("*/*")) }) {
                    Text(stringResource(R.string.import_boot_img))
                }
                OutlinedButton(onClick = {
                    textPicker.launch(
                        arrayOf("application/json", "text/plain", "application/octet-stream", "*/*"),
                    )
                }) {
                    Text(stringResource(R.string.import_json_hocon))
                }
                if (uiState.importMessage.isNotBlank()) {
                    val color = when {
                        uiState.importMessage.contains(stringResource(R.string.import_failed).split(":")[0]) -> CvePalette.Danger
                        uiState.importMessage.contains(stringResource(R.string.profile_missing_fields).split(":")[0]) -> CvePalette.Warning
                        else -> CvePalette.Success
                    }
                    Text(
                        uiState.importMessage,
                        color = color,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }

            SettingsCard(title = stringResource(R.string.imported_profiles, stored.size)) {
                if (stored.isEmpty()) {
                    Text(stringResource(R.string.no_profiles_yet), color = CvePalette.TextMuted, style = MaterialTheme.typography.bodySmall)
                } else {
                    stored.forEach { sp ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    sp.release,
                                    color = CvePalette.TextPrimary,
                                    style = MaterialTheme.typography.bodySmall,
                                    maxLines = 2,
                                    overflow = TextOverflow.Ellipsis,
                                )
                                Text(
                                    if (sp.complete) stringResource(R.string.profile_fields_complete) else stringResource(R.string.profile_missing_fields, sp.missing.joinToString()),
                                    color = if (sp.complete) CvePalette.Success else CvePalette.Warning,
                                    style = MaterialTheme.typography.labelSmall,
                                    maxLines = 2,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                            TextButton(onClick = { viewModel.deleteStoredProfile(sp.fileName) }) {
                                Text(stringResource(R.string.delete), color = CvePalette.Danger, style = MaterialTheme.typography.labelLarge)
                            }
                        }
                        HorizontalDivider(color = CvePalette.Outline, thickness = 1.dp)
                    }
                }
            }

            SettingsCard(title = stringResource(R.string.root_manager)) {
                val cands = uiState.managerCandidates
                /*
                 * Detection is async; initial UI gets "still scanning" intermediate state.
                 * Not distinguishing "still scanning" from "scanned, nothing found" makes users
                 * think "no manager detected".
                 */
                val scanning = uiState.managerScanning
                Text(
                    stringResource(R.string.detected) + when {
                        scanning -> stringResource(R.string.scanning_managers)
                        uiState.managerScanError.isNotBlank() -> stringResource(R.string.scan_error, uiState.managerScanError)
                        else -> uiState.detectedManager.ifBlank { stringResource(R.string.no_managers_found) }
                    },
                    color = if (uiState.managerScanError.isNotBlank() && !scanning) {
                        CvePalette.Warning
                    } else {
                        CvePalette.TextPrimary
                    },
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    stringResource(R.string.ksu_source) + when {
                        scanning -> stringResource(R.string.scanning_managers)
                        else -> uiState.ksuSourceLabel.ifBlank { stringResource(R.string.ksu_source_bundled) }
                    },
                    color = CvePalette.TextSecondary,
                    style = MaterialTheme.typography.bodySmall,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { viewModel.detectKsuSource(force = true) }) {
                        Text(stringResource(R.string.rescan))
                    }
                    if (cands.size > 1) {
                        Button(onClick = { showManagerPicker = true }) {
                            Text(stringResource(R.string.select_manager))
                        }
                    }
                }
                if (cands.size > 1) {
                    Text(
                        stringResource(R.string.current_selection, uiState.selectedManagerPackage ?: stringResource(R.string.auto_priority_first)),
                        color = CvePalette.TextSecondary,
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Text(
                        stringResource(R.string.manager_detected_explanation, cands.size),
                        color = CvePalette.TextMuted,
                        style = MaterialTheme.typography.labelSmall,
                    )
                } else {
                    Text(
                        stringResource(R.string.prefer_device_ksud_explanation),
                        color = CvePalette.TextMuted,
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
            }

            SettingsCard(title = stringResource(R.string.logs)) {
                /* Count held by ViewModel and refreshed on add/delete; previously here used
                   remember { viewModel.listRunLogs().size }, only computed once and on main thread doing disk IO,
                   after a ROOT run you'd still see old number. */
                val runCount = uiState.runLogCount
                OutlinedButton(onClick = onOpenLogs) {
                    Text(stringResource(R.string.view_run_logs, runCount))
                }
                Text(
                    stringResource(R.string.run_logs_description),
                    color = CvePalette.TextMuted,
                    style = MaterialTheme.typography.labelSmall,
                )
            }
        }
    }

    if (showProfilePicker) {
        ProfilePickerDialog(
            options = listOf<String?>(null) + viewModel.knownReleases(),
            selected = selected,
            onPick = { r ->
                viewModel.selectProfile(r)
                showProfilePicker = false
            },
            onDismiss = { showProfilePicker = false },
        )
    }

    if (showManagerPicker) {
        ManagerPickerDialog(
            options = uiState.managerCandidates,
            selected = uiState.selectedManagerPackage,
            onPick = { pkg ->
                viewModel.selectManager(pkg)
                showManagerPicker = false
            },
            onDismiss = { showManagerPicker = false },
        )
    }
}

@Composable
private fun SettingsCard(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(CvePalette.Surface, RoundedCornerShape(12.dp))
            .border(1.dp, CvePalette.Outline, RoundedCornerShape(12.dp))
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(title, style = MaterialTheme.typography.titleSmall, color = CvePalette.TextPrimary)
        content()
    }
}

@Composable
private fun ProfilePickerDialog(
    options: List<String?>,
    selected: String?,
    onPick: (String?) -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel), color = CvePalette.TextMuted)
            }
        },
        title = {
            Text(stringResource(R.string.select_target_profile), color = CvePalette.TextPrimary)
        },
        text = {
            Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                options.forEach { opt ->
                    val isSelected = opt == selected
                    val label = opt ?: stringResource(R.string.auto_adapt_current)
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onPick(opt) }
                            .padding(vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            if (isSelected) "●" else "○",
                            color = if (isSelected) CvePalette.Accent else CvePalette.TextMuted,
                            style = MaterialTheme.typography.bodySmall,
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            label,
                            color = CvePalette.TextSecondary,
                            style = MaterialTheme.typography.bodySmall,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    HorizontalDivider(color = CvePalette.Outline, thickness = 1.dp)
                }
            }
        },
        containerColor = CvePalette.Surface,
    )
}

/** Multi-manager picker dialog: null = auto (priority first), otherwise take over by selected package name. */
@Composable
private fun ManagerPickerDialog(
    options: List<ManagerOption>,
    selected: String?,
    onPick: (String?) -> Unit,
    onDismiss: () -> Unit,
) {
    val rows = listOf<ManagerOption?>(null) + options
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel), color = CvePalette.TextMuted)
            }
        },
        title = {
            Text(stringResource(R.string.select_takeover_manager), color = CvePalette.TextPrimary)
        },
        text = {
            Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                rows.forEach { opt ->
                    val pkg = opt?.packageName
                    val isSelected = pkg == selected
                    val label = opt?.label ?: stringResource(R.string.auto_priority_first)
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onPick(pkg) }
                            .padding(vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            if (isSelected) "●" else "○",
                            color = if (isSelected) CvePalette.Accent else CvePalette.TextMuted,
                            style = MaterialTheme.typography.bodySmall,
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            label,
                            color = CvePalette.TextSecondary,
                            style = MaterialTheme.typography.bodySmall,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    HorizontalDivider(color = CvePalette.Outline, thickness = 1.dp)
                }
            }
        },
        containerColor = CvePalette.Surface,
    )
}

/** 查询 SAF Uri 的显示名（失败则回退到最后路径段）。 */
private fun queryDisplayName(context: Context, uri: Uri): String {
    val proj = arrayOf(android.provider.OpenableColumns.DISPLAY_NAME)
    val name = runCatching {
        context.contentResolver.query(uri, proj, null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                val idx = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                if (idx >= 0) c.getString(idx) else null
            } else null
        }
    }.getOrNull()
    return name ?: uri.lastPathSegment ?: "imported"
}

private fun appVersion(context: Context): String = runCatching {
    context.packageManager.getPackageInfo(context.packageName, 0).versionName
}.getOrNull() ?: "unknown"
