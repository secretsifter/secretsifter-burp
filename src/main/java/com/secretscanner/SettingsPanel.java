package com.secretscanner;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.File;
import java.nio.file.Files;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Swing settings tab shown in Burp's suite-level tab bar.
 *
 * Controls:
 *   - Global enable/disable toggle
 *   - Entropy threshold spinner (0.0 – 6.0, step 0.1)
 *   - PII scanning enable/disable
 *   - CDN blocklist text area (one entry per line)
 *
 * Settings are persisted to Burp's preference store on Save.
 */
public class SettingsPanel {

    private static final String CUSTOM_RULES_PLACEHOLDER =
            "# Format: RuleName | regex | severity  (HIGH / MEDIUM / LOW / INFORMATION)\n" +
            "# Lines starting with # are comments and are ignored by the scanner.\n" +
            "#\n" +
            "# -- Examples (remove the leading # to activate) --\n" +
            "#\n" +
            "# InternalToken   | INT-[0-9]{8}-[A-Z]{4}                | HIGH\n" +
            "# InternalApiKey  | [a-zA-Z0-9]{32,45}                   | MEDIUM\n" +
            "# CorpJwtAudience | iss=corp-[a-z]+-service               | INFORMATION\n" +
            "# InternalHost    | [a-z]+-service\\.corp\\.internal       | LOW\n" +
            "# HardcodedPass   | password\\s*=\\s*[\"'][^\"']{8,}[\"']   | HIGH\n";

    private final ScanSettings settings;
    private final MontoyaApi   api;

    // ---- Swing controls ----
    private JPanel       rootPanel;
    private ToggleSwitch enabledBox;
    private JSpinner     entropySpinner;
    private ToggleSwitch piiBox;
    private ToggleSwitch scanRequestsBox;
    private ToggleSwitch allowInsecureSslBox;
    private JTextArea    cdnArea;
    private JTextArea    keyBlocklistArea;
    private JTextArea    keyAllowlistArea;
    private JTextArea    customRulesArea;
    private ToggleSwitch customRulesEnabledBox;
    private ToggleSwitch customRulesOnlyBox;
    private JLabel       statusLabel;
    private JScrollPane settingsScrollPane;

    public SettingsPanel(ScanSettings settings, MontoyaApi api) {
        this.settings = settings;
        this.api      = api;
        // Build UI on the Event Dispatch Thread
        if (SwingUtilities.isEventDispatchThread()) {
            buildUi();
        } else {
            try {
                SwingUtilities.invokeAndWait(this::buildUi);
            } catch (Exception e) {
                SwingUtilities.invokeLater(this::buildUi);
            }
        }
    }

    /** Returns the Swing panel to register as a Burp suite tab. */
    public JComponent getPanel() {
        return rootPanel != null ? rootPanel : new JPanel();
    }

    // =========================================================================
    // UI construction
    // =========================================================================

    private void buildUi() {
        rootPanel = new JPanel(new BorderLayout(0, 6));
        rootPanel.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));

        // ── Header (above all sub-tabs, always visible) ──────────────────────
        JPanel headerPanel = new JPanel();
        headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.Y_AXIS));
        headerPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));

        JLabel nameLbl = new JLabel("SecretSifter");
        nameLbl.setFont(nameLbl.getFont().deriveFont(Font.BOLD, 22f));
        nameLbl.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel tagLbl = new JLabel("Live Credentials & Secrets Scanner");
        tagLbl.setFont(tagLbl.getFont().deriveFont(Font.PLAIN, 13f));
        tagLbl.setForeground(Color.GRAY);
        tagLbl.setAlignmentX(Component.LEFT_ALIGNMENT);

        headerPanel.add(nameLbl);
        headerPanel.add(Box.createVerticalStrut(2));
        headerPanel.add(tagLbl);
        rootPanel.add(headerPanel, BorderLayout.NORTH);

        // ── Sub-tab pane ──────────────────────────────────────────────────────
        JTabbedPane subTabs = new JTabbedPane();

        // ═══════════════════════════════════════════════════════════════════
        // TAB 1 — Scanner   (controls + 3 filter columns)
        // ═══════════════════════════════════════════════════════════════════
        JPanel scannerTab = new JPanel(new BorderLayout(4, 6));
        scannerTab.setBorder(BorderFactory.createEmptyBorder(6, 4, 4, 4));

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 4));
        topPanel.setBorder(new TitledBorder("Scanner Controls"));

        enabledBox = new ToggleSwitch("Enable passive scanning", settings.isEnabled());
        topPanel.add(enabledBox);

        topPanel.add(new JLabel("   Entropy threshold:"));
        SpinnerNumberModel model = new SpinnerNumberModel(
                settings.getEntropyThreshold(), 0.0, 6.0, 0.1);
        entropySpinner = new JSpinner(model);
        ((JSpinner.NumberEditor) entropySpinner.getEditor()).getFormat().setMaximumFractionDigits(1);
        entropySpinner.setPreferredSize(new Dimension(65, 24));
        entropySpinner.setToolTipText("Shannon entropy threshold (bits/char). Default: 3.5");
        topPanel.add(entropySpinner);

        piiBox = new ToggleSwitch("Enable PII detection (SSN, Credit Cards)", settings.isPiiEnabled());
        topPanel.add(piiBox);

        scanRequestsBox = new ToggleSwitch("Scan request headers / body for secrets", settings.isScanRequestsEnabled());
        scanRequestsBox.setToolTipText(
                "When enabled, scans outbound request headers (X-API-Key, Authorization, etc.) " +
                "and request bodies for hardcoded vendor tokens. " +
                "JWT Bearer tokens are automatically skipped. " +
                "Disable to reduce noise on high-traffic proxies.");
        topPanel.add(scanRequestsBox);

        allowInsecureSslBox = new ToggleSwitch("Allow insecure SSL (trust all certificates)", settings.isAllowInsecureSsl());
        allowInsecureSslBox.setToolTipText(
                "Saved for reference — SSL trust is now governed by Burp's project-level TLS settings " +
                "(Project Options > TLS > Server TLS Certificates). " +
                "For self-signed or internal certs, add the CA to Burp's trust store instead of enabling this option.");
        topPanel.add(allowInsecureSslBox);

        JLabel sslWarnLabel = new JLabel("  \u26a0 Disable only against trusted targets");
        sslWarnLabel.setForeground(new Color(180, 60, 0));
        sslWarnLabel.setFont(sslWarnLabel.getFont().deriveFont(Font.PLAIN, 11f));
        topPanel.add(sslWarnLabel);

        scannerTab.add(topPanel, BorderLayout.NORTH);

        // CDN blocklist
        JPanel cdnPanel = new JPanel(new BorderLayout(4, 4));
        cdnPanel.setBorder(new TitledBorder(
                "CDN / Third-Party Blocklist  (one entry per line — partial host match)"));
        cdnArea = new JTextArea(String.join("\n", settings.getCdnBlocklist()), 8, 20);
        cdnArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        cdnArea.setToolTipText("Responses from hosts matching any of these strings are skipped.");
        cdnPanel.add(new JScrollPane(cdnArea), BorderLayout.CENTER);
        cdnPanel.add(makeSearchBar(cdnArea), BorderLayout.SOUTH);

        // Key Name Blocklist
        JPanel keyBlockPanel = new JPanel(new BorderLayout(4, 4));
        keyBlockPanel.setBorder(new TitledBorder(
                "Key Name Blocklist  (suppress — one pattern per line, substring match)"));
        keyBlocklistArea = new JTextArea(String.join("\n", settings.getKeyBlocklist()), 8, 20);
        keyBlocklistArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        keyBlocklistArea.setToolTipText(
                "Findings whose matched key name contains any entry here are suppressed. " +
                "Example: add STORAGE_KEY_ to hide all localStorage constant names. " +
                "Allowlisted keys override this list.");
        keyBlockPanel.add(new JScrollPane(keyBlocklistArea), BorderLayout.CENTER);
        keyBlockPanel.add(makeSearchBar(keyBlocklistArea), BorderLayout.SOUTH);

        // Key Name Allowlist
        JPanel keyAllowPanel = new JPanel(new BorderLayout(4, 4));
        keyAllowPanel.setBorder(new TitledBorder(
                "Key Name Allowlist  (force-report — one pattern per line, substring match)"));
        keyAllowlistArea = new JTextArea(String.join("\n", settings.getKeyAllowlist()), 8, 20);
        keyAllowlistArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        keyAllowlistArea.setToolTipText(
                "Findings whose matched key name contains any entry here are always reported, " +
                "even if the value fails entropy checks. " +
                "Example: add APIM_KEY to ensure all APIM key names are captured.");
        keyAllowPanel.add(new JScrollPane(keyAllowlistArea), BorderLayout.CENTER);
        keyAllowPanel.add(makeSearchBar(keyAllowlistArea), BorderLayout.SOUTH);

        JPanel filterRow = new JPanel(new GridLayout(1, 3, 8, 0));
        filterRow.add(cdnPanel);
        filterRow.add(keyBlockPanel);
        filterRow.add(keyAllowPanel);
        scannerTab.add(filterRow, BorderLayout.CENTER);

        subTabs.addTab("Scanner", scannerTab);

        // ═══════════════════════════════════════════════════════════════════
        // TAB 2 — Custom Rules
        // ═══════════════════════════════════════════════════════════════════
        JPanel customRulesTab = new JPanel(new BorderLayout(4, 6));
        customRulesTab.setBorder(BorderFactory.createEmptyBorder(6, 4, 4, 4));

        JLabel noiseWarning = new JLabel(
                "\u26a0  Custom regex rules run without key-name filtering and may produce noise. " +
                "Review all findings with a CUSTOM_ rule ID carefully before reporting.");
        noiseWarning.setForeground(new Color(160, 80, 0));
        noiseWarning.setFont(noiseWarning.getFont().deriveFont(Font.PLAIN, 11f));
        noiseWarning.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(200, 140, 0), 1),
                BorderFactory.createEmptyBorder(4, 8, 4, 8)));
        noiseWarning.setOpaque(true);
        noiseWarning.setBackground(new Color(255, 251, 230));
        customRulesTab.add(noiseWarning, BorderLayout.NORTH);

        List<String> savedRules = settings.getCustomRules();
        customRulesArea = new JTextArea(savedRules.isEmpty()
                ? CUSTOM_RULES_PLACEHOLDER
                : String.join("\n", savedRules), 10, 80);
        customRulesArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        customRulesArea.setToolTipText(
                "Add your own detection patterns on top of the built-in rules. " +
                "Format: RuleName | regex | severity  (severity: HIGH / MEDIUM / LOW / INFORMATION). " +
                "Example:  MyInternalToken | [A-Z]{3}-[0-9]{10}-[a-z]{5} | HIGH");
        customRulesTab.add(new JScrollPane(customRulesArea), BorderLayout.CENTER);

        JPanel customRulesBtnBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JButton importRulesBtn = new JButton("Import from file\u2026");
        JButton exportRulesBtn = new JButton("Export to file\u2026");
        importRulesBtn.addActionListener(e -> onImportCustomRules());
        exportRulesBtn.addActionListener(e -> onExportCustomRules());
        customRulesEnabledBox = new ToggleSwitch("Enable custom rules", settings.isCustomRulesEnabled());
        customRulesEnabledBox.setToolTipText("Uncheck to keep imported rules stored but not run during scans.");
        customRulesOnlyBox = new ToggleSwitch("Custom rules only (raw)", settings.isCustomRulesOnly());
        customRulesOnlyBox.setToolTipText(
                "Raw mode: only custom rules run, FP filters bypassed. Allow/block/CDN lists still apply.");
        customRulesBtnBar.add(importRulesBtn);
        customRulesBtnBar.add(exportRulesBtn);
        customRulesBtnBar.add(Box.createHorizontalStrut(12));
        customRulesBtnBar.add(customRulesEnabledBox);
        customRulesBtnBar.add(Box.createHorizontalStrut(12));
        customRulesBtnBar.add(customRulesOnlyBox);

        JPanel customRulesBottom = new JPanel();
        customRulesBottom.setLayout(new BoxLayout(customRulesBottom, BoxLayout.Y_AXIS));
        customRulesBottom.add(makeSearchBar(customRulesArea));
        customRulesBottom.add(customRulesBtnBar);
        customRulesTab.add(customRulesBottom, BorderLayout.SOUTH);

        subTabs.addTab("Custom Rules", customRulesTab);


        rootPanel.add(subTabs, BorderLayout.CENTER);

        // ── Save/Reset — always visible below the sub-tabs ───────────────────
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JButton saveBtn  = new JButton("Save Settings");
        JButton resetBtn = new JButton("Reset to Defaults");
        saveBtn.addActionListener(e  -> onSave());
        resetBtn.addActionListener(e -> onReset());
        statusLabel = new JLabel("Ready.");
        statusLabel.setForeground(Color.GRAY);
        bottomPanel.add(saveBtn);
        bottomPanel.add(resetBtn);
        bottomPanel.add(Box.createHorizontalStrut(20));
        bottomPanel.add(statusLabel);
        rootPanel.add(bottomPanel, BorderLayout.SOUTH);

        settingsScrollPane = null; // no outer scroll — each tab manages its own viewport
    }


    // =========================================================================
    // Actions
    // =========================================================================


    private void onSave() {
        // 1. Read controls into settings
        settings.setEnabled(enabledBox.isSelected());
        settings.setEntropyThreshold(((Number) entropySpinner.getValue()).doubleValue());
        settings.setPiiEnabled(piiBox.isSelected());
        settings.setScanRequestsEnabled(scanRequestsBox.isSelected());
        settings.setAllowInsecureSsl(allowInsecureSslBox.isSelected());
        settings.setCustomRulesEnabled(customRulesEnabledBox.isSelected());
        settings.setCustomRulesOnly(customRulesOnlyBox.isSelected());


        List<String> cdn = new ArrayList<>();
        for (String line : cdnArea.getText().split("\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) cdn.add(trimmed);
        }
        settings.setCdnBlocklist(cdn);

        List<String> keyBlock = new ArrayList<>();
        for (String line : keyBlocklistArea.getText().split("\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) keyBlock.add(trimmed);
        }
        settings.setKeyBlocklist(keyBlock);

        List<String> keyAllow = new ArrayList<>();
        for (String line : keyAllowlistArea.getText().split("\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) keyAllow.add(trimmed);
        }
        settings.setKeyAllowlist(keyAllow);

        List<String> customRules = new ArrayList<>();
        for (String line : customRulesArea.getText().split("\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) customRules.add(trimmed);
        }
        settings.setCustomRules(customRules);

        // 2. Persist to Burp preferences
        settings.saveToPreferences(api);

        // Count valid vs broken custom rules and surface in status bar
        int validRules = 0, brokenRules = 0;
        for (String line : customRules) {
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] parts = line.split(" \\| ", 3);
            if (parts.length < 3) { brokenRules++; continue; }
            try { java.util.regex.Pattern.compile(parts[1].trim()); validRules++; }
            catch (Exception ignored) { brokenRules++; }
        }
        String rulesInfo = validRules + " custom rule" + (validRules != 1 ? "s" : "") + " active";
        if (brokenRules > 0) rulesInfo += "  ⚠ " + brokenRules + " invalid (check Burp Extensions output)";

        String time = LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        statusLabel.setText("Saved at " + time + "   [entropy=" +
                String.format("%.1f", settings.getEntropyThreshold()) +
                "  pii=" + settings.isPiiEnabled() +
                "  " + rulesInfo + "]");
        statusLabel.setForeground(brokenRules > 0 ? new Color(180, 90, 0) : new Color(0, 130, 0));
    }

    private void onImportCustomRules() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import Custom Rules");
        chooser.setFileFilter(new FileNameExtensionFilter("Text files (*.txt)", "txt"));
        chooser.setMultiSelectionEnabled(true);
        if (chooser.showOpenDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;
        File[] files = chooser.getSelectedFiles();
        if (files == null || files.length == 0) return;
        StringBuilder sb = new StringBuilder();
        String existing = customRulesArea.getText().trim();
        if (!existing.isEmpty() && !existing.equals(CUSTOM_RULES_PLACEHOLDER.trim())) {
            sb.append(existing).append("\n");
        }
        List<String> imported = new ArrayList<>();
        for (File f : files) {
            try {
                String content = new String(Files.readAllBytes(f.toPath())).trim();
                if (!content.isEmpty()) {
                    sb.append(content).append("\n");
                    imported.add(f.getName());
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(rootPanel,
                        "Failed to read file: " + ex.getMessage(),
                        "Import Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
        }
        customRulesArea.setText(sb.toString().trim());
        // Count non-comment rule lines across all imported content to give feedback
        long ruleCount = java.util.Arrays.stream(sb.toString().split("\n"))
                .map(String::trim)
                .filter(l -> !l.isEmpty() && !l.startsWith("#") && l.contains(" | "))
                .count();
        String names = String.join(", ", imported);
        statusLabel.setText("Imported " + imported.size() + " file(s) (" + ruleCount +
                " rule lines): " + names + " — click Save to apply.");
        statusLabel.setForeground(new Color(0, 100, 180));
    }

    private void onExportCustomRules() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Custom Rules");
        chooser.setFileFilter(new FileNameExtensionFilter("Text files (*.txt)", "txt"));
        chooser.setSelectedFile(new File("secretsifter-custom-rules.txt"));
        if (chooser.showSaveDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;
        try {
            File f = chooser.getSelectedFile();
            Files.write(f.toPath(), customRulesArea.getText().getBytes());
            statusLabel.setText("Exported rules to " + f.getName());
            statusLabel.setForeground(new Color(0, 130, 0));
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(rootPanel,
                    "Failed to write file: " + ex.getMessage(),
                    "Export Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void onReset() {
        int confirm = JOptionPane.showConfirmDialog(rootPanel,
                "Reset all settings to defaults?", "Confirm Reset",
                JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
        if (confirm != JOptionPane.YES_OPTION) return;

        settings.resetToDefaults();
        enabledBox.setSelected(settings.isEnabled());
        entropySpinner.setValue(settings.getEntropyThreshold());
        piiBox.setSelected(settings.isPiiEnabled());
        scanRequestsBox.setSelected(settings.isScanRequestsEnabled());
        allowInsecureSslBox.setSelected(settings.isAllowInsecureSsl());
        cdnArea.setText(String.join("\n", settings.getCdnBlocklist()));
        keyBlocklistArea.setText(String.join("\n", settings.getKeyBlocklist()));
        keyAllowlistArea.setText(String.join("\n", settings.getKeyAllowlist()));
        customRulesArea.setText(CUSTOM_RULES_PLACEHOLDER);
        customRulesEnabledBox.setSelected(settings.isCustomRulesEnabled());
        if (customRulesOnlyBox != null) customRulesOnlyBox.setSelected(settings.isCustomRulesOnly());
        statusLabel.setText("Reset to defaults.");
        statusLabel.setForeground(Color.GRAY);
    }

    // =========================================================================
    // Public load method — called from SecretScannerExtension after init
    // =========================================================================

    // =========================================================================
    // Search bar helper
    // =========================================================================

    /**
     * Returns a compact search bar panel for the given text area.
     * As the user types, matching lines are highlighted and a Found / Not found
     * indicator is shown — useful for checking whether an entry already exists
     * before adding it to the list.
     */
    private JPanel makeSearchBar(JTextArea area) {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        bar.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));

        JLabel lbl = new JLabel("Search:");
        lbl.setFont(lbl.getFont().deriveFont(Font.PLAIN, 11f));

        JTextField field = new JTextField(16);
        field.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        field.setToolTipText("Type to search. Press Enter to cycle through matches.");

        JLabel result = new JLabel(" ");
        result.setFont(result.getFont().deriveFont(Font.BOLD, 11f));

        bar.add(lbl);
        bar.add(field);
        bar.add(result);

        Highlighter highlighter = area.getHighlighter();
        Highlighter.HighlightPainter allPainter =
                new DefaultHighlighter.DefaultHighlightPainter(new Color(255, 230, 80));
        Highlighter.HighlightPainter currentPainter =
                new DefaultHighlighter.DefaultHighlightPainter(new Color(255, 140, 0));

        List<Integer> matchPositions = new ArrayList<>();
        int[] currentMatch = {0};

        Runnable repaintHighlights = () -> {
            highlighter.removeAllHighlights();
            int len = field.getText().trim().length();
            if (len == 0 || matchPositions.isEmpty()) return;
            for (int i = 0; i < matchPositions.size(); i++) {
                int pos = matchPositions.get(i);
                try {
                    highlighter.addHighlight(pos, pos + len,
                            i == currentMatch[0] ? currentPainter : allPainter);
                } catch (BadLocationException ignored) {}
            }
        };

        Runnable scrollToCurrent = () -> {
            if (matchPositions.isEmpty()) return;
            int pos = matchPositions.get(currentMatch[0]);
            int len = field.getText().trim().length();
            area.setCaretPosition(pos + len);
            area.moveCaretPosition(pos);
            result.setText("\u2713 " + (currentMatch[0] + 1) + " / " + matchPositions.size());
            result.setForeground(new Color(0, 130, 0));
        };

        Runnable doSearch = () -> {
            String query = field.getText().trim();
            matchPositions.clear();
            currentMatch[0] = 0;
            highlighter.removeAllHighlights();
            if (query.isEmpty()) {
                result.setText(" ");
                result.setForeground(Color.GRAY);
                area.select(0, 0);
                return;
            }
            String content = area.getText().toLowerCase();
            String queryLc = query.toLowerCase();
            int idx = 0;
            while ((idx = content.indexOf(queryLc, idx)) >= 0) {
                matchPositions.add(idx);
                idx += queryLc.length();
            }
            if (matchPositions.isEmpty()) {
                result.setText("\u2717 Not found");
                result.setForeground(new Color(180, 0, 0));
                area.select(0, 0);
            } else {
                repaintHighlights.run();
                scrollToCurrent.run();
            }
        };

        field.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e)  { doSearch.run(); }
            public void removeUpdate(DocumentEvent e)  { doSearch.run(); }
            public void changedUpdate(DocumentEvent e) { doSearch.run(); }
        });

        // Enter cycles forward; Shift+Enter cycles backward
        field.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() != KeyEvent.VK_ENTER || matchPositions.isEmpty()) return;
                if (e.isShiftDown()) {
                    currentMatch[0] = (currentMatch[0] - 1 + matchPositions.size()) % matchPositions.size();
                } else {
                    currentMatch[0] = (currentMatch[0] + 1) % matchPositions.size();
                }
                repaintHighlights.run();
                scrollToCurrent.run();
            }
        });

        return bar;
    }



    public void loadFromPreferences() {
        settings.loadFromPreferences(api);
        if (SwingUtilities.isEventDispatchThread()) {
            syncControlsFromSettings();
        } else {
            SwingUtilities.invokeLater(this::syncControlsFromSettings);
        }
    }

    private void syncControlsFromSettings() {
        if (enabledBox        != null) enabledBox.setSelected(settings.isEnabled());
        if (entropySpinner    != null) entropySpinner.setValue(settings.getEntropyThreshold());
        if (piiBox            != null) piiBox.setSelected(settings.isPiiEnabled());
        if (scanRequestsBox      != null) scanRequestsBox.setSelected(settings.isScanRequestsEnabled());
        if (allowInsecureSslBox  != null) allowInsecureSslBox.setSelected(settings.isAllowInsecureSsl());
        if (cdnArea              != null) cdnArea.setText(String.join("\n", settings.getCdnBlocklist()));
        if (keyBlocklistArea  != null) keyBlocklistArea.setText(String.join("\n", settings.getKeyBlocklist()));
        if (keyAllowlistArea  != null) keyAllowlistArea.setText(String.join("\n", settings.getKeyAllowlist()));
        if (customRulesEnabledBox != null) customRulesEnabledBox.setSelected(settings.isCustomRulesEnabled());
        if (customRulesOnlyBox    != null) customRulesOnlyBox.setSelected(settings.isCustomRulesOnly());
        if (customRulesArea != null) {
            List<String> rules = settings.getCustomRules();
            customRulesArea.setText(rules.isEmpty() ? CUSTOM_RULES_PLACEHOLDER : String.join("\n", rules));
        }
        if (statusLabel       != null) statusLabel.setText("Settings loaded from preferences.");
    }

}
