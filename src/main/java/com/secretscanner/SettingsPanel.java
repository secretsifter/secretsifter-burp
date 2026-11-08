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
 * SecretSifter configuration surface, registered in Burp's native Settings dialog via
 * {@link burp.api.montoya.ui.UserInterface#registerSettingsPanel} (implements
 * {@link burp.api.montoya.ui.settings.SettingsPanel}). It is deliberately NOT a suite sub-tab —
 * the suite tab is reserved for operational content (the Bulk Scan dashboard).
 *
 * The structured {@code SettingsPanelBuilder} API only offers boolean / integer / single-line
 * string / single-choice dropdown inputs, which cannot represent this panel's decimal entropy
 * threshold, multi-line CDN blocklist, or multi-line custom-rule editor with import/export. The
 * base {@code SettingsPanel} interface accepts an arbitrary Swing component, so the full editor is
 * supplied via {@link #uiComponent()}.
 *
 * Controls:
 *   - Global enable/disable toggle
 *   - Entropy threshold spinner (0.0 – 6.0, step 0.1)
 *   - PII scanning enable/disable
 *   - CDN blocklist text area (one entry per line)
 *
 * Settings are persisted to Burp's preference store on Save.
 */
public class SettingsPanel implements burp.api.montoya.ui.settings.SettingsPanel {

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

    /** Returns the Swing panel (built once in the constructor). */
    public JComponent getPanel() {
        return rootPanel != null ? rootPanel : new JPanel();
    }

    // ---- burp.api.montoya.ui.settings.SettingsPanel ----

    /** The component Burp renders in its native Settings dialog. */
    @Override
    public JComponent uiComponent() {
        return getPanel();
    }

    /** Keywords for Burp's Settings search box. */
    @Override
    public java.util.Set<String> keywords() {
        return java.util.Set.of("secret", "secrets", "secretsifter", "entropy",
                "pii", "cdn", "api key", "credentials", "custom rules");
    }

    // =========================================================================
    // UI construction
    // =========================================================================

    private void buildUi() {
        // Single scrollable column. Burp's native Settings pane is narrower than the old suite tab,
        // so settings stack vertically and fill the available width (no side-by-side columns and no
        // sub-tabs), and the whole panel scrolls vertically at any dialog size.
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));

        JLabel intro = new JLabel("Detection settings for SecretSifter. Click \"Save Settings\" to apply.");
        intro.setForeground(Color.GRAY);
        intro.setAlignmentX(Component.LEFT_ALIGNMENT);
        content.add(intro);
        content.add(Box.createVerticalStrut(10));

        // Scanner Controls
        JPanel controls = new JPanel(new GridBagLayout());
        controls.setBorder(new TitledBorder("Scanner Controls"));
        GridBagConstraints gc = new GridBagConstraints();
        gc.gridx = 0; gc.gridy = 0; gc.anchor = GridBagConstraints.WEST;
        gc.weightx = 1.0; gc.fill = GridBagConstraints.NONE;
        gc.insets = new Insets(3, 4, 3, 4);

        enabledBox = new ToggleSwitch("Enable passive scanning", settings.isEnabled());
        controls.add(enabledBox, gc);

        gc.gridy++;
        JPanel entropyRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        entropyRow.add(new JLabel("Entropy threshold:"));
        SpinnerNumberModel model = new SpinnerNumberModel(
                settings.getEntropyThreshold(), 0.0, 6.0, 0.1);
        entropySpinner = new JSpinner(model);
        ((JSpinner.NumberEditor) entropySpinner.getEditor()).getFormat().setMaximumFractionDigits(1);
        entropySpinner.setPreferredSize(new Dimension(70, 26));
        entropySpinner.setToolTipText("Shannon entropy threshold (bits/char). Default: 3.5");
        entropyRow.add(entropySpinner);
        controls.add(entropyRow, gc);

        gc.gridy++;
        piiBox = new ToggleSwitch("Enable PII detection (SSN, Credit Cards)", settings.isPiiEnabled());
        controls.add(piiBox, gc);

        gc.gridy++;
        scanRequestsBox = new ToggleSwitch("Scan request headers / body for secrets", settings.isScanRequestsEnabled());
        scanRequestsBox.setToolTipText(
                "When enabled, scans outbound request headers (X-API-Key, Authorization, etc.) " +
                "and request bodies for hardcoded vendor tokens. " +
                "JWT Bearer tokens are automatically skipped. " +
                "Disable to reduce noise on high-traffic proxies.");
        controls.add(scanRequestsBox, gc);

        gc.gridy++;
        allowInsecureSslBox = new ToggleSwitch("Allow insecure SSL (trust all certificates)", settings.isAllowInsecureSsl());
        allowInsecureSslBox.setToolTipText(
                "Saved for reference. Fetches now use Burp's HTTP engine, so TLS trust follows Burp's " +
                "own settings (Burp accepts self-signed / internal certificates by default).");
        controls.add(allowInsecureSslBox, gc);

        gc.gridy++;
        JLabel sslWarnLabel = new JLabel("⚠ Disable only against trusted targets");
        sslWarnLabel.setForeground(new Color(180, 60, 0));
        sslWarnLabel.setFont(sslWarnLabel.getFont().deriveFont(Font.PLAIN, 11f));
        controls.add(sslWarnLabel, gc);

        addSection(content, controls);

        // CDN / Third-Party Blocklist
        cdnArea = new JTextArea(String.join("\n", settings.getCdnBlocklist()), 6, 40);
        cdnArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        cdnArea.setToolTipText("Responses from hosts matching any of these strings are skipped.");
        addSection(content, titledTextArea(
                "CDN / Third-Party Blocklist  (one entry per line, partial host match)", cdnArea));

        // Key Name Blocklist
        keyBlocklistArea = new JTextArea(String.join("\n", settings.getKeyBlocklist()), 6, 40);
        keyBlocklistArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        keyBlocklistArea.setToolTipText(
                "Findings whose matched key name contains any entry here are suppressed. " +
                "Example: add STORAGE_KEY_ to hide all localStorage constant names. " +
                "Allowlisted keys override this list.");
        addSection(content, titledTextArea(
                "Key Name Blocklist  (suppress, one pattern per line, substring match)", keyBlocklistArea));

        // Key Name Allowlist
        keyAllowlistArea = new JTextArea(String.join("\n", settings.getKeyAllowlist()), 6, 40);
        keyAllowlistArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        keyAllowlistArea.setToolTipText(
                "Findings whose matched key name contains any entry here are always reported, " +
                "even if the value fails entropy checks. " +
                "Example: add APIM_KEY to ensure all APIM key names are captured.");
        addSection(content, titledTextArea(
                "Key Name Allowlist  (force-report, one pattern per line, substring match)", keyAllowlistArea));

        // Custom Rules
        JPanel customRules = new JPanel(new BorderLayout(4, 6));
        customRules.setBorder(new TitledBorder("Custom Rules"));

        // Plain JTextArea (not an HTML JLabel): Burp disables HTML rendering in Swing labels,
        // so markup would show as literal tags. A wrapping, non-editable text area wraps reliably.
        JTextArea noiseWarning = new JTextArea(
                "⚠ Custom regex rules run without key-name filtering and may produce noise. "
                + "Review all findings with a CUSTOM_ rule ID carefully before reporting.");
        noiseWarning.setEditable(false);
        noiseWarning.setLineWrap(true);
        noiseWarning.setWrapStyleWord(true);
        noiseWarning.setRows(2);
        noiseWarning.setForeground(new Color(160, 80, 0));
        noiseWarning.setFont(noiseWarning.getFont().deriveFont(Font.PLAIN, 11f));
        noiseWarning.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(200, 140, 0), 1),
                BorderFactory.createEmptyBorder(4, 8, 4, 8)));
        noiseWarning.setOpaque(true);
        noiseWarning.setBackground(new Color(255, 251, 230));
        customRules.add(noiseWarning, BorderLayout.NORTH);

        List<String> savedRules = settings.getCustomRules();
        customRulesArea = new JTextArea(savedRules.isEmpty()
                ? CUSTOM_RULES_PLACEHOLDER
                : String.join("\n", savedRules), 8, 40);
        customRulesArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        customRulesArea.setToolTipText(
                "Add your own detection patterns on top of the built-in rules. " +
                "Format: RuleName | regex | severity  (severity: HIGH / MEDIUM / LOW / INFORMATION). " +
                "Example:  MyInternalToken | [A-Z]{3}-[0-9]{10}-[a-z]{5} | HIGH");
        customRules.add(new JScrollPane(customRulesArea), BorderLayout.CENTER);

        JPanel customRulesBtnBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JButton importRulesBtn = new JButton("Import from file…");
        JButton exportRulesBtn = new JButton("Export to file…");
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
        JPanel crSearch = makeSearchBar(customRulesArea);
        crSearch.setAlignmentX(Component.LEFT_ALIGNMENT);
        customRulesBtnBar.setAlignmentX(Component.LEFT_ALIGNMENT);
        customRulesBottom.add(crSearch);
        customRulesBottom.add(customRulesBtnBar);
        customRules.add(customRulesBottom, BorderLayout.SOUTH);

        addSection(content, customRules);

        content.add(Box.createVerticalGlue());

        JScrollPane scroll = new JScrollPane(content,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        settingsScrollPane = scroll;

        // Save / Reset, always visible below the scroll area
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

        rootPanel = new JPanel(new BorderLayout(0, 6));
        rootPanel.add(scroll, BorderLayout.CENTER);
        rootPanel.add(bottomPanel, BorderLayout.SOUTH);
    }

    /** Adds a section to the vertical column: fills the width, does not stretch vertically. */
    private static void addSection(JPanel column, JComponent section) {
        section.setAlignmentX(Component.LEFT_ALIGNMENT);
        section.setMaximumSize(new Dimension(Integer.MAX_VALUE, section.getPreferredSize().height));
        column.add(section);
        column.add(Box.createVerticalStrut(10));
    }

    /** Builds a titled panel wrapping a scrollable text area plus its search bar. */
    private JPanel titledTextArea(String title, JTextArea area) {
        JPanel p = new JPanel(new BorderLayout(4, 4));
        p.setBorder(new TitledBorder(title));
        p.add(new JScrollPane(area), BorderLayout.CENTER);
        p.add(makeSearchBar(area), BorderLayout.SOUTH);
        return p;
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
