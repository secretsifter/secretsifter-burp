package com.secretscanner;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
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

    private final ScanSettings settings;
    private final MontoyaApi   api;

    // ---- Swing controls ----
    private JPanel    rootPanel;
    private JCheckBox enabledBox;
    private JSpinner  entropySpinner;
    private JCheckBox piiBox;
    private JCheckBox scanRequestsBox;
    private JCheckBox allowInsecureSslBox;
    private JTextArea cdnArea;
    private JTextArea keyBlocklistArea;
    private JTextArea keyAllowlistArea;
    private JLabel    statusLabel;

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
    public JPanel getPanel() {
        return rootPanel != null ? rootPanel : new JPanel();
    }

    // =========================================================================
    // UI construction
    // =========================================================================

    private void buildUi() {
        rootPanel = new JPanel(new BorderLayout(10, 10));
        rootPanel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        // ---- header banner ----
        JPanel headerPanel = new JPanel();
        headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.Y_AXIS));
        headerPanel.setBorder(BorderFactory.createEmptyBorder(2, 0, 10, 0));

        JLabel nameLbl = new JLabel("SecretSifter");
        nameLbl.setFont(nameLbl.getFont().deriveFont(Font.BOLD, 24f));
        nameLbl.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel tagLbl = new JLabel("Live Credentials & Secrets Scanner");
        tagLbl.setFont(tagLbl.getFont().deriveFont(Font.PLAIN, 14f));
        tagLbl.setForeground(Color.GRAY);
        tagLbl.setAlignmentX(Component.LEFT_ALIGNMENT);

        headerPanel.add(nameLbl);
        headerPanel.add(Box.createVerticalStrut(3));
        headerPanel.add(tagLbl);

        // ---- top: global controls ----
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 4));
        topPanel.setBorder(new TitledBorder("Scanner Controls"));

        enabledBox = new JCheckBox("Enable passive scanning", settings.isEnabled());
        topPanel.add(enabledBox);

        topPanel.add(new JLabel("   Entropy threshold:"));
        SpinnerNumberModel model = new SpinnerNumberModel(
                settings.getEntropyThreshold(), 0.0, 6.0, 0.1);
        entropySpinner = new JSpinner(model);
        ((JSpinner.NumberEditor) entropySpinner.getEditor()).getFormat().setMaximumFractionDigits(1);
        entropySpinner.setPreferredSize(new Dimension(65, 24));
        entropySpinner.setToolTipText("Shannon entropy threshold (bits/char). Default: 3.5");
        topPanel.add(entropySpinner);

        piiBox = new JCheckBox("Enable PII detection (SSN, Credit Cards)", settings.isPiiEnabled());
        topPanel.add(piiBox);

        scanRequestsBox = new JCheckBox("Scan request headers / body for secrets", settings.isScanRequestsEnabled());
        scanRequestsBox.setToolTipText(
                "When enabled, scans outbound request headers (X-API-Key, Authorization, etc.) " +
                "and request bodies for hardcoded vendor tokens. " +
                "JWT Bearer tokens are automatically skipped. " +
                "Disable to reduce noise on high-traffic proxies.");
        topPanel.add(scanRequestsBox);

        allowInsecureSslBox = new JCheckBox("Allow insecure SSL (trust all certificates)", settings.isAllowInsecureSsl());
        allowInsecureSslBox.setToolTipText(
                "Saved for reference — SSL trust is now governed by Burp's project-level TLS settings " +
                "(Project Options > TLS > Server TLS Certificates). " +
                "For self-signed or internal certs, add the CA to Burp's trust store instead of enabling this option.");
        topPanel.add(allowInsecureSslBox);

        JLabel sslWarnLabel = new JLabel("  \u26a0 Disable only against trusted targets");
        sslWarnLabel.setForeground(new Color(180, 60, 0));
        sslWarnLabel.setFont(sslWarnLabel.getFont().deriveFont(Font.PLAIN, 11f));
        topPanel.add(sslWarnLabel);

        JPanel northWrapper = new JPanel(new BorderLayout(0, 6));
        northWrapper.add(headerPanel, BorderLayout.NORTH);
        northWrapper.add(topPanel, BorderLayout.CENTER);
        rootPanel.add(northWrapper, BorderLayout.NORTH);

        // ---- centre: CDN blocklist + key filter lists ----
        JPanel centrePanel = new JPanel(new BorderLayout(4, 6));

        // CDN blocklist
        JPanel cdnPanel = new JPanel(new BorderLayout(4, 4));
        cdnPanel.setBorder(new TitledBorder(
                "CDN / Third-Party Blocklist  (one entry per line — partial host match)"));
        cdnArea = new JTextArea(String.join("\n", settings.getCdnBlocklist()), 7, 50);
        cdnArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        cdnArea.setToolTipText("Responses from hosts matching any of these strings are skipped.");
        cdnPanel.add(new JScrollPane(cdnArea), BorderLayout.CENTER);
        cdnPanel.add(makeSearchBar(cdnArea), BorderLayout.SOUTH);
        centrePanel.add(cdnPanel, BorderLayout.NORTH);

        // Key label filter lists — side by side
        JPanel keyFilterPanel = new JPanel(new GridLayout(1, 2, 8, 0));

        JPanel keyBlockPanel = new JPanel(new BorderLayout(4, 4));
        keyBlockPanel.setBorder(new TitledBorder(
                "Key Name Blocklist  (suppress — one pattern per line, substring match)"));
        keyBlocklistArea = new JTextArea(String.join("\n", settings.getKeyBlocklist()), 7, 25);
        keyBlocklistArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        keyBlocklistArea.setToolTipText(
                "Findings whose matched key name contains any entry here are suppressed. " +
                "Example: add STORAGE_KEY_ to hide all localStorage constant names. " +
                "Allowlisted keys override this list.");
        keyBlockPanel.add(new JScrollPane(keyBlocklistArea), BorderLayout.CENTER);
        keyBlockPanel.add(makeSearchBar(keyBlocklistArea), BorderLayout.SOUTH);

        JPanel keyAllowPanel = new JPanel(new BorderLayout(4, 4));
        keyAllowPanel.setBorder(new TitledBorder(
                "Key Name Allowlist  (force-report — one pattern per line, substring match)"));
        keyAllowlistArea = new JTextArea(String.join("\n", settings.getKeyAllowlist()), 7, 25);
        keyAllowlistArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        keyAllowlistArea.setToolTipText(
                "Findings whose matched key name contains any entry here are always reported, " +
                "even if the value fails entropy checks. " +
                "Example: add APIM_KEY to ensure all APIM key names are captured.");
        keyAllowPanel.add(new JScrollPane(keyAllowlistArea), BorderLayout.CENTER);
        keyAllowPanel.add(makeSearchBar(keyAllowlistArea), BorderLayout.SOUTH);

        keyFilterPanel.add(keyBlockPanel);
        keyFilterPanel.add(keyAllowPanel);
        centrePanel.add(keyFilterPanel, BorderLayout.CENTER);

        rootPanel.add(centrePanel, BorderLayout.CENTER);

        // ---- bottom: buttons + status ----
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

        // 2. Persist to Burp preferences
        settings.saveToPreferences(api);

        String time = LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        statusLabel.setText("Saved at " + time + "   [entropy=" +
                String.format("%.1f", settings.getEntropyThreshold()) +
                "  pii=" + settings.isPiiEnabled() + "]");
        statusLabel.setForeground(new Color(0, 130, 0));
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
        field.setToolTipText("Type to check whether an entry already exists in the list above");

        JLabel result = new JLabel(" ");
        result.setFont(result.getFont().deriveFont(Font.BOLD, 11f));

        bar.add(lbl);
        bar.add(field);
        bar.add(result);

        field.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e)  { search(); }
            public void removeUpdate(DocumentEvent e)  { search(); }
            public void changedUpdate(DocumentEvent e) { search(); }

            private void search() {
                String query = field.getText().trim();
                if (query.isEmpty()) {
                    result.setText(" ");
                    result.setForeground(Color.GRAY);
                    area.select(0, 0);
                    return;
                }
                String content = area.getText();
                int idx = content.toLowerCase().indexOf(query.toLowerCase());
                if (idx >= 0) {
                    result.setText("\u2713 Found");
                    result.setForeground(new Color(0, 130, 0));
                    area.select(idx, idx + query.length());
                    area.requestFocusInWindow();
                } else {
                    result.setText("\u2717 Not found");
                    result.setForeground(new Color(180, 0, 0));
                    area.select(0, 0);
                }
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
        if (statusLabel       != null) statusLabel.setText("Settings loaded from preferences.");
    }
}
