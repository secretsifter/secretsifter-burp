package com.secretscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;


import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Bulk Scan tab — lets you paste or import a list of URLs, fetches and scans
 * each one via Burp's HTTP engine, extracts inline scripts + script-src files
 * + webpack chunk references, and presents findings in a live results table.
 *
 * Features:
 *   - Script-src following (fetches all JS files referenced in HTML)
 *   - Webpack / Next.js chunk following (depth-1)
 *   - HTML inline &lt;script&gt; block scanning
 *   - Scope Monitor: passively collects findings from Burp proxy traffic
 *     for any host that appears in the URL list
 *   - Export findings as CSV or HTML report
 *   - Right-click a finding row → copy value or open URL in browser
 */
public class BulkScanPanel {

    // ── Columns ───────────────────────────────────────────────────────────────
    private static final String[] COLS = {
        "#", "Severity", "Confidence", "Rule ID", "Key", "Value", "URL", "Line", "Context", ""
    };
    private static final int COL_SEV  = 1;
    private static final int COL_CONF = 2;
    private static final int COL_VAL  = 5;
    private static final int COL_URL  = 6;
    private static final int COL_DEL  = 9;

    // ── State ─────────────────────────────────────────────────────────────────
    private final SecretScanner  scanner;
    private final ScanSettings   settings;
    private final MontoyaApi     api;

    private final DefaultTableModel            tableModel;
    private final List<SecretFinding>          tableFindings  = Collections.synchronizedList(new ArrayList<>());
    private final AtomicBoolean                running        = new AtomicBoolean(false);
    private final AtomicInteger                urlsDone       = new AtomicInteger(0);
    private final AtomicInteger                urlsStarted    = new AtomicInteger(0);
    /** Total number of HTTP requests to make this scan (grows as JS/chunks are discovered). */
    private final AtomicInteger                totalExpected  = new AtomicInteger(0);
    /** Number of HTTP requests completed so far (incremented after every fetch attempt). */
    private final AtomicInteger                totalDone      = new AtomicInteger(0);
    private volatile ExecutorService           executor;
    /** URL-based dedup set — prevents the same resource from being scanned twice
     *  (e.g. site map sweep + active fetch both reaching the same URL, or the same
     *  shared JS bundle referenced by multiple targets in a multi-target scan).
     *  Using URL strings instead of body.hashCode() avoids 32-bit int collisions
     *  that silently drop findings when ~540+ bodies are processed concurrently. */
    private final Set<String>                  seenUrls       = ConcurrentHashMap.newKeySet();
    /** Finding-level dedup — prevents the same (ruleId, url, value) triple from appearing
     *  more than once in the table across multiple scans of the same site. Cleared only
     *  when the user clicks "Clear Results". Keyed by ruleId + ":" + sourceUrl + ":" + matchedValue. */
    private final Set<String>                  seenFindings   = ConcurrentHashMap.newKeySet();
    /** Limits concurrent headless Chrome processes so they don't all launch at once
     *  when scanning with many threads. Max 3 Chrome instances run simultaneously. */
    private final Semaphore                    headlessSemaphore = new Semaphore(3);
    /** Site map HTML index built once at scan start — maps normalised URL → authenticated
     *  HttpRequestResponse.  Lets processUrl() prefer the site map (authenticated) HTML
     *  body over the unauthenticated active fetch body when a target redirects to
     *  SSO/Entra without a session cookie.  Built in O(n), looked up in O(1) per URL. */
    private volatile Map<String, HttpRequestResponse> siteMapIndex = Collections.emptyMap();
    /** Mask-toggle state for the Value and URL columns. */
    private volatile boolean maskValues = false;
    private volatile boolean maskUrls   = false;
    /** True once the user has accepted the headless-browse consent dialog this session. */
    private volatile boolean headlessConsentGiven = false;

    // ── Target status tracking (Option 1 + 4) ────────────────────────────────
    private final AtomicInteger statusScanned = new AtomicInteger(0);
    private final AtomicInteger statusFailed  = new AtomicInteger(0);
    private final AtomicInteger statusAuth    = new AtomicInteger(0);
    private DefaultTableModel   targetStatusModel;
    private JLabel              sumScannedLbl;
    private JLabel              sumFailedLbl;
    private JLabel              sumAuthLbl;
    /** Non-null while a site-map sweep is running alongside the active bulk fetch. */
    private volatile Thread     siteMapSweepThread;
    /** URL count saved at scan-start so onSweepComplete() can show the final total. */
    private volatile int        lastScanTotal;

    // ── Swing controls ────────────────────────────────────────────────────────
    private JPanel    rootPanel;
    private JTextArea urlArea;
    private JSpinner  concurrencySpinner;
    private JCheckBox followScriptSrcBox;
    private JCheckBox followChunksBox;
    private JCheckBox scopeMonitorBox;
    private JCheckBox crossOriginBox;
    private JCheckBox headlessBrowseBox;
    private JCheckBox debugModeBox;
    private JSpinner  proxyPortSpinner;
    private JComboBox<String> tierCombo;
    private JButton   startBtn;
    private JButton   stopBtn;
    private JButton   siteMapBtn;       // Option B — scan Burp's site map
    private JProgressBar progressBar;
    private JLabel    statusLabel;
    private JLabel    timerLabel;
    private JLabel    currentFileLabel;
    private javax.swing.Timer scanTimer;
    private javax.swing.Timer progressTimer;
    private long      scanStartMs;
    private JTable    resultsTable;
    private TableRowSorter<DefaultTableModel> sorter;
    private JToggleButton critCountBtn;
    private JToggleButton highCountBtn;
    private JToggleButton medCountBtn;
    private JToggleButton lowCountBtn;

    /** Burp persistence key — stores "true" once the user accepts the headless-browse consent. */
    private static final String PREF_HEADLESS_CONSENT = "secretsifter.headless.consent";

    // ── Severity sort order ───────────────────────────────────────────────────
    private static final Map<String, Integer> SEV_ORDER = Map.of(
            "CRITICAL", 0, "HIGH", 1, "MEDIUM", 2, "LOW", 3, "INFORMATION", 4, "INFO", 4
    );

    // ── Severity colours ──────────────────────────────────────────────────────
    private static final Map<String, Color> SEV_BG = Map.of(
            "CRITICAL",    new Color(220, 180, 220),
            "HIGH",        new Color(255, 215, 215),
            "MEDIUM",      new Color(255, 235, 200),
            "LOW",         new Color(255, 252, 200),
            "INFORMATION", new Color(220, 235, 255),
            "INFO",        new Color(220, 235, 255)
    );

    // =========================================================================

    public BulkScanPanel(SecretScanner scanner, ScanSettings settings, MontoyaApi api) {
        this.scanner  = scanner;
        this.settings = settings;
        this.api      = api;
        this.HTTP_CLIENT   = buildHttpClient(settings.isAllowInsecureSsl(), 8080);
        this.IP_HTTP_CLIENT = buildHttpClient(true, 8080);

        tableModel = new DefaultTableModel(COLS, 0) {
            @Override public boolean isCellEditable(int r, int c) {
                return c == COL_SEV || c == COL_CONF || c == COL_DEL;
            }
        };

        if (SwingUtilities.isEventDispatchThread()) buildUi();
        else try { SwingUtilities.invokeAndWait(this::buildUi); }
             catch (Exception e) { SwingUtilities.invokeLater(this::buildUi); }
    }

    public JPanel getPanel() {
        return rootPanel != null ? rootPanel : new JPanel();
    }

    // =========================================================================
    // UI construction
    // =========================================================================

    private void buildUi() {
        rootPanel = new JPanel(new BorderLayout(8, 8));
        rootPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // ── Left: URL input (top) + Target Status table (bottom) ──────────
        JPanel inputPanel = new JPanel(new BorderLayout(0, 0));

        // Top half: URL textarea + buttons (unchanged UX)
        JPanel urlTopPanel = new JPanel(new BorderLayout(4, 4));
        urlTopPanel.setBorder(new TitledBorder("Target URLs  (one per line)"));

        urlArea = new JTextArea();
        urlArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        urlArea.setLineWrap(false);
        urlArea.setToolTipText("Paste URLs or hostnames, one per line");
        urlTopPanel.add(new JScrollPane(urlArea), BorderLayout.CENTER);

        JPanel urlBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JButton importBtn    = new JButton("Import File…");
        JButton importHarBtn = new JButton("Scan HAR…");
        JButton clearUrlBtn  = new JButton("Clear");
        importBtn.addActionListener(e -> importUrlFile());
        importHarBtn.addActionListener(e -> importAndScanHar());
        importHarBtn.setToolTipText("Import a .har file and scan all captured JS/HTML/JSON responses");
        clearUrlBtn.addActionListener(e -> urlArea.setText(""));
        urlBtns.add(importBtn);
        urlBtns.add(importHarBtn);
        urlBtns.add(clearUrlBtn);
        urlTopPanel.add(urlBtns, BorderLayout.SOUTH);

        // Bottom half: Target Status mini-table (fills in live during scan)
        targetStatusModel = new DefaultTableModel(new String[]{"", "Target URL", "Detail"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        JTable targetStatusTable = new JTable(targetStatusModel);
        targetStatusTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        targetStatusTable.setRowHeight(18);
        targetStatusTable.getTableHeader().setReorderingAllowed(false);
        targetStatusTable.getColumnModel().getColumn(0).setMaxWidth(26);
        targetStatusTable.getColumnModel().getColumn(0).setPreferredWidth(26);
        targetStatusTable.getColumnModel().getColumn(0).setResizable(false);
        targetStatusTable.getColumnModel().getColumn(1).setPreferredWidth(192);
        targetStatusTable.getColumnModel().getColumn(2).setPreferredWidth(70);
        // Colored icon renderer: "+" = green OK, "×" = red fail, "~" = orange auth
        targetStatusTable.getColumnModel().getColumn(0).setCellRenderer(
            new DefaultTableCellRenderer() {
                @Override public java.awt.Component getTableCellRendererComponent(
                        JTable t, Object value, boolean sel, boolean focus, int row, int col) {
                    super.getTableCellRendererComponent(t, value, sel, focus, row, col);
                    setHorizontalAlignment(CENTER);
                    String v = value != null ? value.toString() : "";
                    if (!sel) {
                        switch (v) {
                            case "+" -> setForeground(new Color(0, 150, 0));
                            case "×" -> setForeground(new Color(200, 0, 0));
                            case "~" -> setForeground(new Color(160, 80, 0));
                            default  -> setForeground(Color.GRAY);
                        }
                    }
                    setFont(getFont().deriveFont(Font.BOLD));
                    return this;
                }
            });

        JPanel statusBottomPanel = new JPanel(new BorderLayout(4, 4));
        statusBottomPanel.setBorder(new TitledBorder("Target Status"));
        statusBottomPanel.add(new JScrollPane(targetStatusTable), BorderLayout.CENTER);

        JSplitPane leftSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, urlTopPanel, statusBottomPanel);
        leftSplit.setDividerLocation(220);
        leftSplit.setResizeWeight(0.6);
        inputPanel.add(leftSplit, BorderLayout.CENTER);

        // ── Top: options bar ───────────────────────────────────────────────
        JPanel optPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 4));
        optPanel.setBorder(new TitledBorder("Scan Options  \u2014  \u26a0 Turn Proxy Intercept OFF before scanning"));

        optPanel.add(new JLabel("Threads:"));
        concurrencySpinner = new JSpinner(new SpinnerNumberModel(10, 1, 50, 1));
        concurrencySpinner.setPreferredSize(new Dimension(50, 24));
        optPanel.add(concurrencySpinner);

        followScriptSrcBox = new JCheckBox("Follow <script src>",  true);
        followScriptSrcBox.setToolTipText("Fetch and scan all external JS files referenced in HTML");

        followChunksBox = new JCheckBox("Follow webpack chunks", true);
        followChunksBox.setToolTipText("Follow webpack/Next.js chunk references inside JS bundles (depth 1)");

        // Scope monitor defaults to ON so passive proxy traffic is captured automatically
        scopeMonitorBox = new JCheckBox("Scope Monitor", true);
        scopeMonitorBox.setToolTipText(
                "Also capture passive-scan findings from Burp proxy traffic\n" +
                "for any host that appears in the URL list above");
        scopeMonitorBox.addActionListener(e -> toggleScopeMonitor());
        // Initialize listener immediately — the checkbox defaults to ON so the user never
        // clicks it, meaning toggleScopeMonitor() is never called and listener stays null.
        // Without this, SecretProxyHandler findings are silently dropped on startup.
        ScopeMonitor.setListener((f, url) -> SwingUtilities.invokeLater(() -> appendFinding(f)));
        ScopeMonitor.setActive(true);   // activate immediately on startup

        crossOriginBox = new JCheckBox("Cross-origin APIs", true);
        crossOriginBox.setToolTipText(
                "Capture API calls fired by a watched host's JavaScript to other domains. " +
                "Example: api.example.com called from app.example.com is captured. " +
                "Note: third-party services (analytics, CDN) loaded from the same page " +
                "may also appear — add them to the CDN blocklist to suppress.");
        crossOriginBox.addActionListener(e -> ScopeMonitor.setCrossOriginFollow(crossOriginBox.isSelected()));
        ScopeMonitor.setCrossOriginFollow(true);  // initialise immediately — action listener only fires on click

        headlessBrowseBox = new JCheckBox("Headless Browse", false);
        headlessBrowseBox.setToolTipText(
                "Launch Chrome via Burp proxy to capture dynamic XHR/fetch calls static fetch misses. " +
                "Requires Chrome/Chromium. Intercept must be OFF during scan.");
        headlessBrowseBox.addItemListener(e -> {
            if (e.getStateChange() == java.awt.event.ItemEvent.SELECTED) {
                // Already accepted this session — no dialog needed
                if (headlessConsentGiven) return;

                // Defer dialog so the ItemListener fully completes before the modal opens.
                // Showing a JOptionPane synchronously inside an ItemListener causes Swing's
                // secondary EDT loop to reset the checkbox state before the listener returns.
                SwingUtilities.invokeLater(() -> {
                    JTextArea msg = new JTextArea(
                            "Headless Browse \u2014 What this feature does:\n\n" +
                            "  \u2022  Spawns a Chrome or Chromium process on your machine for each scanned URL.\n" +
                            "  \u2022  Routes all Chrome traffic through Burp\u2019s local proxy \u2014 no data leaves via Chrome directly.\n" +
                            "  \u2022  Creates an isolated temporary Chrome profile (in system temp) deleted after each scan.\n" +
                            "  \u2022  Makes real HTTP requests to the target; JavaScript executes in a full browser context.\n\n" +
                            "Requirements: Google Chrome or Chromium must be installed and on PATH.\n\n" +
                            "\u26a0  Only use against systems you own or have explicit written authorisation to test.");
                    msg.setEditable(false);
                    msg.setLineWrap(true);
                    msg.setWrapStyleWord(true);
                    msg.setOpaque(false);
                    msg.setFont(UIManager.getFont("OptionPane.messageFont"));
                    msg.setColumns(52);
                    int choice = JOptionPane.showConfirmDialog(
                            rootPanel,
                            msg,
                            "Headless Browse \u2014 Consent Required",
                            JOptionPane.OK_CANCEL_OPTION,
                            JOptionPane.WARNING_MESSAGE);
                    if (choice != JOptionPane.OK_OPTION) {
                        headlessBrowseBox.setSelected(false);
                        return;
                    }
                    headlessConsentGiven = true;
                });
            }
        });
        // Headless Browse is always OFF on load — user must opt in each session.
        // Prior consent is stored only to skip the consent dialog (not to auto-enable the feature).

        optPanel.add(new JLabel("Proxy:"));
        proxyPortSpinner = new JSpinner(new SpinnerNumberModel(8080, 1, 65535, 1));
        proxyPortSpinner.setPreferredSize(new Dimension(65, 24));
        proxyPortSpinner.setToolTipText("Burp proxy port. NOTE: Proxy Intercept must be OFF before scanning — if Intercept is ON, all requests will be held and the scan will complete with no findings.");
        // Disable locale thousands-separator so port shows as "8080" not "8,080"
        JSpinner.NumberEditor portEditor = new JSpinner.NumberEditor(proxyPortSpinner, "#");
        proxyPortSpinner.setEditor(portEditor);
        optPanel.add(proxyPortSpinner);

        debugModeBox = new JCheckBox("Debug", false);
        debugModeBox.setToolTipText(
                "Log every CDP-observed URL and proxy-replay detail to Extensions → Output. " +
                "Disable for normal use to reduce log noise.");
        optPanel.add(debugModeBox);

        optPanel.add(Box.createHorizontalStrut(10));

        startBtn   = new JButton("▶  Start Scan");
        stopBtn    = new JButton("■  Stop");
        siteMapBtn = new JButton("🗺  Scan Site Map");
        stopBtn.setEnabled(false);
        startBtn.addActionListener(e   -> startScan());
        stopBtn.addActionListener(e    -> stopScan());
        siteMapBtn.addActionListener(e -> scanFromSiteMap());
        siteMapBtn.setToolTipText(
                "Scan all JS and HTML responses Burp has already captured in its site map\n" +
                "for the hosts in the URL list above. Requires prior browsing through Burp proxy.");
        optPanel.add(startBtn);
        optPanel.add(stopBtn);
        optPanel.add(Box.createHorizontalStrut(6));
        optPanel.add(siteMapBtn);
        optPanel.add(Box.createHorizontalStrut(10));
        optPanel.add(new JLabel("Scan Tier:"));
        tierCombo = new JComboBox<>(new String[]{"FULL", "LIGHT", "FAST"});
        tierCombo.setSelectedItem(settings.getTier().name());
        tierCombo.setToolTipText(
                "FULL: all checks (slowest, most thorough)\n" +
                "LIGHT: vendor tokens + DB strings\n" +
                "FAST: vendor tokens + URL creds only");
        optPanel.add(tierCombo);

        // ── Centre: results table ──────────────────────────────────────────
        resultsTable = new JTable(tableModel);
        resultsTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        resultsTable.setRowHeight(20);
        resultsTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        resultsTable.setFillsViewportHeight(true);
        resultsTable.setDefaultRenderer(Object.class, new SeverityCellRenderer());
        resultsTable.getTableHeader().setReorderingAllowed(false);

        // ── Row sorter: sortable columns with severity-aware comparator ─────────
        sorter = new TableRowSorter<>(tableModel);
        sorter.setSortable(COL_DEL, false);   // delete button
        // # column — numeric comparator so 2 < 10 (not lexicographic)
        sorter.setComparator(0, (Comparator<Object>) (a, b) -> {
            try { return Integer.compare(Integer.parseInt(a.toString()), Integer.parseInt(b.toString())); }
            catch (Exception e2) { return 0; }
        });
        // Severity column — order by CRITICAL → HIGH → MEDIUM → LOW → INFORMATION
        sorter.setComparator(COL_SEV, (Comparator<Object>) (a, b) -> Integer.compare(
                SEV_ORDER.getOrDefault(a != null ? a.toString().toUpperCase() : "", 99),
                SEV_ORDER.getOrDefault(b != null ? b.toString().toUpperCase() : "", 99)));
        resultsTable.setRowSorter(sorter);
        // Default: severity ascending (CRITICAL first), then arrival order within each group
        sorter.setSortKeys(List.of(
                new RowSorter.SortKey(COL_SEV, SortOrder.ASCENDING),
                new RowSorter.SortKey(0, SortOrder.ASCENDING)));

        // Column widths
        int[] widths = { 35, 65, 75, 130, 130, 220, 220, 45, 200, 28 };
        for (int i = 0; i < widths.length && i < resultsTable.getColumnCount(); i++) {
            resultsTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }

        // Severity dropdown editor
        JComboBox<String> sevCombo = new JComboBox<>(new String[]{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATION"});
        resultsTable.getColumnModel().getColumn(COL_SEV).setCellEditor(new DefaultCellEditor(sevCombo));

        // Keep severity count badges in sync when user edits a severity cell via the dropdown
        tableModel.addTableModelListener(e -> {
            if (e.getColumn() == COL_SEV)
                SwingUtilities.invokeLater(this::updateCountBadges);
        });

        // Confidence dropdown editor
        JComboBox<String> confCombo = new JComboBox<>(new String[]{"FIRM", "CERTAIN", "TENTATIVE"});
        resultsTable.getColumnModel().getColumn(COL_CONF).setCellEditor(new DefaultCellEditor(confCombo));

        // Delete (×) column — render as a red button; handle click via mouse listener
        resultsTable.getColumnModel().getColumn(COL_DEL).setCellRenderer(new DeleteButtonRenderer());
        resultsTable.getColumnModel().getColumn(COL_DEL).setResizable(false);
        resultsTable.getColumnModel().getColumn(COL_DEL).setMaxWidth(28);

        // Right-click context menu on table
        JPopupMenu tableMenu = new JPopupMenu();
        JMenuItem copyValItem  = new JMenuItem("Copy Value");
        JMenuItem copyRowItem  = new JMenuItem("Copy Row");
        JMenuItem openUrlItem  = new JMenuItem("Open URL in Browser");
        copyValItem.addActionListener(e -> copyTableCell(COL_VAL));
        copyRowItem.addActionListener(e -> copyTableRow());
        openUrlItem.addActionListener(e -> openUrlInBrowser());
        tableMenu.add(copyValItem);
        tableMenu.add(copyRowItem);
        tableMenu.addSeparator();
        tableMenu.add(openUrlItem);

        resultsTable.addMouseListener(new MouseAdapter() {
            @Override public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = resultsTable.rowAtPoint(e.getPoint());
                    if (row >= 0) resultsTable.setRowSelectionInterval(row, row);
                    tableMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
            @Override public void mouseClicked(MouseEvent e) {
                int viewRow = resultsTable.rowAtPoint(e.getPoint());
                int col     = resultsTable.columnAtPoint(e.getPoint());
                if (viewRow >= 0 && col == COL_DEL) {
                    int modelRow = sorter.convertRowIndexToModel(viewRow);
                    tableModel.removeRow(modelRow);
                    synchronized (tableFindings) {
                        if (modelRow < tableFindings.size()) tableFindings.remove(modelRow);
                    }
                    updateCountBadges();
                }
            }
        });

        JScrollPane tableScroll = new JScrollPane(resultsTable,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        // Stretch the Context column (index 8) to fill remaining viewport width
        tableScroll.addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override public void componentResized(java.awt.event.ComponentEvent e) {
                int viewportW = tableScroll.getViewport().getWidth();
                int fixed = 0;
                for (int i = 0; i < resultsTable.getColumnCount(); i++) {
                    if (i != 8) fixed += resultsTable.getColumnModel().getColumn(i).getWidth();
                }
                int ctx = Math.max(120, viewportW - fixed);
                resultsTable.getColumnModel().getColumn(8).setPreferredWidth(ctx);
                resultsTable.getColumnModel().getColumn(8).setWidth(ctx);
            }
        });

        // Eye-toggle buttons for masking Value / URL columns
        JToggleButton eyeValueBtn = new JToggleButton("👁 Value");
        eyeValueBtn.setFont(eyeValueBtn.getFont().deriveFont(Font.PLAIN, 11f));
        eyeValueBtn.setToolTipText("Mask / unmask the Value column");
        eyeValueBtn.addActionListener(e -> {
            maskValues = eyeValueBtn.isSelected();
            resultsTable.repaint();
        });
        JToggleButton eyeUrlBtn = new JToggleButton("👁 URL");
        eyeUrlBtn.setFont(eyeUrlBtn.getFont().deriveFont(Font.PLAIN, 11f));
        eyeUrlBtn.setToolTipText("Mask / unmask the URL column");
        eyeUrlBtn.addActionListener(e -> {
            maskUrls = eyeUrlBtn.isSelected();
            resultsTable.repaint();
        });
        JPanel findingsHeader = new JPanel(new BorderLayout(4, 0));
        findingsHeader.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
        JLabel findingsLbl = new JLabel("Findings");
        findingsLbl.setFont(findingsLbl.getFont().deriveFont(Font.BOLD, 12f));

        critCountBtn = makeSevBadge("CRITICAL", 0);
        highCountBtn = makeSevBadge("HIGH",     0);
        medCountBtn  = makeSevBadge("MEDIUM",   0);
        lowCountBtn  = makeSevBadge("LOW",      0);

        // Click a badge to filter to that severity+; click again to clear
        critCountBtn.addActionListener(e -> onBadgeClicked(critCountBtn));
        highCountBtn.addActionListener(e -> onBadgeClicked(highCountBtn));
        medCountBtn .addActionListener(e -> onBadgeClicked(medCountBtn));
        lowCountBtn .addActionListener(e -> onBadgeClicked(lowCountBtn));

        JPanel countPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        countPanel.setOpaque(false);
        countPanel.add(critCountBtn);
        countPanel.add(highCountBtn);
        countPanel.add(medCountBtn);
        countPanel.add(lowCountBtn);

        JPanel eyeBtns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        eyeBtns.add(eyeValueBtn);
        eyeBtns.add(eyeUrlBtn);

        JPanel westRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        westRow.setOpaque(false);
        westRow.add(findingsLbl);
        westRow.add(countPanel);

        findingsHeader.add(westRow, BorderLayout.WEST);
        findingsHeader.add(eyeBtns, BorderLayout.EAST);

        JPanel centrePanel = new JPanel(new BorderLayout(4, 4));
        centrePanel.setBorder(BorderFactory.createTitledBorder(""));
        centrePanel.add(findingsHeader, BorderLayout.NORTH);
        centrePanel.add(tableScroll, BorderLayout.CENTER);

        // ── Bottom: progress + export ──────────────────────────────────────
        JPanel bottomPanel = new JPanel(new BorderLayout(6, 4));

        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setString("");
        progressBar.setPreferredSize(new Dimension(0, 18));
        // Force BasicProgressBarUI so orange foreground works on all platforms (macOS Aqua LAF
        // ignores setForeground for indeterminate bars; this overrides it globally).
        progressBar.setUI(new javax.swing.plaf.basic.BasicProgressBarUI() {
            @Override protected Color getSelectionBackground() { return Color.BLACK; }  // text on unfilled portion
            @Override protected Color getSelectionForeground() { return Color.WHITE; }  // text on filled (orange) portion
        });
        progressBar.setForeground(new Color(220, 110, 10));

        timerLabel = new JLabel("");
        timerLabel.setForeground(Color.GRAY);
        timerLabel.setFont(timerLabel.getFont().deriveFont(Font.PLAIN, 11f));

        statusLabel = new JLabel("Ready.");
        statusLabel.setForeground(Color.GRAY);
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.PLAIN, 11f));

        currentFileLabel = new JLabel("");
        currentFileLabel.setForeground(new Color(0, 140, 80));   // green — distinct from blue status
        currentFileLabel.setFont(currentFileLabel.getFont().deriveFont(Font.PLAIN, 11f));

        JPanel exportBtns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        JButton clearResultsBtn = new JButton("Clear Results");
        // CSV / JSON export — dropdown: "Export CSV" | "Export JSON"
        JButton exportDataBtn = new JButton("Export  \u25BE");
        exportDataBtn.setToolTipText("Export findings as CSV or JSON");
        JPopupMenu dataExportMenu = new JPopupMenu();
        JMenuItem exportCsvItem  = new JMenuItem("Export CSV");
        JMenuItem exportJsonItem = new JMenuItem("Export JSON");
        exportCsvItem.setToolTipText("Save all findings as a CSV spreadsheet");
        exportJsonItem.setToolTipText("Save all findings as a JSON file");
        exportCsvItem.addActionListener(e  -> exportCsv());
        exportJsonItem.addActionListener(e -> exportJson());
        dataExportMenu.add(exportCsvItem);
        dataExportMenu.add(exportJsonItem);
        exportDataBtn.addActionListener(e ->
                dataExportMenu.show(exportDataBtn, 0, exportDataBtn.getHeight()));

        // HTML export — dropdown: "All-in-one Report" | "Per-Domain Reports (ZIP)"
        JButton exportHtmlBtn = new JButton("Export HTML  \u25BE");
        exportHtmlBtn.setToolTipText("Export findings as HTML report");
        JPopupMenu htmlExportMenu = new JPopupMenu();
        JMenuItem allInOneItem  = new JMenuItem("All-in-one Report");
        JMenuItem perDomainItem = new JMenuItem("Per-Domain Reports (ZIP)");
        allInOneItem.setToolTipText("Single HTML file containing all findings");
        perDomainItem.setToolTipText("One HTML report per base domain, packaged as a ZIP file");
        allInOneItem.addActionListener(e  -> exportHtml());
        perDomainItem.addActionListener(e -> exportHtmlPerDomain());
        htmlExportMenu.add(allInOneItem);
        htmlExportMenu.add(perDomainItem);
        exportHtmlBtn.addActionListener(e ->
                htmlExportMenu.show(exportHtmlBtn, 0, exportHtmlBtn.getHeight()));

        clearResultsBtn.addActionListener(e -> clearResults());
        exportBtns.add(clearResultsBtn);
        exportBtns.add(exportDataBtn);
        exportBtns.add(exportHtmlBtn);

        // Row 1: orange progress bar (CENTER) + elapsed timer (EAST)
        JPanel progressRow = new JPanel(new BorderLayout(6, 0));
        progressRow.add(progressBar, BorderLayout.CENTER);
        progressRow.add(timerLabel,  BorderLayout.EAST);

        // Row 2: general status text (WEST) + current file being scanned (CENTER)
        JPanel infoRow = new JPanel(new BorderLayout(6, 0));
        infoRow.add(statusLabel,      BorderLayout.WEST);
        infoRow.add(currentFileLabel, BorderLayout.CENTER);

        // Stack rows vertically; GridLayout ensures both rows get the same full width
        JPanel statusPanel = new JPanel(new GridLayout(2, 1, 0, 2));
        statusPanel.add(progressRow);
        statusPanel.add(infoRow);

        bottomPanel.add(statusPanel, BorderLayout.CENTER);
        bottomPanel.add(exportBtns,  BorderLayout.EAST);

        // ── Option 4: Summary bar — thin strip between Scan Options and Findings ──
        JPanel summaryBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 14, 3));
        summaryBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 1, 0, new Color(210, 215, 225)),
                BorderFactory.createEmptyBorder(1, 4, 1, 4)));
        summaryBar.setBackground(new Color(246, 248, 252));
        Font sf = summaryBar.getFont().deriveFont(Font.PLAIN, 11f);
        sumScannedLbl = new JLabel("Scanned: 0");
        sumFailedLbl  = new JLabel("Failed: 0");
        sumAuthLbl    = new JLabel("Auth: 0");
        sumScannedLbl.setFont(sf.deriveFont(Font.BOLD));
        sumFailedLbl.setFont(sf.deriveFont(Font.BOLD));
        sumAuthLbl.setFont(sf.deriveFont(Font.BOLD));
        sumScannedLbl.setForeground(new Color(0, 130, 0));
        sumFailedLbl.setForeground(new Color(180, 0, 0));
        sumAuthLbl.setForeground(new Color(120, 80, 0));
        summaryBar.add(sumScannedLbl);
        summaryBar.add(new JLabel("  |"));
        summaryBar.add(sumFailedLbl);
        summaryBar.add(new JLabel("  |"));
        summaryBar.add(sumAuthLbl);
        summaryBar.add(new JLabel("  |"));
        for (JCheckBox cb : new JCheckBox[]{
                followScriptSrcBox, followChunksBox, scopeMonitorBox, crossOriginBox, headlessBrowseBox}) {
            cb.setFont(sf);
            cb.setOpaque(false);
            summaryBar.add(cb);
        }

        // Cap heights so BoxLayout below never stretches either row into dead empty space.
        optPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE,
                Math.max(36, optPanel.getPreferredSize().height) + 4));
        summaryBar.setMaximumSize(new Dimension(Integer.MAX_VALUE,
                Math.max(30, summaryBar.getPreferredSize().height) + 6));

        // BoxLayout stacks optPanel + summaryBar with no empty gap in between.
        JPanel northWrapper = new JPanel();
        northWrapper.setLayout(new BoxLayout(northWrapper, BoxLayout.Y_AXIS));
        northWrapper.add(optPanel);
        northWrapper.add(summaryBar);

        // ── Assemble layout ────────────────────────────────────────────────
        // Vertical split: drag divider to resize Scan Options vs Findings table.
        // resizeWeight=0 → findings panel absorbs all extra height on window resize.
        JSplitPane vertSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, northWrapper, centrePanel);
        vertSplit.setResizeWeight(0.0);
        vertSplit.setBorder(null);
        // Set the divider to northWrapper's real height AFTER the panel is shown,
        // so the pixel value is respected regardless of DPI or L&F.
        vertSplit.addHierarchyListener(e -> {
            if ((e.getChangeFlags() & java.awt.event.HierarchyEvent.SHOWING_CHANGED) != 0
                    && vertSplit.isShowing()) {
                SwingUtilities.invokeLater(() ->
                        vertSplit.setDividerLocation(northWrapper.getPreferredSize().height + 2));
            }
        });

        JPanel topArea = new JPanel(new BorderLayout(6, 6));
        topArea.add(vertSplit,   BorderLayout.CENTER);
        topArea.add(bottomPanel, BorderLayout.SOUTH);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, inputPanel, topArea);
        split.setResizeWeight(0.0);   // findings panel absorbs all extra width on window resize
        // Set divider proportionally when first shown so it fills the window correctly
        // regardless of screen size or DPI — avoids the fixed 300px feeling too narrow
        // on large displays and too wide on small ones.
        split.addHierarchyListener(e -> {
            if ((e.getChangeFlags() & java.awt.event.HierarchyEvent.SHOWING_CHANGED) != 0
                    && split.isShowing()) {
                SwingUtilities.invokeLater(() -> split.setDividerLocation(0.22));
            }
        });

        rootPanel.add(split, BorderLayout.CENTER);
    }

    // =========================================================================
    // Scope Monitor toggle
    // =========================================================================

    private void toggleScopeMonitor() {
        boolean on = scopeMonitorBox.isSelected();
        if (on) {
            ScopeMonitor.clearWatched();
            parseUrls().forEach(ScopeMonitor::addWatchedUrl);
            ScopeMonitor.setListener((f, url) -> SwingUtilities.invokeLater(() -> appendFinding(f)));
            ScopeMonitor.setActive(true);
            statusLabel.setText("Scope monitor active (" + parseUrls().size() + " hosts watched).");
        } else {
            ScopeMonitor.setActive(false);
            ScopeMonitor.setListener(null);
            statusLabel.setText("Scope monitor disabled.");
        }
    }

    // =========================================================================
    // Scan orchestration
    // =========================================================================

    private void startScan() {
        List<String> urls = parseUrls();
        if (urls.isEmpty()) {
            JOptionPane.showMessageDialog(rootPanel,
                    "Please enter at least one URL to scan.",
                    "No URLs", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Warn if Burp's proxy intercept is ON — all scan requests will be held,
        // causing the scan to complete immediately with zero findings.
        // Apply the bulk-scan tier selection to the shared settings object so that
        // all scan code paths (SecretScanner, processUrl, etc.) use the correct tier.
        settings.setTier(ScanSettings.ScanTier.valueOf((String) tierCombo.getSelectedItem()));

        running.set(true);
        urlsDone.set(0);
        urlsStarted.set(0);
        totalExpected.set(urls.size());   // seed with base URL count so bar never prematurely hits 100%
        totalDone.set(0);
        seenUrls.clear();
        seenFindings.clear();   // reset per-scan dedup so a re-run always shows all findings fresh
        scanner.clearRequestDedup();
        statusScanned.set(0);
        statusFailed.set(0);
        statusAuth.set(0);
        targetStatusModel.setRowCount(0);
        updateSummaryBar();
        startBtn.setEnabled(false);
        siteMapBtn.setEnabled(false);
        stopBtn.setEnabled(true);
        statusLabel.setForeground(new Color(0, 100, 180));
        startScanTimer();

        // Register scope monitor watched hosts from URL list
        if (scopeMonitorBox.isSelected()) {
            ScopeMonitor.clearWatched();
            urls.forEach(ScopeMonitor::addWatchedUrl);
            // Re-set listener in case it was cleared; ensures proxy findings continue to
            // flow into the panel for the duration of this scan session.
            ScopeMonitor.setListener((f, url) -> SwingUtilities.invokeLater(() -> appendFinding(f)));
            ScopeMonitor.setActive(true);
        }

        // ── Static HTTP fetch ──────────────────────────────────────────────
        {
            lastScanTotal = urls.size();
            progressBar.setIndeterminate(true);
            progressBar.setString("Discovering…");
            startProgressTimer();
            statusLabel.setText("Scanning " + urls.size() + " URL(s)…");
            api.logging().logToOutput("[BulkScan] Starting scan of " + urls.size()
                    + " URL(s). Tier=" + tierCombo.getSelectedItem()
                    + "  Threads=" + (int) concurrencySpinner.getValue()
                    + "  Burp=" + api.burpSuite().version()
                    + "  OS=" + System.getProperty("os.name") + " " + System.getProperty("os.version")
                    + "  Java=" + System.getProperty("java.version"));

            // Auto site-map sweep — runs in parallel with active fetch.
            // Captures authenticated HTML responses recorded in Burp's site map
            // during manual Burp Browser browsing: pages that redirect to an SSO
            // provider (e.g. Microsoft Entra, Okta) when fetched without a session
            // cookie would otherwise be missed by the active fetch below.
            Set<String> watchedHosts = new HashSet<>();
            for (String u : urls) {
                String norm = normaliseUrl(u);
                if (norm != null) {
                    try { watchedHosts.add(new java.net.URL(norm).getHost().toLowerCase()); }
                    catch (Exception ignored) {}
                }
            }
            if (!watchedHosts.isEmpty()) {
                // Build a URL→HttpRequestResponse index of site map HTML pages for the watched
                // hosts.  processUrl() uses this to prefer authenticated HTML (captured during
                // Burp Browser browsing) over the unauthenticated active-fetch body.
                siteMapIndex = buildSiteMapIndex(watchedHosts);
                Set<String> hostsSnap = Collections.unmodifiableSet(watchedHosts);
                siteMapSweepThread = new Thread(() -> {
                    sweepSiteMapForHosts(hostsSnap);
                    // Also sweep proxy history for entries not in the site map — primarily
                    // captures authenticated JSON API endpoint responses (e.g. OAuth token
                    // endpoints) that Burp records in proxy history but does not promote to
                    // the site map unless the URL is in Burp's configured target scope.
                    sweepProxyHistoryForHosts(hostsSnap);
                    siteMapSweepThread = null;
                    SwingUtilities.invokeLater(this::onSweepComplete);
                }, "SecretSifter-SiteMapSweep");
                siteMapSweepThread.setDaemon(true);
                siteMapSweepThread.start();
            }

            int threads = (int) concurrencySpinner.getValue();
            executor = Executors.newFixedThreadPool(threads, r -> {
                Thread t = new Thread(r, "SecretSifter-Bulk");
                t.setDaemon(true);
                return t;
            });

            for (String url : urls) {
                executor.submit(() -> {
                    if (!running.get()) return;
                    urlsStarted.incrementAndGet();
                    try {
                        processUrl(url);
                    } catch (Exception e) {
                        debugLog("BulkScanPanel.processUrl(" + url + "): " + e.toString());
                    } finally {
                        totalDone.incrementAndGet();   // count this base URL as done in the progress bar
                        int mainDone  = urlsDone.incrementAndGet();
                        int mainTotal = urls.size();
                        if (mainDone >= mainTotal) {
                            SwingUtilities.invokeLater(() -> onScanComplete(mainTotal));
                        }
                    }
                });
            }
            executor.shutdown();
        }
    }

    // =========================================================================
    // Scan Burp's site map
    // =========================================================================

    private void scanFromSiteMap() {
        // Apply the bulk-scan tier selection before scanning.
        settings.setTier(ScanSettings.ScanTier.valueOf((String) tierCombo.getSelectedItem()));

        // Clear URL-dedup set so a prior browser scan or static scan does not
        // silently suppress findings here. Each "Scan Site Map" invocation is
        // independent and must process every matching entry from scratch.
        seenUrls.clear();
        scanner.clearRequestDedup();

        // "Scan Site Map" always scans ALL entries — the URL list is for active fetch only.
        final Set<String> watchedHosts = Collections.emptySet();
        final boolean filterByHost = false;

        startBtn.setEnabled(false);
        siteMapBtn.setEnabled(false);
        statusLabel.setText("Querying Burp site map…");
        statusLabel.setForeground(new Color(0, 100, 180));
        progressBar.setIndeterminate(true);
        progressBar.setString("Scanning site map…");
        startScanTimer();

        // Pre-fetch site map on the EDT — on macOS, Burp's internal site-map model is
        // Swing-backed and calling requestResponses() from a background thread returns an
        // empty snapshot (silent failure). On Windows/Linux Swing is more permissive off-EDT,
        // which is why it works there but not on macOS. Pre-fetching here is safe on all OSes.
        final List<burp.api.montoya.http.message.HttpRequestResponse> siteMapSnapshot;
        try {
            siteMapSnapshot = api.siteMap().requestResponses();
        } catch (Exception fetchErr) {
            debugLog("scanFromSiteMap: cannot read site map: " + fetchErr);
            progressBar.setIndeterminate(false);
            progressBar.setString("");
            startBtn.setEnabled(true);
            siteMapBtn.setEnabled(true);
            statusLabel.setText("Site map unavailable: " + fetchErr);
            statusLabel.setForeground(Color.RED);
            stopScanTimer();
            return;
        }

        debugLog("[SiteMap] snapshot size=" + siteMapSnapshot.size()
                + "  watchedHosts=" + (filterByHost ? watchedHosts : "ALL")
                + "  EDT=" + SwingUtilities.isEventDispatchThread());

        running.set(true);
        stopBtn.setEnabled(true);

        Thread t = new Thread(() -> {
            try {
                int scanned = 0;
                int skippedNoMatch = 0, skippedNoCt = 0;
                for (burp.api.montoya.http.message.HttpRequestResponse rr : siteMapSnapshot) {
                    if (!running.get()) break;
                    if (rr.response() == null || rr.request() == null) continue;
                    String itemUrl = rr.request().url();
                    if (itemUrl == null || itemUrl.isBlank()) continue;

                    // Match host against watched set (exact or subdomain)
                    boolean matches = false;
                    try {
                        String host = new java.net.URL(itemUrl).getHost().toLowerCase();
                        for (String wh : watchedHosts) {
                            if (host.equals(wh) || host.endsWith("." + wh)) {
                                matches = true;
                                break;
                            }
                        }
                    } catch (Exception ignored) {}
                    // Cross-origin: check Referer header for API calls made from a watched host
                    // (e.g. api.example.com called from app.example.com)
                    if (!matches) {
                        String referer = rr.request().headerValue("Referer");
                        if (referer != null && !referer.isBlank()) {
                            try {
                                String refHost = new java.net.URL(referer).getHost().toLowerCase();
                                for (String wh : watchedHosts) {
                                    if (refHost.equals(wh) || refHost.endsWith("." + wh)) {
                                        matches = true;
                                        break;
                                    }
                                }
                            } catch (Exception ignored) {}
                        }
                    }
                    // Also check Origin header — XHR/Fetch requests always include it
                    if (!matches) {
                        String origin = rr.request().headerValue("Origin");
                        if (origin != null && !origin.isBlank()) {
                            try {
                                String originHost = new java.net.URL(origin).getHost().toLowerCase();
                                for (String wh : watchedHosts) {
                                    if (originHost.equals(wh) || originHost.endsWith("." + wh)) {
                                        matches = true;
                                        break;
                                    }
                                }
                            } catch (Exception ignored) {}
                        }
                    }
                    if (filterByHost && !matches) { skippedNoMatch++; continue; }
                    // Reject CDN/analytics domains even when Referer/Origin points to a watched host
                    // (e.g. cdn.segment.com analytics loaded from app.example.com — not in scope)
                    if (settings.isExternalCdn(itemUrl)) continue;

                    String ct = rr.response().headerValue("Content-Type");
                    if (ct == null) ct = "";
                    ct = ct.toLowerCase();

                    String urlLc  = itemUrl.toLowerCase().replaceAll("[?#].*$", "");
                    boolean isJs   = urlLc.endsWith(".js")   || urlLc.endsWith(".mjs") ||
                                    ct.contains("javascript") || ct.contains("ecmascript");
                    boolean isHtml = ct.contains("text/html") || ct.contains("application/xhtml");
                    boolean isJson = urlLc.endsWith(".json")  ||
                                    ct.contains("application/json") || ct.contains("+json");
                    boolean isXml  = urlLc.endsWith(".xml")   ||
                                    ct.contains("text/xml")   || ct.contains("application/xml") ||
                                    ct.contains("+xml");
                    // OAuth token endpoints may return application/x-www-form-urlencoded
                    // or text/plain — scan these response bodies with the full scanner.
                    boolean isFormEncoded = ct.contains("application/x-www-form-urlencoded")
                                           || ct.contains("text/plain");

                    // ── Request body pre-check (needed for early-exit logic below) ─
                    String reqBody = null;
                    try { reqBody = rr.response() != null ? rr.request().bodyToString() : null; }
                    catch (Exception ignored) {}
                    boolean hasReqBody = reqBody != null && !reqBody.isBlank();

                    if (!isJs && !isHtml && !isJson && !isXml && !isFormEncoded && !hasReqBody) { skippedNoCt++; continue; }

                    // Scan response body
                    if (isJs || isHtml || isJson || isXml || isFormEncoded) {
                        String body = rr.response().bodyToString();
                        if (body != null && !body.isBlank()) {
                            String finalCt = isJs   ? "application/javascript"
                                           : isJson ? "application/json"
                                           : isXml  ? "text/xml"
                                           : ct;
                            scanAndAppend(body, finalCt, itemUrl, rr);
                            scanned++;
                        }
                    }

                    // Scan request body (POST/PUT/PATCH data may embed hardcoded secrets)
                    if (hasReqBody) {
                        String reqCt = rr.request().headerValue("Content-Type");
                        scanAndAppend(reqBody, reqCt != null ? reqCt : "text/plain",
                                      itemUrl + " [REQ-BODY]", rr);
                    }

                    // Scan request headers (x-api-key, Authorization, custom headers)
                    if (isJs || isHtml || isJson || isXml || isFormEncoded) {
                        try {
                            StringBuilder hdrs = new StringBuilder();
                            for (var h : rr.request().headers()) {
                                hdrs.append(h.name()).append(": ").append(h.value()).append("\n");
                            }
                            if (hdrs.length() > 0) {
                                scanAndAppend(hdrs.toString(), "text/plain",
                                              itemUrl + " [REQ-HEADERS]", rr);
                            }
                        } catch (Exception ignored) {}
                    }
                }

                debugLog("[SiteMap] done: scanned=" + scanned
                        + "  skippedNoMatch=" + skippedNoMatch
                        + "  skippedNoCt=" + skippedNoCt);
                int finalScanned = scanned;
                SwingUtilities.invokeLater(() -> {
                    // If the user clicked Stop, stopScan() already updated the UI —
                    // do not overwrite the "Stopped." message or re-enable/disable buttons.
                    boolean wasRunning = running.getAndSet(false);
                    if (!wasRunning) return;
                    stopScanTimer();
                    progressBar.setIndeterminate(false);
                    progressBar.setString("");
                    startBtn.setEnabled(true);
                    siteMapBtn.setEnabled(true);
                    stopBtn.setEnabled(false);
                    String scope = filterByHost ? "" : " (all hosts)";
                    statusLabel.setText("Site map scan done. Processed " + finalScanned +
                            " response(s). " + tableFindings.size() + " finding(s) total." + scope);
                    statusLabel.setForeground(new Color(0, 130, 0));
                });
            } catch (Exception e) {
                debugLog("Site map scan error: " + e);
                SwingUtilities.invokeLater(() -> {
                    stopScanTimer();
                    progressBar.setIndeterminate(false);
                    progressBar.setString("");
                    startBtn.setEnabled(true);
                    siteMapBtn.setEnabled(true);
                    stopBtn.setEnabled(false);
                    running.set(false);
                    statusLabel.setText("Site map scan failed: " + e);
                    statusLabel.setForeground(Color.RED);
                });
            }
        }, "SecretSifter-SiteMap");
        t.setDaemon(true);
        t.start();
    }

    /**
     * Scans Burp site map responses whose host matches any of the watched hosts.
     * <p>
     * Called automatically at the start of each active Bulk Scan (in a daemon thread)
     * so that HTML pages captured during authenticated Burp Browser sessions are
     * included in the results — even when the active fetch below gets a 302 redirect
     * to an SSO provider (Microsoft Entra, Okta, etc.) because it has no session cookie.
     * <p>
     * Uses the same body-hash dedup as {@link #scanAndAppend} so there are no
     * duplicate findings when the same response body is also returned by active fetch.
     */
    private void sweepSiteMapForHosts(Set<String> watchedHosts) {
        if (watchedHosts.isEmpty()) return;
        try {
            // Pre-fetch on EDT — Burp's site-map model is Swing-backed; reading it off
            // the EDT on macOS returns an empty snapshot (same root cause as scanFromSiteMap).
            // This method runs on a daemon background thread so invokeAndWait is safe (no deadlock).
            final List<burp.api.montoya.http.message.HttpRequestResponse>[] ref = new List[1];
            try {
                SwingUtilities.invokeAndWait(() -> ref[0] = api.siteMap().requestResponses());
            } catch (Exception fetchErr) {
                debugLog("sweepSiteMapForHosts: cannot fetch site map: " + fetchErr);
                return;
            }
            for (burp.api.montoya.http.message.HttpRequestResponse rr : ref[0]) {
                // IMPORTANT: do NOT check running.get() here.
                // The active fetch (network requests) for a single URL completes very quickly
                // when the target redirects to SSO — onScanComplete sets running=false before
                // this sweep has iterated the site map. This sweep only reads cached local data
                // (no network I/O) so letting it always run to completion is correct and safe.
                if (rr.request() == null || rr.response() == null) continue;

                String itemUrl = rr.request().url();
                if (itemUrl == null || itemUrl.isBlank()) continue;

                // ── Match 1: direct host (exact or subdomain) ──────────────────────────
                boolean matches = false;
                try {
                    String host = new java.net.URL(itemUrl).getHost().toLowerCase();
                    for (String wh : watchedHosts) {
                        if (host.equals(wh) || host.endsWith("." + wh)) { matches = true; break; }
                    }
                } catch (Exception ignored) {}

                // ── Match 2: cross-origin via Referer header ────────────────────────────
                // e.g. target abc.com triggers API call to bcn.com — Referer: https://abc.com/
                if (!matches) {
                    String referer = rr.request().headerValue("Referer");
                    if (referer != null && !referer.isBlank()) {
                        try {
                            String refHost = new java.net.URL(referer).getHost().toLowerCase();
                            for (String wh : watchedHosts) {
                                if (refHost.equals(wh) || refHost.endsWith("." + wh)) { matches = true; break; }
                            }
                        } catch (Exception ignored) {}
                    }
                }

                // ── Match 3: cross-origin via Origin header ─────────────────────────────
                // XHR/Fetch requests always include Origin; use it as fallback
                if (!matches) {
                    String origin = rr.request().headerValue("Origin");
                    if (origin != null && !origin.isBlank()) {
                        try {
                            String originHost = new java.net.URL(origin).getHost().toLowerCase();
                            for (String wh : watchedHosts) {
                                if (originHost.equals(wh) || originHost.endsWith("." + wh)) { matches = true; break; }
                            }
                        } catch (Exception ignored) {}
                    }
                }

                if (!matches) continue;

                // Skip CDN/analytics domains (applied after scope check to avoid false positives)
                if (settings.isExternalCdn(itemUrl)) continue;

                // Only successful responses
                int status = rr.response().statusCode();
                if (status < 200 || status >= 300) continue;

                String ct   = rr.response().headerValue("Content-Type");
                String ctLc = ct != null ? ct.toLowerCase() : "";
                String urlLc = itemUrl.toLowerCase().replaceAll("[?#].*$", "");
                boolean isJs   = urlLc.endsWith(".js")   || urlLc.endsWith(".mjs") ||
                                 ctLc.contains("javascript") || ctLc.contains("ecmascript");
                boolean isHtml = ctLc.contains("text/html") || ctLc.contains("application/xhtml");
                boolean isJson = urlLc.endsWith(".json")  ||
                                 ctLc.contains("application/json") || ctLc.contains("+json");
                boolean isXml  = urlLc.endsWith(".xml")   ||
                                 ctLc.contains("text/xml")  || ctLc.contains("application/xml") ||
                                 ctLc.contains("+xml");
                // OAuth token endpoints may return application/x-www-form-urlencoded
                // or text/plain — scan these response bodies with the full scanner.
                boolean isFormEncoded = ctLc.contains("application/x-www-form-urlencoded")
                                       || ctLc.contains("text/plain");
                // ── Determine whether there is a request body to scan ─────────────
                String reqBody = null;
                try { reqBody = rr.request().bodyToString(); } catch (Exception ignored) {}
                boolean hasReqBody = reqBody != null && !reqBody.isBlank();

                // Skip if no scannable content at all
                if (!isJs && !isHtml && !isJson && !isXml && !isFormEncoded && !hasReqBody) continue;

                // Scan response body (JS / HTML / JSON / XML / form-encoded)
                if (isJs || isHtml || isJson || isXml || isFormEncoded) {
                    String body = rr.response().bodyToString();
                    if (body != null && !body.isBlank()) {
                        scanAndAppend(body, ct, itemUrl, rr);
                    }
                }

                // Scan request body — POST/PUT/PATCH bodies may carry hardcoded secrets
                // (e.g. API keys embedded in frontend code and sent in every POST call)
                if (hasReqBody) {
                    String reqCt = rr.request().headerValue("Content-Type");
                    scanAndAppend(reqBody, reqCt != null ? reqCt : "text/plain",
                                  itemUrl + " [REQ-BODY]", rr);
                }

                // Scan request headers — custom headers like x-api-key, Authorization,
                // x-auth-token may carry hardcoded API keys injected by frontend JS.
                // Limit to API/page traffic to avoid noise from static asset requests.
                if (isJs || isHtml || isJson || isXml || isFormEncoded) {
                    try {
                        StringBuilder hdrs = new StringBuilder();
                        for (var h : rr.request().headers()) {
                            hdrs.append(h.name()).append(": ").append(h.value()).append("\n");
                        }
                        if (hdrs.length() > 0) {
                            scanAndAppend(hdrs.toString(), "text/plain",
                                          itemUrl + " [REQ-HEADERS]", rr);
                        }
                    } catch (Exception ignored) {}
                }
            }
        } catch (Exception e) {
            debugLog("sweepSiteMapForHosts: " + e.toString());
        }
    }

    /**
     * Sweeps Burp's proxy history for entries matching the watched hosts and scans
     * any JSON, JS, or form-encoded responses not already covered by the site map sweep.
     * <p>
     * This is the primary path for capturing authenticated API endpoint responses
     * (e.g. OAuth2 token endpoints returning JWT access_tokens) that Burp records in
     * proxy history during manual Burp Browser browsing but does NOT promote to the
     * site map unless the URL is inside Burp's configured target scope.
     * <p>
     * Called from the same background thread as {@link #sweepSiteMapForHosts} so
     * there is no additional thread overhead. The URL-based dedup in
     * {@link #scanAndAppend} ensures that responses already scanned by the site map
     * sweep are not scanned again.
     */
    private void sweepProxyHistoryForHosts(Set<String> watchedHosts) {
        if (watchedHosts.isEmpty()) return;
        try {
            final List<burp.api.montoya.proxy.ProxyHttpRequestResponse>[] ref = new List[1];
            try {
                SwingUtilities.invokeAndWait(() -> {
                    try { ref[0] = api.proxy().history(); }
                    catch (Exception ignored) { ref[0] = List.of(); }
                });
            } catch (Exception e) {
                debugLog("sweepProxyHistoryForHosts: cannot fetch history: " + e);
                return;
            }
            int swept = 0;
            for (burp.api.montoya.proxy.ProxyHttpRequestResponse prr : ref[0]) {
                if (prr.request() == null || prr.response() == null) continue;
                int s = prr.response().statusCode();
                if (s < 200 || s >= 300) continue;
                String phUrl = prr.request().url();
                if (phUrl == null || settings.isExternalCdn(phUrl)) continue;

                // Match against watched hosts (direct host + cross-origin Referer/Origin)
                boolean matches = false;
                try {
                    String host = new java.net.URL(phUrl).getHost().toLowerCase();
                    for (String wh : watchedHosts) {
                        if (host.equals(wh) || host.endsWith("." + wh)) { matches = true; break; }
                    }
                } catch (Exception ignored) {}
                if (!matches) {
                    String referer = prr.request().headerValue("Referer");
                    if (referer != null && !referer.isBlank()) {
                        try {
                            String refHost = new java.net.URL(referer).getHost().toLowerCase();
                            for (String wh : watchedHosts) {
                                if (refHost.equals(wh) || refHost.endsWith("." + wh)) { matches = true; break; }
                            }
                        } catch (Exception ignored) {}
                    }
                }
                if (!matches) {
                    String origin = prr.request().headerValue("Origin");
                    if (origin != null && !origin.isBlank()) {
                        try {
                            String originHost = new java.net.URL(origin).getHost().toLowerCase();
                            for (String wh : watchedHosts) {
                                if (originHost.equals(wh) || originHost.endsWith("." + wh)) { matches = true; break; }
                            }
                        } catch (Exception ignored) {}
                    }
                }
                if (!matches) continue;

                String phCt   = prr.response().headerValue("Content-Type");
                if (phCt == null) phCt = "";
                String phCtLc = phCt.toLowerCase();
                String phUrlLc = phUrl.toLowerCase().replaceAll("[?#].*$", "");
                boolean isJs   = phCtLc.contains("javascript") || phCtLc.contains("ecmascript")
                                 || phUrlLc.endsWith(".js")    || phUrlLc.endsWith(".mjs");
                boolean isJson = phCtLc.contains("application/json") || phCtLc.contains("+json")
                                 || phUrlLc.endsWith(".json");
                boolean isHtml = phCtLc.contains("text/html") || phCtLc.contains("application/xhtml");
                boolean isFormEncoded = phCtLc.contains("application/x-www-form-urlencoded")
                                       || phCtLc.contains("text/plain");
                if (!isJs && !isJson && !isHtml && !isFormEncoded) continue;

                // Scan response body — scanAndAppend's seenUrls guard prevents rescanning
                // URLs already covered by sweepSiteMapForHosts.
                String phBody = prr.response().bodyToString();
                if (phBody != null && !phBody.isBlank()) {
                    HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(
                            prr.request(), prr.response());
                    scanAndAppend(phBody, phCt, phUrl, rr);
                    swept++;
                }

                // Scan request headers for API keys
                try {
                    StringBuilder hdrs = new StringBuilder();
                    for (var h : prr.request().headers()) {
                        hdrs.append(h.name()).append(": ").append(h.value()).append("\n");
                    }
                    if (hdrs.length() > 0)
                        scanAndAppend(hdrs.toString(), "text/plain", phUrl + " [REQ-HEADERS]", null);
                } catch (Exception ignored) {}
            }
            if (swept > 0)
                debugLog("[ProxyHistSweep] Scanned " + swept
                        + " proxy history entry(ies) for watched hosts.");
        } catch (Exception e) {
            debugLog("sweepProxyHistoryForHosts: " + e.toString());
        }
    }

    /**
     * Builds a URL → HttpRequestResponse index from Burp's site map, restricted to
     * 200-OK HTML responses for the given watched hosts.
     * <p>
     * Called once at the start of each static bulk scan so {@link #processUrl} can
     * look up each target URL in O(1) instead of iterating the full site map per URL.
     * Only HTML responses are indexed because the goal is to replace the unauthenticated
     * active-fetch HTML body with the authenticated site map body for HTML scanning and
     * {@code <script src>} extraction.
     */
    private Map<String, HttpRequestResponse> buildSiteMapIndex(Set<String> watchedHosts) {
        Map<String, HttpRequestResponse> index = new HashMap<>();
        try {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr.request() == null || rr.response() == null) continue;
                int status = rr.response().statusCode();
                if (status < 200 || status >= 300) continue;
                String ct = rr.response().headerValue("Content-Type");
                if (ct == null) continue;
                String ctLc = ct.toLowerCase();
                if (!ctLc.contains("text/html") && !ctLc.contains("application/xhtml")) continue;
                String url = rr.request().url();
                if (url == null) continue;
                try {
                    String host = new java.net.URL(url).getHost().toLowerCase();
                    for (String wh : watchedHosts) {
                        if (host.equals(wh) || host.endsWith("." + wh)) {
                            // Normalise: strip query/fragment + trailing slash for matching
                            String normUrl = url.split("[?#]")[0].replaceAll("/$", "");
                            index.putIfAbsent(normUrl, rr);
                            break;
                        }
                    }
                } catch (Exception ignored) {}
            }
        } catch (Exception e) {
            debugLog("buildSiteMapIndex: " + e.toString());
        }
        debugLog("buildSiteMapIndex: indexed " + index.size() + " HTML page(s).");
        return index;
    }

    public void stopScan() {
        running.set(false);
        if (executor != null) executor.shutdownNow();
        onScanComplete(-1);
    }

    /**
     * Called by the extension unloading handler.
     * Stops any running scan, interrupts the site-map sweep thread, and releases
     * large in-memory state so the old class loader can be garbage-collected.
     */
    public void shutdown() {
        stopScan();
        Thread sweepThread = siteMapSweepThread;
        if (sweepThread != null) sweepThread.interrupt();
        siteMapIndex = Collections.emptyMap();
        ScopeMonitor.setActive(false);
        ScopeMonitor.setListener(null);
        ScopeMonitor.clearWatched();
    }

    /** Syncs the Scan Tier combo to the value loaded from persisted preferences. */
    public void syncFromSettings() {
        SwingUtilities.invokeLater(() -> {
            if (tierCombo != null) tierCombo.setSelectedItem(settings.getTier().name());
        });
    }

    /**
     * Rebuilds HTTP_CLIENT using the current allowInsecureSsl preference.
     * Must be called after settings are loaded from preferences so that a saved
     * "Allow insecure SSL = true" preference is honoured at startup.
     * No-op if the value has not changed since the client was last built.
     */
    public void syncHttpClient() {
        boolean allow = settings.isAllowInsecureSsl();
        int port = (proxyPortSpinner != null) ? (int) proxyPortSpinner.getValue() : 8080;
        if (allow == httpClientAllowInsecureSsl) return;
        httpClientAllowInsecureSsl = allow;
        HTTP_CLIENT   = buildHttpClient(allow, port);
        IP_HTTP_CLIENT = buildHttpClient(true, port);
    }

    // =========================================================================
    // Scan timer helpers
    // =========================================================================

    /** Starts (or restarts) the elapsed-time ticker shown next to the progress bar. */
    private void startScanTimer() {
        scanStartMs = System.currentTimeMillis();
        if (scanTimer != null) scanTimer.stop();
        timerLabel.setForeground(new Color(0, 100, 180));
        timerLabel.setText("⏱ 0:00");
        scanTimer = new javax.swing.Timer(1000, e -> {
            long secs = (System.currentTimeMillis() - scanStartMs) / 1000;
            timerLabel.setText(String.format("⏱ %d:%02d", secs / 60, secs % 60));
        });
        scanTimer.start();
    }

    /** Stops the ticker and freezes the final elapsed time display. */
    private void stopScanTimer() {
        if (scanTimer != null) {
            scanTimer.stop();
            long secs = (System.currentTimeMillis() - scanStartMs) / 1000;
            timerLabel.setText(String.format("⏱ %d:%02d", secs / 60, secs % 60));
            timerLabel.setForeground(Color.GRAY);
        }
    }

    /** Polls totalDone/totalExpected every 100 ms and updates the progress bar.
     *  Discovery phase (totalExpected==0): indeterminate swinging bar + "Discovering…".
     *  Scanning phase  (totalExpected> 0): determinate bar showing done/total count.
     *  Runs on the EDT via Swing Timer — worker threads only update atomics, no invokeLater flooding. */
    private void startProgressTimer() {
        if (progressTimer != null) progressTimer.stop();
        progressTimer = new javax.swing.Timer(100, e -> {
            int done = totalDone.get();
            int exp  = totalExpected.get();
            if (exp == 0) {
                // Discovery phase — JS files not yet counted; keep swinging
                if (!progressBar.isIndeterminate()) {
                    progressBar.setIndeterminate(true);
                }
                int uDone  = urlsStarted.get();
                int uTotal = lastScanTotal;
                progressBar.setString(uDone + " / " + uTotal + "  Discovering…");
            } else {
                // Scanning phase — show URL count + live findings count
                if (!progressBar.isIndeterminate()) {
                    progressBar.setIndeterminate(true);
                }
                int findings = tableFindings.size();
                progressBar.setString("Scanning " + lastScanTotal + " URL(s)  \u00b7  " + findings + " finding(s) so far");
            }
        });
        progressTimer.start();
    }

    private void stopProgressTimer() {
        if (progressTimer != null) {
            progressTimer.stop();
            progressTimer = null;
        }
    }

    private void onScanComplete(int total) {
        stopProgressTimer();
        running.set(false);
        siteMapIndex = Collections.emptyMap();   // release site-map HTML bodies held since scan start
        if (total >= 0) lastScanTotal = total;
        currentFileLabel.setText("");
        startBtn.setEnabled(true);
        siteMapBtn.setEnabled(true);
        stopBtn.setEnabled(false);
        // Stop oscillation and show fully filled bar on completion
        progressBar.setIndeterminate(false);
        progressBar.setMinimum(0);
        progressBar.setMaximum(100);
        progressBar.setValue(100);
        progressBar.setString("Complete");

        if (total < 0) {
            // Manual stop
            stopScanTimer();
            statusLabel.setText(String.format("Stopped.  %d URL(s) scanned  ·  %d finding(s)%s",
                    urlsDone.get(), tableFindings.size(), severitySummary()));
            statusLabel.setForeground(Color.GRAY);
        } else {
            Thread sweep = siteMapSweepThread;
            if (sweep != null && sweep.isAlive()) {
                // Active fetch done; site-map sweep still running — show interim status
                // and leave the timer ticking so the user can see it's still working.
                statusLabel.setText(String.format(
                        "Active scan done · Site map sweep running · %d finding(s) so far…",
                        tableFindings.size()));
                statusLabel.setForeground(new Color(0, 100, 180));
            } else {
                // Sweep already finished (or never started) — show final totals now.
                stopScanTimer();
                statusLabel.setText(String.format("Done.  %d URL(s) scanned  ·  %d finding(s)%s",
                        total, tableFindings.size(), severitySummary()));
                statusLabel.setForeground(new Color(0, 130, 0));
                // Heuristic: all URLs failed with no findings → likely cause is Burp Intercept ON
                if (total > 0 && statusFailed.get() >= total && tableFindings.isEmpty()) {
                    statusLabel.setText(statusLabel.getText() + "  —  Tip: Is Burp Proxy Intercept ON?");
                    statusLabel.setForeground(new Color(160, 80, 0));
                }
            }
        }
    }

    /** Called on the EDT when the background site-map sweep thread finishes. */
    private void onSweepComplete() {
        if (!running.get()) {
            // Active scan has already finished — show final totals now.
            stopScanTimer();
            statusLabel.setText(String.format("Done.  %d URL(s) scanned  ·  %d finding(s)%s",
                    lastScanTotal, tableFindings.size(), severitySummary()));
            statusLabel.setForeground(new Color(0, 130, 0));
            api.logging().logToOutput("[BulkScan] Site map sweep complete. Total findings: "
                    + tableFindings.size());
        }
        // else: active scan still running; onScanComplete() will update the final status.
    }

    // =========================================================================
    // Per-URL processing
    // =========================================================================

    private void processUrl(String targetUrl) {
        if (!running.get()) return;
        String normalisedInit = normaliseUrl(targetUrl);
        if (normalisedInit == null) return;
        SwingUtilities.invokeLater(() -> currentFileLabel.setText("→ " + normalisedInit));
        debugLog("[BulkScan] Processing: " + normalisedInit);
        String normalised = normalisedInit;

        // 1. Fetch the landing page to determine the final URL after redirects.
        //    The fetched body may be a login/SSO page if the target requires authentication.
        FetchResult page = fetchUrl(normalised);

        // HTTP fallback: if HTTPS fetch failed (SSL error, cert mismatch, IP-based host
        // without a valid TLS cert), retry with HTTP.  Many internal apps and dev servers
        // don't have TLS.  Only applied when the caller didn't explicitly specify https://.
        if (page == null && normalised.startsWith("https://")) {
            String httpUrl = "http://" + normalised.substring(8);
            api.logging().logToOutput("[BulkScan] HTTPS failed — retrying HTTP: " + httpUrl);
            page = fetchUrl(httpUrl);
            if (page != null) normalised = httpUrl;
        }

        // Record per-target reachability status (Option 1 + 4)
        if (page == null) {
            // Complete connection failure — DNS, timeout, SSL exception
            statusFailed.incrementAndGet();
            recordTargetStatus(targetUrl, "×", "Unreachable");
            api.logging().logToOutput("[BulkScan] Unreachable: " + targetUrl);
            return;
        }
        if (page.body() == null) {
            // Got an HTTP response but server returned an error code
            int sc = page.statusCode();
            if (sc == 401 || sc == 403) {
                statusAuth.incrementAndGet();
                recordTargetStatus(targetUrl, "~", "HTTP " + sc);
            } else {
                statusFailed.incrementAndGet();
                recordTargetStatus(targetUrl, "×", "HTTP " + sc);
            }
            api.logging().logToOutput("[BulkScan] HTTP " + sc + " — skipped: " + targetUrl);
            return;
        }
        debugLog("[BulkScan] Fetched: ct=" + page.contentType()
                + "  bodyLen=" + page.body().length()
                + (page.finalUrl() != null && !page.finalUrl().equals(normalised)
                   ? "  final=" + page.finalUrl() : ""));

        String effectiveUrl = (page.finalUrl() != null && !page.finalUrl().equals(normalised))
                ? page.finalUrl() : normalised;
        // Register the redirect-target host in the scope monitor so future proxy traffic
        // (Burp Browser browsing) from that host routes findings to this panel.
        if (!effectiveUrl.equals(normalised) && scopeMonitorBox.isSelected()) {
            ScopeMonitor.addWatchedUrl(effectiveUrl);
        }

        // Detect cross-host redirect (e.g. app → SSO/Entra/Okta login page).
        // When the active fetch lands on a completely different host than the one requested,
        // the fetched HTML is the IdP login page — useless for secret scanning and script
        // extraction.  We must anchor script-src host-filtering to the ORIGINAL requested
        // host (not the SSO domain) so we never follow Microsoft/Okta login-page scripts.
        // If no site-map entry is found, we also reset baseUrl to the original URL so that
        // relative script paths resolve against the real application domain.
        String originalHost  = null;
        String effectiveHost = null;
        boolean crossHostRedirect = false;
        try {
            originalHost  = new java.net.URL(normalised).getHost().toLowerCase();
            effectiveHost = new java.net.URL(effectiveUrl).getHost().toLowerCase();
            crossHostRedirect = !effectiveHost.equals(originalHost)
                             && !effectiveHost.endsWith("." + originalHost)
                             && !originalHost.endsWith("." + effectiveHost);
        } catch (Exception ignored) {}

        if (crossHostRedirect) {
            // Auth-wall: show "~" in target status (same icon as 401/403), not "+" (clean scan).
            // This makes Windows users immediately see that the target is behind SSO/auth,
            // rather than wondering why a "+" target returned 0 findings.
            statusAuth.incrementAndGet();
            recordTargetStatus(targetUrl, "~", "SSO→" + effectiveHost);
            api.logging().logToOutput("[BulkScan] SSO/auth redirect: " + normalised
                    + " → " + effectiveHost + " — browse in Burp Browser first to populate site map");
            debugLog("[BulkScan] Cross-host redirect detail: final=" + effectiveUrl
                    + "  script-host anchored to: " + originalHost);
        } else {
            statusScanned.incrementAndGet();
            recordTargetStatus(targetUrl, "+", "HTTP " + page.statusCode());
        }

        // 2. Site map priority: prefer the authenticated HTML body captured in Burp's site
        //    map during prior Burp Browser browsing over the unauthenticated active fetch body.
        //
        //    When a target redirects to SSO/Entra without a session cookie, the fetched body
        //    is the IdP login page — useless for secret scanning and <script src> extraction.
        //    Checking the site map for both the entry-point URL and the final redirect target
        //    covers two common patterns:
        //      • abc.com → 302 → login.microsoftonline.com  (entry-point has real HTML in site map)
        //      • 192.168.1.1 → 302 → app.example.com        (finalUrl has real HTML in site map)
        //    siteMapIndex is built once in startScan() so this lookup is O(1).
        String              htmlBody = page.body();
        String              htmlCt   = page.contentType();
        HttpRequestResponse htmlRr   = page.requestResponse();
        // For cross-host redirects with no site-map override: anchor baseUrl to the original
        // requested URL so relative script paths resolve against the real application domain.
        String              baseUrl  = crossHostRedirect ? normalised : effectiveUrl;

        Map<String, HttpRequestResponse> idx = siteMapIndex;
        if (!idx.isEmpty()) {
            String normOrig  = normalised.split("[?#]")[0].replaceAll("/$", "");
            String normFinal = effectiveUrl.split("[?#]")[0].replaceAll("/$", "");
            HttpRequestResponse smEntry = idx.get(normOrig);
            if (smEntry == null && !normFinal.equals(normOrig)) smEntry = idx.get(normFinal);
            if (smEntry != null) {
                String smBody = smEntry.response().bodyToString();
                String smCt   = smEntry.response().headerValue("Content-Type");
                if (smBody != null && !smBody.isBlank()) {
                    htmlBody = smBody;
                    htmlCt   = smCt;
                    htmlRr   = smEntry;
                    baseUrl  = smEntry.request().url();   // use site map URL as base for resolving relative paths
                }
            }
        }

        scanAndAppend(htmlBody, htmlCt, baseUrl, htmlRr);

        // 3. Headless browse — launch Chrome through Burp proxy so JS executes and all
        //    dynamic XHR/fetch API calls fire.  SecretProxyHandler captures the traffic
        //    passively; findings appear in the table automatically via ScopeMonitor.
        // 4. Headless browse — launch Chrome through Burp proxy so JS executes and all
        //    dynamic XHR/fetch API calls fire.  SecretProxyHandler captures the traffic
        //    passively; findings appear in the table automatically via ScopeMonitor.
        // Collect scripts found in site map HTML pages AFTER headless populates it,
        // so multi-hop JS-redirect chains (e.g. IP → nawstart.html → 49 JS files) are captured.
        Set<String> postHeadlessScripts = new LinkedHashSet<>();
        if (headlessBrowseBox.isSelected() && running.get()) {
            int proxyPort = (int) proxyPortSpinner.getValue();
            // Snapshot proxy history size before headless visit so we can scan only the
            // new entries that Chrome's CDP replay added.  Cross-origin JSON API endpoints
            // (e.g. uat.studiogateway.chubb.com called from modelent.chubbworldview.com)
            // appear in proxy history immediately after replay but may not appear in the
            // site map if the host is out of Burp's scope.
            int[] proxyHistSnap = {-1};
            try { SwingUtilities.invokeAndWait(() -> {
                try { proxyHistSnap[0] = api.proxy().history().size(); } catch (Exception ignored) {}
            }); } catch (Exception ignored) {}
            String headlessDom = headlessVisit(normalised, proxyPort);
            // Sweep the live site map for all HTML pages now added by Chrome
            String targetHost;
            try { targetHost = new java.net.URL(baseUrl).getHost().toLowerCase(); }
            catch (Exception ignored) { targetHost = null; }
            if (targetHost != null) {
                // Fetch site-map snapshot on the EDT — on macOS the model is Swing-backed
                // and requestResponses() returns an empty list from a background thread.
                @SuppressWarnings("unchecked")
                List<HttpRequestResponse>[] postRef = new List[]{List.of()};
                try { SwingUtilities.invokeAndWait(() -> postRef[0] = api.siteMap().requestResponses()); }
                catch (Exception ignored) {}
                try {
                    for (HttpRequestResponse smRr : postRef[0]) {
                        if (smRr.request() == null || smRr.response() == null) continue;
                        int s = smRr.response().statusCode();
                        if (s < 200 || s >= 300) continue;
                        String smUrl = smRr.request().url();
                        if (smUrl == null) continue;
                        String smHost;
                        try { smHost = new java.net.URL(smUrl).getHost().toLowerCase(); }
                        catch (Exception ignored) { continue; }
                        if (!smHost.equals(targetHost)) {
                            // Cross-origin: scan new JSON/API responses whose request Referer
                            // points to the target (i.e. loaded by Chrome while on the target page).
                            // Catches pre-auth API calls to sub-domains / API gateways that ScopeMonitor
                            // may miss when the Referer header is absent from the request.
                            if (settings.isExternalCdn(smUrl)) { continue; }
                            String smCt2 = smRr.response().headerValue("Content-Type");
                            if (smCt2 != null) {
                                String smCt2Lc = smCt2.toLowerCase();
                                boolean isApiResp = smCt2Lc.contains("application/json")
                                        || smCt2Lc.contains("+json");
                                if (isApiResp && smRr.request() != null) {
                                    String referer = smRr.request().headerValue("Referer");
                                    if (referer != null) {
                                        try {
                                            String refHost = new java.net.URL(referer).getHost().toLowerCase();
                                            if (refHost.equals(targetHost)) {
                                                String smBody2 = smRr.response().bodyToString();
                                                if (smBody2 != null && !smBody2.isBlank()) {
                                                    scanAndAppend(smBody2, smCt2, smUrl, smRr);
                                                }
                                            }
                                        } catch (Exception ignored) {}
                                    }
                                }
                            }
                            continue;
                        }
                        if (settings.isExternalCdn(smUrl)) continue;
                        String smCt = smRr.response().headerValue("Content-Type");
                        if (smCt == null) continue;
                        String smCtLc = smCt.toLowerCase();
                        String smUrlLc = smUrl.toLowerCase().replaceAll("[?#].*$", "");
                        boolean smIsHtml = smCtLc.contains("text/html") || smCtLc.contains("application/xhtml");
                        boolean smIsJs   = smCtLc.contains("javascript") || smCtLc.contains("ecmascript")
                                           || smUrlLc.endsWith(".js") || smUrlLc.endsWith(".mjs");
                        boolean smIsJson = smCtLc.contains("application/json") || smCtLc.contains("+json")
                                           || smUrlLc.endsWith(".json");

                        if (!smIsHtml && !smIsJs && !smIsJson) continue;

                        String smBody = smRr.response().bodyToString();
                        if (smBody == null || smBody.isBlank()) continue;

                        // Scan this resource directly (dedup prevents double-scanning).
                        scanAndAppend(smBody, smCt, smUrl, smRr);

                        if (smIsHtml) {
                            // Collect script references for the active-fetch JS loop below.
                            postHeadlessScripts.addAll(SecretScanner.extractScriptSrcs(smBody, smUrl));
                            postHeadlessScripts.addAll(SecretScanner.extractPreloadLinks(smBody, smUrl));
                        }
                        if (smIsJs) {
                            // Collect chunk references from JS bundles so they are also fetched.
                            postHeadlessScripts.addAll(SecretScanner.extractWebpackChunkUrls(smBody, smUrl));
                        }
                    }
                    if (!postHeadlessScripts.isEmpty())
                        debugLog("[HeadlessSiteMap] Found " + postHeadlessScripts.size()
                                + " additional URL(s) from site map for: " + targetHost);
                } catch (Exception e) {
                    debugLog("[HeadlessSiteMap] Sweep failed: " + e.toString());
                }
            }
            // Extract script URLs directly from the rendered DOM.  This is the primary
            // discovery path when the Burp site map is empty (no prior browsing) — the
            // rendered DOM contains dynamically-injected <script> tags that the static
            // HTML fetch above cannot see.
            if (headlessDom != null && !headlessDom.isBlank()) {
                List<String> domScripts = new ArrayList<>();
                domScripts.addAll(SecretScanner.extractScriptSrcs(headlessDom, baseUrl));
                domScripts.addAll(SecretScanner.extractPreloadLinks(headlessDom, baseUrl));
                postHeadlessScripts.addAll(domScripts);
                if (!domScripts.isEmpty())
                    debugLog("[HeadlessDOM] Extracted " + domScripts.size()
                            + " script URL(s) from rendered DOM for: " + baseUrl);
            }

            // ── Proxy history sweep ──────────────────────────────────────────────────
            // CDP replay sends requests through Burp's proxy so they appear in proxy
            // history.  Cross-origin API endpoints (e.g. uat.studiogateway.chubb.com)
            // may not appear in the site map if they are out of Burp's scope, but they
            // ARE in proxy history.  Scan all new entries that appeared since proxyHistSnap.
            // Covers JSON API responses with tokens and request headers with API keys.
            if (proxyHistSnap[0] >= 0) {
                @SuppressWarnings("unchecked")
                java.util.List<burp.api.montoya.proxy.ProxyHttpRequestResponse>[] phRef =
                        new java.util.List[]{java.util.List.of()};
                try { SwingUtilities.invokeAndWait(() -> {
                    try { phRef[0] = api.proxy().history(); } catch (Exception ignored) {}
                }); } catch (Exception ignored) {}
                int phSwept = 0;
                for (int hi = proxyHistSnap[0]; hi < phRef[0].size(); hi++) {
                    if (!running.get()) break;
                    burp.api.montoya.proxy.ProxyHttpRequestResponse prr = phRef[0].get(hi);
                    if (prr.request() == null || prr.response() == null) continue;
                    int s = prr.response().statusCode();
                    if (s < 200 || s >= 300) continue;
                    String phUrl = prr.request().url();
                    if (phUrl == null || settings.isExternalCdn(phUrl)) continue;
                    String phCt = prr.response().headerValue("Content-Type");
                    if (phCt == null) phCt = "";
                    String phCtLc = phCt.toLowerCase();
                    String phUrlLc = phUrl.toLowerCase().replaceAll("[?#].*$", "");
                    boolean phIsJs   = phCtLc.contains("javascript") || phCtLc.contains("ecmascript")
                                       || phUrlLc.endsWith(".js")    || phUrlLc.endsWith(".mjs");
                    boolean phIsJson = phCtLc.contains("application/json") || phCtLc.contains("+json")
                                       || phUrlLc.endsWith(".json");
                    boolean phIsHtml = phCtLc.contains("text/html") || phCtLc.contains("application/xhtml");
                    if (!phIsJs && !phIsJson && !phIsHtml) continue;
                    // Scan response body — bypass seenUrls guard so that fresh proxy history
                    // responses captured during the CDP headless visit are always scanned,
                    // even if the same URL was already picked up by the pre-headless
                    // site-map sweep (sweepSiteMapForHosts adds the raw URL to seenUrls,
                    // which would otherwise silently block the fresh CDP response here).
                    String phBody = prr.response().bodyToString();
                    if (phBody != null && !phBody.isBlank()) {
                        String phLabelledUrl = sourceLabel(phUrl, phCt);
                        List<SecretFinding> phFindings = scanner.scanText(phBody, phCt, phLabelledUrl);
                        // Mark URL as seen so the script-src following loop doesn't re-fetch this
                        // URL via HTTP — it was just scanned from Chrome's proxy history capture.
                        seenUrls.add(phUrl);
                        debugLog("[HeadlessProxy] " + phFindings.size()
                                + " finding(s) in: " + phLabelledUrl
                                + "  (body=" + phBody.length() + " chars)");
                        for (SecretFinding pf : phFindings) {
                            SwingUtilities.invokeLater(() -> appendFinding(pf));
                        }
                        phSwept++;
                    }
                    // Scan request headers for API keys (x-api-key, Authorization, etc.)
                    try {
                        StringBuilder hdrs = new StringBuilder();
                        for (var h : prr.request().headers()) {
                            hdrs.append(h.name()).append(": ").append(h.value()).append("\n");
                        }
                        if (hdrs.length() > 0)
                            scanAndAppend(hdrs.toString(), "text/plain", phUrl + " [REQ-HEADERS]", null);
                    } catch (Exception ignored) {}
                }
                if (phSwept > 0)
                    debugLog("[HeadlessProxy] Scanned " + phSwept
                            + " new proxy history entry(ies) from CDP replay.");
            }
        }

        // 5. If HTML — follow script-src, <link rel="preload" as="script">, and manifests.
        //    Use baseUrl (authenticated site map URL or redirect-target URL) so that
        //    relative script paths resolve against the real app domain, not the entry-point.
        String ct = htmlCt != null ? htmlCt.toLowerCase() : "";
        if (ct.contains("text/html") || ct.contains("application/xhtml")) {
            Set<String> fetched = new HashSet<>();
            fetched.add(normalised);
            fetched.add(effectiveUrl);

            if (followScriptSrcBox.isSelected()) {
                // 3a. Collect JS URLs from <script src> + <link rel="preload" as="script">
                List<String> scriptUrls = new ArrayList<>(
                        SecretScanner.extractScriptSrcs(htmlBody, baseUrl));
                List<String> preloadUrls = SecretScanner.extractPreloadLinks(htmlBody, baseUrl);
                for (String u : preloadUrls) {
                    if (!scriptUrls.contains(u)) scriptUrls.add(u);
                }
                // Merge in scripts discovered from post-headless site map HTML pages
                for (String u : postHeadlessScripts) {
                    if (!scriptUrls.contains(u)) scriptUrls.add(u);
                }

                // Filter to same-host only. CDN / 3rd-party scripts (React, jQuery,
                // analytics bundles on cdn.jsdelivr.net, ajax.googleapis.com, etc.) are
                // public libraries — fetching and scanning them is slow and pointless.
                //
                // IMPORTANT: when a cross-host redirect was detected (e.g. app → SSO login),
                // anchor the host filter to the ORIGINAL requested host — not the SSO/IdP
                // domain — so login-page scripts (Microsoft, Okta, etc.) are excluded.
                // Without this, Windows machines with an empty site map would follow SSO
                // login-page scripts and find no app secrets (0 findings).
                String baseHost;
                if (crossHostRedirect && originalHost != null) {
                    baseHost = originalHost;   // anchor to original app domain, not SSO domain
                } else {
                    try { baseHost = new java.net.URL(baseUrl).getHost().toLowerCase(); }
                    catch (Exception e) { baseHost = null; }
                }
                int beforeFilter = scriptUrls.size();
                if (baseHost != null) {
                    final String fh = baseHost;
                    scriptUrls.removeIf(u -> {
                        try { return !new java.net.URL(u).getHost().toLowerCase().equals(fh); }
                        catch (Exception ignored) { return true; }
                    });
                }

                // Follow <frame src> and <iframe src> — frameset-based apps hide their
                // <script> references inside child frames rather than the root HTML.
                List<String> frameUrls = new ArrayList<>(SecretScanner.extractFrameSrcs(htmlBody, baseUrl));
                if (baseHost != null) {
                    final String fh2 = baseHost;
                    frameUrls.removeIf(u -> {
                        try { return !new java.net.URL(u).getHost().toLowerCase().equals(fh2); }
                        catch (Exception ignored) { return true; }
                    });
                }
                if (!frameUrls.isEmpty()) {
                    debugLog("[Frame] " + frameUrls.size()
                            + " frame(s) discovered in: " + baseUrl);
                }
                for (String frameUrl : frameUrls) {
                    if (!running.get()) break;
                    if (!fetched.add(frameUrl)) continue;
                    debugLog("[Frame] Fetching: " + frameUrl);
                    FetchResult fr = fetchUrl(frameUrl);
                    if (fr == null || fr.body() == null) continue;
                    scanAndAppend(fr.body(), "text/html", frameUrl, fr.requestResponse());
                    for (String u : SecretScanner.extractScriptSrcs(fr.body(), frameUrl)) {
                        try { if (baseHost != null && !new java.net.URL(u).getHost().toLowerCase().equals(baseHost)) continue; } catch (Exception ignored) { continue; }
                        if (!scriptUrls.contains(u)) scriptUrls.add(u);
                    }
                    for (String u : SecretScanner.extractPreloadLinks(fr.body(), frameUrl)) {
                        try { if (baseHost != null && !new java.net.URL(u).getHost().toLowerCase().equals(baseHost)) continue; } catch (Exception ignored) { continue; }
                        if (!scriptUrls.contains(u)) scriptUrls.add(u);
                    }
                    // Also recurse one level for nested frames
                    for (String u : SecretScanner.extractFrameSrcs(fr.body(), frameUrl)) {
                        try {
                            if (baseHost != null &&
                                !new java.net.URL(u).getHost().toLowerCase().equals(baseHost)) continue;
                        } catch (Exception ignored) { continue; }
                        if (!fetched.add(u)) continue;
                        debugLog("[Frame] Fetching nested frame: " + u);
                        FetchResult nfr = fetchUrl(u);
                        if (nfr == null || nfr.body() == null) continue;
                        scanAndAppend(nfr.body(), "text/html", u, nfr.requestResponse());
                        for (String s : SecretScanner.extractScriptSrcs(nfr.body(), u)) {
                            if (!scriptUrls.contains(s)) scriptUrls.add(s);
                        }
                    }
                }

                // Follow JS window.location / meta-refresh redirects — for apps that
                // navigate to a shell page via JS rather than <frame src>.
                // Example: root / → window.location="/webfw/html/nawstart.html"
                //          nawstart.html → <frame src="/html/gap/GA/GAZ911M0.html">
                //          GAZ911M0.html → <script src="ksbiz_config.js"> ← secrets here
                List<String> redirectUrls = new ArrayList<>(SecretScanner.extractJsRedirects(htmlBody, baseUrl));
                if (baseHost != null) {
                    final String fhR = baseHost;
                    redirectUrls.removeIf(u -> {
                        try { return !new java.net.URL(u).getHost().toLowerCase().equals(fhR); }
                        catch (Exception ignored) { return true; }
                    });
                }
                if (!redirectUrls.isEmpty()) {
                    debugLog("[Redirect] " + redirectUrls.size()
                            + " JS redirect(s) found in: " + baseUrl);
                }
                for (String redirectUrl : redirectUrls) {
                    if (!running.get()) break;
                    if (!fetched.add(redirectUrl)) continue;
                    api.logging().logToOutput("[Redirect] Following: " + redirectUrl);
                    FetchResult rr = fetchUrl(redirectUrl);
                    if (rr == null || rr.body() == null) continue;
                    scanAndAppend(rr.body(), "text/html", redirectUrl, rr.requestResponse());
                    // Scripts directly in the redirect target
                    for (String u : SecretScanner.extractScriptSrcs(rr.body(), redirectUrl)) {
                        if (!scriptUrls.contains(u)) scriptUrls.add(u);
                    }
                    for (String u : SecretScanner.extractPreloadLinks(rr.body(), redirectUrl)) {
                        if (!scriptUrls.contains(u)) scriptUrls.add(u);
                    }
                    // Frames inside the redirect target (e.g. nawstart.html → <frame src="GAZ911M0.html">)
                    for (String frameUrl : SecretScanner.extractFrameSrcs(rr.body(), redirectUrl)) {
                        try {
                            if (baseHost != null &&
                                !new java.net.URL(frameUrl).getHost().toLowerCase().equals(baseHost)) continue;
                        } catch (Exception ignored) { continue; }
                        if (!fetched.add(frameUrl)) continue;
                        debugLog("[Redirect→Frame] Fetching: " + frameUrl);
                        FetchResult fr2 = fetchUrl(frameUrl);
                        if (fr2 == null || fr2.body() == null) continue;
                        scanAndAppend(fr2.body(), "text/html", frameUrl, fr2.requestResponse());
                        for (String s : SecretScanner.extractScriptSrcs(fr2.body(), frameUrl)) {
                            if (!scriptUrls.contains(s)) scriptUrls.add(s);
                        }
                        for (String s : SecretScanner.extractPreloadLinks(fr2.body(), frameUrl)) {
                            if (!scriptUrls.contains(s)) scriptUrls.add(s);
                        }
                    }
                    // Nested JS redirects one level deeper
                    for (String u : SecretScanner.extractJsRedirects(rr.body(), redirectUrl)) {
                        try {
                            if (baseHost != null &&
                                !new java.net.URL(u).getHost().toLowerCase().equals(baseHost)) continue;
                        } catch (Exception ignored) { continue; }
                        if (!fetched.add(u)) continue;
                        debugLog("[Redirect→Redirect] Fetching: " + u);
                        FetchResult nrr = fetchUrl(u);
                        if (nrr == null || nrr.body() == null) continue;
                        scanAndAppend(nrr.body(), "text/html", u, nrr.requestResponse());
                        for (String s : SecretScanner.extractScriptSrcs(nrr.body(), u)) {
                            if (!scriptUrls.contains(s)) scriptUrls.add(s);
                        }
                        for (String s : SecretScanner.extractFrameSrcs(nrr.body(), u)) {
                            try {
                                if (baseHost != null &&
                                    !new java.net.URL(s).getHost().toLowerCase().equals(baseHost)) continue;
                            } catch (Exception ignored) { continue; }
                            if (!fetched.add(s)) continue;
                            FetchResult nfr2 = fetchUrl(s);
                            if (nfr2 == null || nfr2.body() == null) continue;
                            scanAndAppend(nfr2.body(), "text/html", s, nfr2.requestResponse());
                            for (String ss : SecretScanner.extractScriptSrcs(nfr2.body(), s)) {
                                if (!scriptUrls.contains(ss)) scriptUrls.add(ss);
                            }
                        }
                    }
                }

                totalExpected.addAndGet(scriptUrls.size());
                // Pre-add the 4 asset-manifest probes so the bar doesn't hit 100%
                // after the JS loop before manifests are even started.
                if (followChunksBox.isSelected()) totalExpected.addAndGet(4);
                updateProgress();
                debugLog("[JS] Discovered " + scriptUrls.size()
                        + " script URL(s) in: " + baseUrl
                        + (beforeFilter != scriptUrls.size()
                           ? "  (" + (beforeFilter - scriptUrls.size()) + " cross-host filtered)" : ""));

                // Diagnostic: if the HTML body is large but we found no scripts, log a
                // preview so you can see what the page actually returned.
                if (scriptUrls.isEmpty() && htmlBody != null && htmlBody.length() > 200) {
                    debugLog("[JS] No scripts found. HTML preview: "
                            + htmlBody.substring(0, Math.min(500, htmlBody.length()))
                                      .replace("\n", " ").replace("\r", ""));
                }

                for (String jsUrl : scriptUrls) {
                    if (!running.get()) return;
                    if (!fetched.add(jsUrl)) { totalDone.incrementAndGet(); updateProgress(); continue; }
                    // Skip URLs already scanned by inline CDP, HeadlessSiteMap, sweepSiteMapForHosts,
                    // or any prior fetch path — scanAndAppend would reject them anyway, but calling
                    // fetchUrl first wastes a network round-trip for every such file.
                    if (seenUrls.contains(jsUrl)) { totalDone.incrementAndGet(); updateProgress(); continue; }
                    debugLog("[JS] Fetching [" + totalDone.get() + "/" + totalExpected.get() + "]: " + jsUrl);
                    SwingUtilities.invokeLater(() -> currentFileLabel.setText("→ " + jsUrl));
                    FetchResult js = fetchUrl(jsUrl);
                    totalDone.incrementAndGet();
                    updateProgress();
                    if (js == null || js.body() == null) {
                        debugLog("[JS] FETCH FAILED (null body): " + jsUrl);
                        continue;
                    }
                    debugLog("[JS] Fetched " + js.body().length() + " bytes: " + jsUrl);
                    scanAndAppend(js.body(), "application/javascript", jsUrl, js.requestResponse());

                    // 4. Depth-1 webpack chunk following inside each JS file
                    if (followChunksBox.isSelected()) {
                        List<String> chunkUrls = SecretScanner.extractWebpackChunkUrls(js.body(), jsUrl);
                        totalExpected.addAndGet(chunkUrls.size());
                        updateProgress();
                        for (String chunkUrl : chunkUrls) {
                            if (!running.get()) return;
                            if (!fetched.add(chunkUrl)) { totalDone.incrementAndGet(); updateProgress(); continue; }
                            if (seenUrls.contains(chunkUrl)) { totalDone.incrementAndGet(); updateProgress(); continue; }
                            debugLog("[JS] Fetching chunk [" + totalDone.get() + "/" + totalExpected.get() + "]: " + chunkUrl);
                            SwingUtilities.invokeLater(() -> currentFileLabel.setText("→ " + chunkUrl));
                            FetchResult chunk = fetchUrl(chunkUrl);
                            totalDone.incrementAndGet();
                            updateProgress();
                            if (chunk == null || chunk.body() == null) continue;
                            scanAndAppend(chunk.body(), "application/javascript",
                                          chunkUrl, chunk.requestResponse());
                        }
                    }
                }

                // 5. Asset manifest following: fetch /asset-manifest.json and similar
                //    to discover additional JS chunks not linked in HTML
                if (followChunksBox.isSelected()) {
                    followAssetManifests(baseUrl, fetched);
                }
            }
        }
    }

    /**
     * Tries to fetch well-known webpack/Vite/CRA asset manifest files and scans
     * any JS chunk URLs discovered in them. Safe — 404s are silently ignored.
     */
    private void followAssetManifests(String baseUrl, Set<String> fetched) {
        String origin;
        try {
            java.net.URL u = new java.net.URL(baseUrl);
            origin = u.getProtocol() + "://" + u.getHost() +
                     (u.getPort() > 0 && u.getPort() != 80 && u.getPort() != 443
                             ? ":" + u.getPort() : "");
        } catch (Exception e) { return; }

        String[] manifestPaths = {
            "/asset-manifest.json", "/static/js/manifest.json",
            "/chunk-manifest.json", "/webpack-manifest.json"
        };

        // totalExpected already pre-incremented by 4 in processUrl() before the JS loop.
        for (String path : manifestPaths) {
            if (!running.get()) return;
            String manifestUrl = origin + path;
            if (!fetched.add(manifestUrl)) { totalDone.incrementAndGet(); updateProgress(); continue; }
            debugLog("[JS] Fetching manifest: " + manifestUrl);
            SwingUtilities.invokeLater(() -> currentFileLabel.setText("→ " + manifestUrl));
            FetchResult mf = fetchUrl(manifestUrl);
            totalDone.incrementAndGet();
            updateProgress();
            if (mf == null || mf.body() == null) continue;

            List<String> chunkUrls = SecretScanner.extractAssetManifestUrls(mf.body(), baseUrl);
            totalExpected.addAndGet(chunkUrls.size());
            updateProgress();
            debugLog("[JS] Manifest at " + manifestUrl
                    + " yielded " + chunkUrls.size() + " chunk(s).");
            for (String chunkUrl : chunkUrls) {
                if (!running.get()) return;
                if (!fetched.add(chunkUrl)) { totalDone.incrementAndGet(); updateProgress(); continue; }
                debugLog("[JS] Fetching manifest chunk [" + totalDone.get() + "/" + totalExpected.get() + "]: " + chunkUrl);
                SwingUtilities.invokeLater(() -> currentFileLabel.setText("→ " + chunkUrl));
                FetchResult chunk = fetchUrl(chunkUrl);
                totalDone.incrementAndGet();
                updateProgress();
                if (chunk == null || chunk.body() == null) continue;
                scanAndAppend(chunk.body(), "application/javascript", chunkUrl, chunk.requestResponse());
            }
        }
    }

    // =========================================================================
    // Headless browse — routes Chrome through Burp proxy to capture dynamic APIs
    // =========================================================================

    /**
     * Launches Chrome/Chromium in headless mode with Burp as the proxy for the
     * given URL, then waits up to 45 seconds for the page to load and JS to run.
     *
     * All traffic (XHR, Fetch, WebSockets HTTP-upgrade) flows through Burp proxy →
     * SecretProxyHandler picks it up → ScopeMonitor dispatches findings to the
     * Bulk Scan panel automatically.
     *
     * Returns null — URL discovery is done via post-headless site map sweep.
     */
    private String headlessVisit(String url, int proxyPort) {
        String chromePath = findChrome();
        if (chromePath == null) {
            api.logging().logToOutput(
                    "[Headless] Chrome/Chromium not found — skipping headless browse for: " + url +
                    "\n  Install Google Chrome or Chromium and ensure it is on PATH.");
            return null;
        }

        // Pre-flight: verify the proxy port is reachable before launching Chrome.
        // A wrong proxy port is the most common reason traffic never appears in Burp on Windows.
        try (java.net.Socket testSock = new java.net.Socket()) {
            testSock.connect(new java.net.InetSocketAddress("127.0.0.1", proxyPort), 1500);
            debugLog("[Headless] Proxy reachable at 127.0.0.1:" + proxyPort);
        } catch (Exception proxyEx) {
            api.logging().logToOutput(
                    "[Headless] WARNING: Cannot reach Burp proxy at 127.0.0.1:" + proxyPort +
                    " — Chrome traffic will not appear in Burp proxy history." +
                    " Check that the proxy port spinner matches Burp's listener port." +
                    " Skipping headless for: " + url);
            return null;
        }

        // Throttle: at most 3 Chrome instances run simultaneously across all scan threads.
        try { headlessSemaphore.acquire(); } catch (InterruptedException ie) {
            Thread.currentThread().interrupt(); return null;
        }
        try {
            // Use a unique temp dir so Chrome never conflicts with an already-running instance
            // (on Windows the default profile is locked while Chrome is open, causing launch failure).
            // Delete any leftover dir from a prior scan so Chrome starts with a clean cache —
            // a stale disk cache causes Chrome to make 0 network requests (serving everything
            // from cache), so proxy history gets no new entries and secrets are missed.
            File tmpDir = new File(System.getProperty("java.io.tmpdir"),
                    "secretsifter-chrome-" + Thread.currentThread().getId());
            try { deleteDirectory(tmpDir); } catch (Exception ignored) {}
            ProcessBuilder pb = new ProcessBuilder(
                    chromePath,
                    "--headless=new",
                    "--disable-gpu",
                    "--no-sandbox",
                    "--remote-debugging-port=0",
                    // Route all Chrome traffic through Burp proxy so SecretProxyHandler captures
                    // every response body (including cross-origin POST token endpoints like
                    // uat.studiogateway.chubb.com/enterprise.operations.authorization).
                    // Without this, POST response bodies never go through Burp and CDP
                    // getResponseBody evicts the buffer before we can fetch it.
                    "--proxy-server=http://127.0.0.1:" + proxyPort,
                    // Bypass well-known browser-internal and CDN/tracking domains so they
                    // don't appear in Burp's proxy history.  Chrome fires background requests
                    // (update checks, translate, sign-in, metrics) that would otherwise flood
                    // the site map.  Application traffic is unaffected.
                    "--proxy-bypass-list="
                        + "*.google.com;*.googleapis.com;*.gstatic.com;"
                        + "*.doubleclick.net;*.googletagmanager.com;*.google-analytics.com;"
                        + "*.facebook.net;*.facebook.com;*.twitter.com;*.ads-twitter.com;"
                        + "*.linkedin.com;*.licdn.com;*.hotjar.com;*.sentry.io;"
                        + "*.akamaiedge.net;*.cloudflareinsights.com;*.launchdarkly.com;"
                        + "*.fullstory.com;*.segment.com;*.segment.io;*.klaviyo.com;"
                        + "*.bing.com;*.online-metrix.net;*.visualstudio.com;"
                        + "*.jsdelivr.net;*.unpkg.com;*.cookielaw.org",
                    "--ignore-certificate-errors",           // trust Burp's self-signed cert
                    "--allow-insecure-localhost",
                    "--disable-extensions",
                    "--no-first-run",
                    "--disable-sync",
                    "--mute-audio",
                    "--user-data-dir=" + tmpDir.getAbsolutePath()
            );
            pb.redirectErrorStream(true);
            Process p = pb.start();
            try {

            // Capture Chrome output; signal the DevTools WS URL as soon as it appears.
            StringBuilder chromeOut = new StringBuilder();
            java.util.concurrent.BlockingQueue<String> devtoolsSignal =
                    new java.util.concurrent.LinkedBlockingQueue<>();
            Thread drainer = new Thread(() -> {
                try (java.io.BufferedReader br = new java.io.BufferedReader(
                        new java.io.InputStreamReader(p.getInputStream()))) {
                    String line;
                    int n = 0;
                    while ((line = br.readLine()) != null) {
                        // Signal the main thread with the CDP WebSocket URL the moment we see it
                        if (line.contains("DevTools listening on ws://")) {
                            int idx = line.indexOf("ws://");
                            if (idx >= 0) devtoolsSignal.offer(line.substring(idx).trim());
                        }
                        if (++n <= 80) chromeOut.append(line).append('\n');
                    }
                } catch (Exception ignored) {}
                devtoolsSignal.offer(""); // EOF sentinel so poll() doesn't hang forever
            }, "headless-stdout-drainer");
            drainer.setDaemon(true);
            drainer.start();

            // Wait up to 10 s for Chrome to expose its DevTools port, then navigate via CDP.
            String devtoolsWsUrl = devtoolsSignal.poll(10, TimeUnit.SECONDS);
            if (devtoolsWsUrl != null && !devtoolsWsUrl.isEmpty()) {
                cdpNavigateWithProxy(devtoolsWsUrl, url, proxyPort);
            } else {
                api.logging().logToOutput(
                        "[Headless] CDP: DevTools URL not available within 10 s — " +
                        "Chrome may not have started correctly for: " + url);
            }

            // Chrome will be killed here; give it a short grace period then force-destroy.
            boolean done = p.waitFor(5, TimeUnit.SECONDS);
            if (!done) p.destroyForcibly();
            drainer.join(2000);

            String outSnippet = chromeOut.toString().trim();
            if (!outSnippet.isEmpty()) {
                debugLog("[Headless] Chrome log for " + url + ":\n" + outSnippet);
            }
            debugLog("[Headless] Visited (ok): " + url);
            return null;
            } finally {
                if (p.isAlive()) p.destroyForcibly();  // safety net if exception skipped waitFor
            }
        } catch (Exception e) {
            debugLog("[Headless] Failed for " + url + ": " + e.toString());
            return null;
        } finally {
            headlessSemaphore.release();
        }
    }

    /**
     * Uses Chrome's CDP to observe every network request the page makes, then replays
     * those URLs through a Java HttpClient whose proxy is set to Burp
     * ({@code 127.0.0.1:proxyPort}).  This is the only reliable approach on enterprise
     * Windows where GPO blocks both {@code --proxy-server} CLI override and
     * {@code Browser.createBrowserContext} CDP proxy settings.
     *
     * Flow:
     *   1. Open an about:blank tab via Target.createTarget
     *   2. Connect to the tab's CDP WebSocket and enable Network.enable
     *   3. Navigate to pageUrl via Page.navigate (all network events are captured)
     *   4. Collect every URL from Network.requestWillBeSent for 25 s
     *   5. Replay each URL through a Burp-proxied Java HttpClient so the traffic
     *      appears in Burp's proxy history and sitemap
     */
    private void cdpNavigateWithProxy(String browserWsUrl, String pageUrl, int proxyPort) {
        try {
            // Extract CDP HTTP port from "ws://127.0.0.1:PORT/devtools/browser/UUID"
            java.util.regex.Matcher pm =
                    java.util.regex.Pattern.compile("ws://127\\.0\\.0\\.1:(\\d+)/").matcher(browserWsUrl);
            if (!pm.find()) {
                api.logging().logToOutput("[Headless] CDP: cannot parse port from " + browserWsUrl);
                return;
            }
            int cdpPort = Integer.parseInt(pm.group(1));

            java.net.http.HttpClient hc = java.net.http.HttpClient.newHttpClient();

            // ── Step 1: Open an about:blank tab so we can enable Network monitoring
            //           BEFORE the page starts loading (avoids missing early requests).
            java.util.concurrent.BlockingQueue<String> browserInbox =
                    new java.util.concurrent.LinkedBlockingQueue<>();
            java.net.http.WebSocket browserWs = hc.newWebSocketBuilder()
                    .buildAsync(java.net.URI.create(browserWsUrl), makeCdpListener(browserInbox))
                    .get(5, TimeUnit.SECONDS);
            try {
            browserWs.request(1);

            browserWs.sendText(
                    "{\"id\":1,\"method\":\"Target.createTarget\"," +
                    "\"params\":{\"url\":\"about:blank\"}}",
                    true).get(5, TimeUnit.SECONDS);

            String createResp = browserInbox.poll(10, TimeUnit.SECONDS);
            String targetId = null;
            if (createResp != null) {
                try {
                    JsonObject j = gParseObject(createResp);
                    if (j != null && j.has("result")) targetId = gOptString(gOptObject(j, "result"), "targetId", null);
                } catch (Exception ignored) {}
            }
            if (targetId == null) {
                api.logging().logToOutput("[Headless] CDP: Target.createTarget failed: " + createResp);
                return;  // browserWs closed in finally
            }

            // ── Step 2: Get the tab's WebSocket URL from /json/list
            String tabWsUrl = null;
            try {
                java.net.http.HttpResponse<String> listResp = hc.send(
                        java.net.http.HttpRequest.newBuilder()
                                .uri(java.net.URI.create("http://127.0.0.1:" + cdpPort + "/json/list"))
                                .build(),
                        java.net.http.HttpResponse.BodyHandlers.ofString());
                JsonArray tabs = gParseArray(listResp.body());
                if (tabs != null) for (int i = 0; i < tabs.size(); i++) {
                    JsonObject tab = tabs.get(i).isJsonObject() ? tabs.get(i).getAsJsonObject() : null;
                    if (tab != null && targetId.equals(gOptString(tab, "id"))) {
                        tabWsUrl = gOptString(tab, "webSocketDebuggerUrl", null);
                        break;
                    }
                }
            } catch (Exception ignored) {}
            if (tabWsUrl == null) {
                api.logging().logToOutput("[Headless] CDP: no WS URL for targetId=" + targetId);
                return;  // browserWs closed in finally
            }

            // ── Step 3: Connect to the tab, enable Network monitoring, then navigate
            java.util.concurrent.BlockingQueue<String> tabInbox =
                    new java.util.concurrent.LinkedBlockingQueue<>();
            java.net.http.WebSocket tabWs = hc.newWebSocketBuilder()
                    .buildAsync(java.net.URI.create(tabWsUrl), makeCdpListener(tabInbox))
                    .get(5, TimeUnit.SECONDS);
            try {
            tabWs.request(1);

            tabWs.sendText("{\"id\":2,\"method\":\"Network.enable\",\"params\":{}}",
                    true).get(5, TimeUnit.SECONDS);
            tabInbox.poll(3, TimeUnit.SECONDS); // drain the Network.enable ack

            // Block asset types at Chrome level — images, fonts, CSS, and media never
            // contain secrets. Blocking them reduces Chrome's download overhead and
            // speeds up scanning across 100 concurrent domains.
            tabWs.sendText("{\"id\":10,\"method\":\"Network.setBlockedURLs\"," +
                    "\"params\":{\"urls\":[" +
                    "\"*.jpg\",\"*.jpeg\",\"*.png\",\"*.gif\",\"*.ico\",\"*.bmp\"," +
                    "\"*.woff\",\"*.woff2\",\"*.ttf\",\"*.eot\",\"*.otf\"," +
                    "\"*.css\",\"*.mp4\",\"*.webm\",\"*.mp3\",\"*.wav\",\"*.ogg\"]}}",
                    true).get(3, TimeUnit.SECONDS);
            tabInbox.poll(2, TimeUnit.SECONDS); // drain the setBlockedURLs ack

            String escapedUrl = pageUrl.replace("\\", "\\\\").replace("\"", "\\\"");
            tabWs.sendText(
                    "{\"id\":3,\"method\":\"Page.navigate\"," +
                    "\"params\":{\"url\":\"" + escapedUrl + "\"}}",
                    true).get(5, TimeUnit.SECONDS);
            tabInbox.poll(3, TimeUnit.SECONDS); // drain the Page.navigate ack

            // ── Step 4: Collect every URL Chrome fetches for the next 25 s.
            //           Also capture request headers (for API-key scanning) and
            //           response MIME types (for targeted CDP body extraction).
            java.util.Set<String> discovered = new java.util.LinkedHashSet<>();
            // reqId → url  (first requestWillBeSent per request ID)
            java.util.Map<String, String> cdpReqUrls = new java.util.LinkedHashMap<>();
            // reqId → {headerName → headerValue}
            java.util.Map<String, java.util.Map<String, String>> cdpReqHdrs = new java.util.LinkedHashMap<>();
            // reqId → mimeType string from responseReceived
            java.util.Map<String, String> cdpRespTypes = new java.util.LinkedHashMap<>();

            // Inline body capture: maps CDP command ID → reqId for getResponseBody calls
            // sent during the collection window. Results stored in inlineBodies (reqId → text).
            // IDs start at 1000 to avoid collisions with Step 1-3 IDs (1, 2, 3, 10).
            java.util.Map<Integer, String> pendingBodyFetches = new java.util.LinkedHashMap<>();
            java.util.Map<String, String>  inlineBodies       = new java.util.LinkedHashMap<>();
            final int[] inlineBodyIdCounter = {1000};

            long deadline = System.currentTimeMillis() + 25_000;
            while (System.currentTimeMillis() < deadline) {
                String msg = tabInbox.poll(200, TimeUnit.MILLISECONDS);
                if (msg == null) continue;
                try {
                    JsonObject j = gParseObject(msg);
                    if (j == null) continue;

                    // ── Handle CDP command responses first (getResponseBody results).
                    // These carry an "id" field and "result"/"error" — no "method"/"params".
                    // Must be handled BEFORE the params==null guard which would drop them.
                    int cmdId = gOptInt(j, "id", -1);
                    if (cmdId >= 1000 && pendingBodyFetches.containsKey(cmdId)) {
                        String pendingReqId = pendingBodyFetches.remove(cmdId);
                        JsonObject res = gOptObject(j, "result");
                        if (res != null) {
                            String body = gOptString(res, "body", "");
                            boolean b64 = gOptBoolean(res, "base64Encoded", false);
                            if (body != null && !body.isBlank()) {
                                if (b64) {
                                    try { body = new String(java.util.Base64.getDecoder().decode(body),
                                              java.nio.charset.StandardCharsets.UTF_8); }
                                    catch (Exception ignored) { body = ""; }
                                }
                                if (!body.isBlank()) inlineBodies.put(pendingReqId, body);
                            }
                        } else if (debugModeBox.isSelected()) {
                            // Chrome returned {"error":{...}} — body not in CDP buffer.
                            // This can happen for XHR/fetch responses under memory pressure.
                            // Step 4.5b will attempt another getResponseBody call as fallback.
                            JsonObject err = gOptObject(j, "error");
                            api.logging().logToOutput("[Headless] CDP inline getResponseBody failed for "
                                    + nvl(cdpReqUrls.get(pendingReqId), pendingReqId) + ": "
                                    + (err != null ? gOptString(err, "message", "no message") : "no result"));
                        }
                        continue;
                    }

                    String evtMethod = gOptString(j, "method");
                    JsonObject params = gOptObject(j, "params");
                    if (params == null) continue;

                    if ("Network.requestWillBeSent".equals(evtMethod)) {
                        String reqId = gOptString(params, "requestId");
                        JsonObject req = gOptObject(params, "request");
                        if (req == null) continue;
                        String u = gOptString(req, "url", "");
                        if (!u.startsWith("http://") && !u.startsWith("https://")) continue;
                        // Filter by resource type — image/stylesheet/font/media never
                        // contain secrets and would only slow down the scan.
                        String resourceType = gOptString(params, "type", "");
                        if ("Image".equals(resourceType) || "Stylesheet".equals(resourceType)
                                || "Font".equals(resourceType) || "Media".equals(resourceType)) continue;
                        // Block CDN / analytics / SSO domains listed in the CDN blocklist.
                        // All other cross-origin URLs — including backend API gateways like
                        // uat.studiogateway.chubb.com called from modelent.chubbworldview.com —
                        // are captured because they carry secrets in request headers and
                        // JSON response bodies.
                        if (settings.isExternalCdn(u)) continue;
                        discovered.add(u);
                        if (cdpReqUrls.putIfAbsent(reqId, u) == null) {
                            // First time we see this reqId — capture request headers
                            JsonObject hdrs = gOptObject(req, "headers");
                            if (hdrs != null) {
                                java.util.Map<String, String> hMap = new java.util.LinkedHashMap<>();
                                for (Map.Entry<String, JsonElement> hk : hdrs.entrySet())
                                    hMap.put(hk.getKey(), gOptString(hdrs, hk.getKey()));
                                if (!hMap.isEmpty()) cdpReqHdrs.put(reqId, hMap);
                            }
                        }
                        if (debugModeBox.isSelected())
                            api.logging().logToOutput("[Headless] CDP observed: " + u);

                    } else if ("Network.responseReceived".equals(evtMethod)) {
                        String reqId = gOptString(params, "requestId");
                        if (!cdpReqUrls.containsKey(reqId)) continue;
                        JsonObject resp = gOptObject(params, "response");
                        if (resp == null) continue;
                        String mime = gOptString(resp, "mimeType", "");
                        if (mime.isEmpty()) {
                            JsonObject rh = gOptObject(resp, "headers");
                            if (rh != null) {
                                mime = gOptString(rh, "content-type", "");
                                if (mime.isEmpty()) mime = gOptString(rh, "Content-Type", "");
                            }
                        }
                        // Use put() not putIfAbsent() so the LAST responseReceived wins.
                        // For redirected requests Chrome fires responseReceived twice (once for the
                        // 3xx redirect response, once for the final 200). putIfAbsent would keep
                        // the redirect's empty/"text/html" MIME and cause wantBody=false in
                        // loadingFinished, silently skipping the response body entirely.
                        cdpRespTypes.put(reqId, mime);

                    } else if ("Network.loadingFinished".equals(evtMethod)) {
                        // Response body is guaranteed to be in Chrome's CDP buffer at this
                        // instant. Fetch it immediately for JSON/JS responses so we capture
                        // the body before Chrome can evict it from its internal buffer
                        // (eviction is most likely for XHR/fetch responses that JS consumed
                        // and for large pages that create memory pressure).
                        String reqId = gOptString(params, "requestId");
                        if (!cdpReqUrls.containsKey(reqId) || inlineBodies.containsKey(reqId)) continue;
                        String reqUrl = cdpReqUrls.get(reqId);
                        String mime   = cdpRespTypes.get(reqId);
                        if (reqUrl == null || mime == null || seenUrls.contains(reqUrl)) continue;
                        String mimeLc = mime.toLowerCase();
                        String uLc    = reqUrl.toLowerCase().replaceAll("[?#].*$", "");
                        boolean wantBody = mimeLc.contains("application/json") || mimeLc.contains("+json")
                                || uLc.endsWith(".json") || mimeLc.contains("javascript")
                                || mimeLc.contains("ecmascript") || uLc.endsWith(".js") || uLc.endsWith(".mjs");
                        if (!wantBody) continue;
                        int bid = inlineBodyIdCounter[0]++;
                        tabWs.sendText("{\"id\":" + bid + ",\"method\":\"Network.getResponseBody\"," +
                                "\"params\":{\"requestId\":\"" +
                                reqId.replace("\\", "\\\\").replace("\"", "\\\"") + "\"}}",
                                true).get(3, TimeUnit.SECONDS);
                        pendingBodyFetches.put(bid, reqId);
                        debugLog("[Headless] CDP: inline body fetch queued for: " + reqUrl);
                    }
                } catch (Exception ignored) {}
            }

            // Scan response bodies captured inline during the event loop.
            // These were fetched immediately on loadingFinished — Chrome's buffer is intact.
            for (java.util.Map.Entry<String, String> ib : inlineBodies.entrySet()) {
                String ibReqId  = ib.getKey();
                String ibReqUrl = cdpReqUrls.get(ibReqId);
                String ibMime   = cdpRespTypes.get(ibReqId);
                if (ibReqUrl != null && ibMime != null)
                    scanAndAppend(ib.getValue(), ibMime, ibReqUrl, null);
            }

            debugLog("[Headless] CDP: Chrome observed " + discovered.size() + " request(s) for: " + pageUrl);

            // ── Step 4.5: Scan CDP-observed request headers and response bodies
            //             directly from Chrome's network events.
            //
            //             The replay in Step 5 sends unauthenticated GET requests, so
            //             API endpoints that require auth headers (e.g. x-api-key,
            //             Ocp-Apim-Subscription-Key) return 401 and are filtered out.
            //             Here we use the real headers Chrome sent and the real response
            //             bodies Chrome received — no proxy round-trip needed.
            //
            //             4.5a: Request header scanning (API keys the JS set at runtime)
            //             4.5b: Response body scanning via Network.getResponseBody CDP call

            // 4.5a — Request headers
            for (java.util.Map.Entry<String, java.util.Map<String, String>> he : cdpReqHdrs.entrySet()) {
                String reqUrl = cdpReqUrls.get(he.getKey());
                if (reqUrl == null || settings.isExternalCdn(reqUrl)) continue;
                java.util.Map<String, String> hMap = he.getValue();
                // Only scan when at least one header name suggests an API credential
                boolean hasSecHdr = hMap.keySet().stream().anyMatch(k -> {
                    String kl = k.toLowerCase();
                    return kl.contains("key")    || kl.contains("auth")   || kl.contains("token")
                        || kl.contains("secret") || kl.contains("api")    || kl.contains("bearer")
                        || kl.contains("subscription") || kl.contains("credential");
                });
                if (!hasSecHdr) continue;
                StringBuilder hdrTxt = new StringBuilder();
                for (java.util.Map.Entry<String, String> h : hMap.entrySet())
                    hdrTxt.append(h.getKey()).append(": ").append(h.getValue()).append("\n");
                scanAndAppend(hdrTxt.toString(), "text/plain", reqUrl + " [REQ-HEADERS]", null);
            }

            // 4.5b — Response bodies (JSON and JS only; HTML is handled by the main fetch path)
            int cdpBodyId = 500; // start above the IDs used in Steps 1–3 (1,2,3)
            for (java.util.Map.Entry<String, String> re : cdpRespTypes.entrySet()) {
                if (!running.get()) break;
                String reqId = re.getKey();
                String reqUrl = cdpReqUrls.get(reqId);
                if (reqUrl == null || settings.isExternalCdn(reqUrl)) continue;
                String ct    = re.getValue();
                String ctLc  = ct == null ? "" : ct.toLowerCase();
                String uLc   = reqUrl.toLowerCase().replaceAll("[?#].*$", "");
                boolean isJson = ctLc.contains("application/json") || ctLc.contains("+json")
                                 || uLc.endsWith(".json");
                boolean isJs   = ctLc.contains("javascript") || ctLc.contains("ecmascript")
                                 || uLc.endsWith(".js") || uLc.endsWith(".mjs");
                if (!isJson && !isJs) continue;
                // Skip URLs already scanned by the static-fetch or sitemap path
                if (seenUrls.contains(reqUrl)) continue;
                try {
                    final int myId = cdpBodyId++;
                    tabWs.sendText(
                            "{\"id\":" + myId + ",\"method\":\"Network.getResponseBody\"," +
                            "\"params\":{\"requestId\":\"" +
                            reqId.replace("\\", "\\\\").replace("\"", "\\\"") + "\"}}",
                            true).get(3, TimeUnit.SECONDS);
                    // Poll until we get the response matching myId; skip unrelated CDP events.
                    // Use continue (not break) on empty poll — Chrome may take a moment to
                    // respond even though the body should be cached; rely on bodyDeadline.
                    String bodyResp = null;
                    long bodyDeadline = System.currentTimeMillis() + 5_000;
                    while (System.currentTimeMillis() < bodyDeadline) {
                        String bMsg = tabInbox.poll(300, TimeUnit.MILLISECONDS);
                        if (bMsg == null) continue;
                        try {
                            JsonObject bj = gParseObject(bMsg);
                            if (bj != null && gOptInt(bj, "id", -1) == myId) { bodyResp = bMsg; break; }
                        } catch (Exception ignored) {}
                    }
                    if (bodyResp != null) {
                        JsonObject br  = gParseObject(bodyResp);
                        JsonObject res = br != null ? gOptObject(br, "result") : null;
                        if (res != null) {
                            String body = gOptString(res, "body", "");
                            boolean b64 = gOptBoolean(res, "base64Encoded", false);
                            if (body != null && !body.isBlank()) {
                                if (b64) {
                                    try { body = new String(java.util.Base64.getDecoder().decode(body),
                                              java.nio.charset.StandardCharsets.UTF_8); }
                                    catch (Exception ignored) { body = ""; }
                                }
                                if (!body.isBlank()) scanAndAppend(body, ct, reqUrl, null);
                            }
                        }
                    }
                } catch (Exception ex) {
                    if (debugModeBox.isSelected())
                        api.logging().logToOutput(
                                "[Headless] CDP getResponseBody error for " + reqUrl
                                + ": " + ex.getMessage());
                }
            }

            // Step 5 (URL replay via Java HttpClient) removed: with --proxy-server active,
            // Chrome already routes all traffic through Burp during the CDP window above.
            // Replaying URLs again would cause SecretProxyHandler to fire twice per URL,
            // doubling scan work and significantly increasing scan time.

            } finally {
                closeCdpWs(tabWs);
            }
            } finally {
                closeCdpWs(browserWs);  // always close browserWs, including on early returns
            }

        } catch (Exception e) {
            debugLog("[Headless] CDP error for " + pageUrl + ": " + e.toString());
        }
    }

    /** Creates a CDP WebSocket listener that feeds each complete message into {@code inbox}. */
    private static java.net.http.WebSocket.Listener makeCdpListener(
            java.util.concurrent.BlockingQueue<String> inbox) {
        return new java.net.http.WebSocket.Listener() {
            private final StringBuilder buf = new StringBuilder();
            @Override
            public java.util.concurrent.CompletionStage<?> onText(
                    java.net.http.WebSocket ws, CharSequence data, boolean last) {
                buf.append(data);
                if (last) { inbox.offer(buf.toString()); buf.setLength(0); }
                ws.request(1);
                return null;
            }
        };
    }

    /** Recursively deletes a directory and all its contents. */
    private static void deleteDirectory(File dir) {
        if (dir == null || !dir.exists()) return;
        File[] files = dir.listFiles();
        if (files != null) for (File f : files) {
            if (f.isDirectory()) deleteDirectory(f);
            else f.delete();
        }
        dir.delete();
    }

    private static void closeCdpWs(java.net.http.WebSocket ws) {
        if (ws == null) return;
        try { ws.sendClose(java.net.http.WebSocket.NORMAL_CLOSURE, "").get(2, TimeUnit.SECONDS); }
        catch (Exception ignored) { ws.abort(); }
    }

    /** Returns the path to a Chrome, Chromium, or Edge executable, or null if none found. */
    private static String findChrome() {
        String os = System.getProperty("os.name", "").toLowerCase();
        String[] candidates;
        if (os.contains("mac")) {
            candidates = new String[]{
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
                "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"
            };
        } else if (os.contains("win")) {
            // Null-safe env-var helpers — PROGRAMFILES(X86) is absent on 32-bit-only Windows
            String pf   = nvl(System.getenv("PROGRAMFILES"),     "C:\\Program Files");
            String pf86 = nvl(System.getenv("PROGRAMFILES(X86)"),"C:\\Program Files (x86)");
            String lad  = nvl(System.getenv("LOCALAPPDATA"),     "");
            candidates = new String[]{
                pf   + "\\Google\\Chrome\\Application\\chrome.exe",
                pf86 + "\\Google\\Chrome\\Application\\chrome.exe",
                lad  + "\\Google\\Chrome\\Application\\chrome.exe",
                pf   + "\\Microsoft\\Edge\\Application\\msedge.exe",
                pf86 + "\\Microsoft\\Edge\\Application\\msedge.exe",
                lad  + "\\Microsoft\\Edge\\Application\\msedge.exe"
            };
        } else {
            // Linux — check PATH
            candidates = new String[]{ "google-chrome", "google-chrome-stable", "chromium", "chromium-browser" };
        }
        boolean isWindows = os.contains("win");
        for (String c : candidates) {
            if (c == null || c.isBlank()) continue;
            File f = new File(c);
            if (f.exists() && f.canExecute()) return c;
            // For short names (Linux/Windows PATH lookup)
            if (!c.contains(File.separator)) {
                Process p = null;
                try {
                    String lookupCmd = isWindows ? "where" : "which";
                    p = new ProcessBuilder(lookupCmd, c).start();
                    if (p.waitFor(2, TimeUnit.SECONDS) && p.exitValue() == 0) return c;
                } catch (Exception ignored) {
                } finally {
                    if (p != null) {
                        try { p.getInputStream().close(); } catch (Exception ignored2) {}
                        try { p.getErrorStream().close(); } catch (Exception ignored2) {}
                        p.destroy();
                    }
                }
            }
        }
        return null;
    }

    /** Returns {@code value} if non-null, otherwise {@code fallback}. */
    private static String nvl(String value, String fallback) {
        return value != null ? value : fallback;
    }

    /** Returns the registrable domain (last two DNS labels) of a host, or the host for IPs. */
    private static String registrableDomain(String host) {
        if (host == null || host.isEmpty()) return "";
        if (host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) return host;  // IPv4 — use as-is
        String[] p = host.split("\\.");
        return p.length >= 2 ? p[p.length - 2] + "." + p[p.length - 1] : host;
    }

    /** True when {@code candidateUrl} shares the same registrable domain as {@code targetUrl}. */
    private static boolean isSameDomain(String targetUrl, String candidateUrl) {
        try {
            String th = new java.net.URL(targetUrl).getHost().toLowerCase();
            String ch = new java.net.URL(candidateUrl).getHost().toLowerCase();
            return registrableDomain(th).equals(registrableDomain(ch));
        } catch (Exception e) { return false; }
    }

    /** True when the URL's host is a raw IPv4 address (no hostname validation possible). */
    private static boolean isIpUrl(String url) {
        try { return new java.net.URL(url).getHost().matches("\\d+\\.\\d+\\.\\d+\\.\\d+"); }
        catch (Exception e) { return false; }
    }

    /** Overload used when no HttpRequestResponse is available (ScopeMonitor listener). */
    private void scanAndAppend(String body, String contentType, String url) {
        scanAndAppend(body, contentType, url, null);
    }

    /**
     * Scans {@code body} for secrets and appends each finding to the results table.
     * If {@code rr} is non-null, also pushes findings to Burp's Dashboard as AuditIssues
     * so they appear in Issue Activity alongside passive scanner findings.
     * <p>
     * Uses URL-based dedup: the same URL is never scanned twice in one session.
     * This eliminates the 32-bit hashCode collision risk that caused silent finding
     * loss when ~500+ bodies were processed in a concurrent multi-target scan.
     * The URL is also tagged with its content type ([HTML] / [JS] / [JSON] / [XML])
     * so the findings table clearly indicates the source of each finding.
     */
    private void scanAndAppend(String body, String contentType, String url,
                                HttpRequestResponse rr) {
        if (body == null || body.isBlank()) return;
        // URL-based dedup: same URL = same resource, no need to scan twice.
        if (!seenUrls.add(url != null ? url : "")) return;
        // Tag the URL with its content type for clear source identification.
        String labelledUrl = sourceLabel(url, contentType);
        List<SecretFinding> findings = scanner.scanText(body, contentType, labelledUrl);
        api.logging().logToOutput("[BulkScan] " + findings.size() + " finding(s) in: " + labelledUrl);
        debugLog("[BulkScan] body=" + body.length() + " chars: " + labelledUrl);
        // Push to Burp Dashboard / site map: one AuditIssue per (URL, rule) group.
        // rr may be null when called from the active-fetch path (fetchUrl returns no
        // HttpRequestResponse); toGroupedAuditIssue handles null safely — markers are
        // skipped but the AuditIssue URL and detail are still correct.
        if (!findings.isEmpty()) {
            Map<String, java.util.List<SecretFinding>> grouped = new LinkedHashMap<>();
            for (SecretFinding f : findings)
                grouped.computeIfAbsent(f.ruleName(), k -> new ArrayList<>()).add(f);
            for (java.util.List<SecretFinding> group : grouped.values()) {
                if (!SitemapDeduplicator.shouldAdd(group)) continue;
                try { api.siteMap().add(SecretFinding.toGroupedAuditIssue(group, rr)); }
                catch (Exception e) { debugLog("siteMap.add failed for " + url + ": " + e.toString()); }
            }
        }
        for (SecretFinding f : findings) {
            SwingUtilities.invokeLater(() -> appendFinding(f));
        }
    }

    private void appendFinding(SecretFinding f) {
        // Deduplicate: same rule + value seen via both headless-proxy path and active-fetch path.
        // Strip content-type label suffixes ([JSON], [JS], [HTML], [XML], [REQ-HEADERS]) from
        // sourceUrl before hashing so that the two scan paths (sweepSiteMapForHosts produces
        // "url [JSON]"; SecretProxyHandler produces "url") collapse to the same key.
        String dedupUrl = f.sourceUrl() != null
                ? f.sourceUrl().replaceAll(" \\[(JSON|JS|HTML|XML|REQ-HEADERS|REQ-BODY)\\]$", "")
                : "";
        // Deduplicate on (url, value) only — the same secret caught by multiple rules
        // (e.g. JWT_TOKEN_001 + GENERIC_KV + JSON_WALK all matching the same token)
        // should appear once in the table.  ruleId is intentionally excluded.
        if (!seenFindings.add(dedupUrl + ":" + f.matchedValue())) return;
        tableFindings.add(f);
        int row = tableModel.getRowCount() + 1;
        tableModel.addRow(new Object[]{
                row,
                f.severity(),
                f.confidence(),
                f.ruleId(),
                f.keyName(),
                f.matchedValue(),
                f.sourceUrl(),
                f.lineNumber(),
                f.context() != null ? f.context().replace("\n", " ").strip() : "",
                ""   // delete button column
        });
        // Auto-scroll to latest finding (convert model index → view index for the sorter)
        int lastModelRow = tableModel.getRowCount() - 1;
        if (lastModelRow >= 0) {
            try {
                int viewRow = sorter.convertRowIndexToView(lastModelRow);
                if (viewRow >= 0)
                    resultsTable.scrollRectToVisible(resultsTable.getCellRect(viewRow, 0, true));
            } catch (Exception ignored) {}
        }
        updateCountBadges();
    }

    /**
     * Returns the URL tagged with its content type suffix for display in the
     * findings table.  Examples:
     *   https://example.com/page          → https://example.com/page [HTML]
     *   https://example.com/app.js        → https://example.com/app.js [JS]
     *   https://example.com/config.json   → https://example.com/config.json [JSON]
     *   https://example.com/sitemap.xml   → https://example.com/sitemap.xml [XML]
     */
    private static String sourceLabel(String url, String contentType) {
        if (url == null) return "";
        // URLs pre-labeled for request scanning ([REQ-HEADERS], [REQ-BODY]) carry their
        // own tag — don't append a second content-type label on top.
        if (url.contains(" [REQ-")) return url;
        String ct = contentType != null ? contentType.toLowerCase() : "";
        if (ct.contains("text/html")        || ct.contains("application/xhtml")) return url + " [HTML]";
        if (ct.contains("javascript")       || ct.contains("ecmascript"))        return url + " [JS]";
        if (ct.contains("application/json") || ct.contains("+json"))             return url + " [JSON]";
        if (ct.contains("text/xml")         || ct.contains("application/xml")
                                            || ct.contains("+xml"))              return url + " [XML]";
        return url;
    }

    // =========================================================================
    // HTTP fetching via Java's native HttpClient
    // =========================================================================

    /**
     * Shared HTTP client for all bulk-scan fetches.
     * Trust-all SSL accepts self-signed / internal certs common in enterprise environments.
     * Redirect.ALWAYS follows cross-host redirects; processUrl() detects SSO redirects by
     * comparing the final URI host against the original request host.
     * Using Java's built-in HttpClient instead of api.http().sendRequest() because Burp's
     * HTTP engine silently returns a null response on Windows for many HTTPS targets.
     */
    private java.net.http.HttpClient HTTP_CLIENT;
    private boolean httpClientAllowInsecureSsl = false; // tracks value used to build HTTP_CLIENT
    /** Trust-all HTTPS client used automatically for raw-IP targets (SAN-for-IP certs are rare). */
    private java.net.http.HttpClient IP_HTTP_CLIENT;

    private java.net.http.HttpClient buildHttpClient(boolean allowInsecureSsl, int proxyPort) {
        // Route through Burp's proxy so traffic appears in Proxy History and passive scanning fires.
        // This also prevents Windows WinHTTP system-proxy interference that causes fetchUrl to fail
        // silently on Windows when Burp is not registered as the system proxy (unlike macOS).
        java.net.ProxySelector proxy = (proxyPort > 0)
                ? java.net.ProxySelector.of(new java.net.InetSocketAddress("127.0.0.1", proxyPort))
                : java.net.ProxySelector.getDefault();

        // When routing through an explicit Burp proxy port, always use trust-all SSL.
        // Burp acts as a TLS MITM and re-signs every certificate with its own CA.
        // Java's JDK cacerts store does not contain Burp's CA, so strict validation
        // rejects every HTTPS connection with a PKIX error.  Trust-all is safe here
        // because Burp has already validated the real server cert on its side.
        if (!allowInsecureSsl && proxyPort <= 0) {
            // Strict mode — only when NOT routing through an explicit proxy
            return java.net.http.HttpClient.newBuilder()
                    .proxy(proxy)
                    .followRedirects(java.net.http.HttpClient.Redirect.ALWAYS)
                    .connectTimeout(java.time.Duration.ofSeconds(20))
                    .build();
        }
        try {
            // X509ExtendedTrustManager takes over the ENTIRE validation including
            // the SAN/IP hostname check — bypasses cert chain + IP mismatch errors.
            javax.net.ssl.TrustManager[] trustAll = {
                new javax.net.ssl.X509ExtendedTrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new java.security.cert.X509Certificate[0];
                    }
                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] c, String a) {}
                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] c, String a) {}
                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] c, String a,
                            java.net.Socket s) {}
                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] c, String a,
                            java.net.Socket s) {}
                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] c, String a,
                            javax.net.ssl.SSLEngine e) {}
                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] c, String a,
                            javax.net.ssl.SSLEngine e) {}
                }
            };
            javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("TLS");
            sc.init(null, trustAll, new java.security.SecureRandom());
            javax.net.ssl.SSLParameters sslParams = new javax.net.ssl.SSLParameters();
            // null disables endpoint identification (hostname/IP SAN check) in Java's HttpClient.
            // Empty string "" is theoretically equivalent but has been observed to be ignored in
            // some Java 17–25 HttpClient builds; null is the safe choice.
            sslParams.setEndpointIdentificationAlgorithm(null);
            return java.net.http.HttpClient.newBuilder()
                    // Force HTTP/1.1: HTTP/2 has stricter TLS requirements (RFC 7540 §9.2) that
                    // can re-enable hostname verification even when the trust manager accepts everything.
                    .version(java.net.http.HttpClient.Version.HTTP_1_1)
                    .proxy(proxy)
                    .sslContext(sc)
                    .sslParameters(sslParams)
                    .followRedirects(java.net.http.HttpClient.Redirect.ALWAYS)
                    .connectTimeout(java.time.Duration.ofSeconds(20))
                    .build();
        } catch (Exception e) {
            // Log to stderr so the failure is visible in Burp's Extensions > Output even though
            // this is a static method without access to api.logging().
            if (api != null)
                api.logging().logToError("[SecretSifter] WARN: buildHttpClient(allowInsecureSsl=true) failed — " +
                    "IP HTTPS scanning will use strict cert validation. Cause: " + e);
            return java.net.http.HttpClient.newBuilder()
                    .proxy(proxy)
                    .followRedirects(java.net.http.HttpClient.Redirect.ALWAYS)
                    .connectTimeout(java.time.Duration.ofSeconds(20))
                    .build();
        }
    }

    private record FetchResult(String body, String contentType,
                               String finalUrl, HttpRequestResponse requestResponse,
                               int statusCode) {}

    private FetchResult fetchUrl(String url) {
        try {
            // Java's native HttpClient — reliably handles HTTPS on all platforms including
            // Windows where api.http().sendRequest() silently returns a null response for
            // many HTTPS targets.  Redirect.ALWAYS follows cross-host redirects; the final
            // URI is available via resp.uri() so processUrl() can detect SSO redirects.
            java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                    .uri(java.net.URI.create(url))
                    .header("User-Agent",
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            + "AppleWebKit/537.36 (KHTML, like Gecko) "
                            + "Chrome/124.0.0.0 Safari/537.36")
                    .header("Accept",
                            "text/html,application/xhtml+xml,application/xml;"
                            + "q=0.9,image/avif,image/webp,*/*;q=0.8")
                    .header("Accept-Language", "en-US,en;q=0.9")
                    // Only gzip+deflate — brotli (br) omitted: no Java stdlib decoder.
                    // decompressBytes() handles gzip and deflate manually.
                    .header("Accept-Encoding", "gzip, deflate")
                    // "Connection" and "Upgrade-Insecure-Requests" are restricted headers in
                    // Java's HttpClient and will throw IllegalArgumentException if set manually.
                    // HttpClient manages connection keep-alive automatically.
                    .header("Cache-Control", "max-age=0")
                    .timeout(java.time.Duration.ofSeconds(20))
                    .GET()
                    .build();
            // Raw-IP URLs never have valid SAN certs — use the trust-all client automatically.
            java.net.http.HttpClient clientToUse = isIpUrl(url) ? IP_HTTP_CLIENT : HTTP_CLIENT;
            java.net.http.HttpResponse<byte[]> resp =
                    clientToUse.send(req, java.net.http.HttpResponse.BodyHandlers.ofByteArray());

            String finalUrl = resp.uri().toString();
            int    status   = resp.statusCode();
            // 4xx/5xx: return a result with null body so callers get the status code
            // (used by processUrl() to distinguish auth errors from connection failures)
            if (status >= 400) {
                return new FetchResult(null, null, finalUrl, null, status);
            }
            String contentType     = resp.headers().firstValue("Content-Type").orElse(null);
            String contentEncoding = resp.headers().firstValue("Content-Encoding").orElse(null);
            String body            = decompressBytes(resp.body(), contentEncoding, finalUrl);
            return new FetchResult(body, contentType, finalUrl, null, status);
        } catch (Exception e) {
            // Unwrap cause chain — UnknownHostException / ConnectException means the target
            // is unreachable; log at INFO level and skip quietly.
            Throwable cause = e;
            while (cause != null) {
                if (cause instanceof java.net.UnknownHostException
                        || cause instanceof java.net.ConnectException) {
                    debugLog("[fetchUrl] Unreachable: " + url
                            + " — " + cause.getClass().getSimpleName() + ": " + cause.toString());
                    return null;
                }
                cause = cause.getCause();
            }
            // For SSL errors, timeouts, or protocol errors: log the full exception chain
            // so the root cause is visible in Extensions → Output.
            StringBuilder sb = new StringBuilder("[fetchUrl] ERROR for ").append(url).append(" — ");
            Throwable t = e;
            while (t != null) {
                sb.append(t.getClass().getName()).append(": ").append(t.getMessage());
                t = t.getCause();
                if (t != null) sb.append(" | caused by: ");
            }
            debugLog(sb.toString());
            return null;
        }
    }

    /**
     * Decompresses a raw response body byte array using the given Content-Encoding value.
     * Handles gzip and deflate; returns a UTF-8 string for unknown or absent encodings.
     *
     * @param raw  raw response body bytes from Java's HttpClient
     * @param enc  value of the Content-Encoding response header (may be null)
     * @param url  URL string used only for diagnostic log messages
     * @return decompressed body as UTF-8 text
     */
    private String decompressBytes(byte[] raw, String enc, String url) {
        if (raw == null || raw.length == 0) return "";
        if (enc == null || enc.isBlank()) return new String(raw, StandardCharsets.UTF_8);
        enc = enc.toLowerCase(java.util.Locale.ROOT).trim();

        if (enc.contains("gzip")) {
            try (java.util.zip.GZIPInputStream gis = new java.util.zip.GZIPInputStream(
                         new ByteArrayInputStream(raw));
                 ByteArrayOutputStream bos = new ByteArrayOutputStream(raw.length * 4)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = gis.read(buf)) != -1) bos.write(buf, 0, n);
                String result = bos.toString(StandardCharsets.UTF_8);
                debugLog("[fetchUrl] gzip decompressed "
                        + raw.length + " → " + bos.size() + " bytes: " + url);
                return result;
            } catch (Exception e) {
                debugLog("[fetchUrl] gzip decompress failed ("
                        + e.toString() + "), using raw body: " + url);
                return new String(raw, StandardCharsets.UTF_8);
            }
        }

        if (enc.contains("deflate")) {
            try (java.util.zip.InflaterInputStream iis = new java.util.zip.InflaterInputStream(
                         new ByteArrayInputStream(raw));
                 ByteArrayOutputStream bos = new ByteArrayOutputStream(raw.length * 4)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = iis.read(buf)) != -1) bos.write(buf, 0, n);
                return bos.toString(StandardCharsets.UTF_8);
            } catch (Exception e) {
                debugLog("[fetchUrl] deflate decompress failed ("
                        + e.toString() + "), using raw body: " + url);
                return new String(raw, StandardCharsets.UTF_8);
            }
        }

        // br (Brotli) has no Java stdlib support; Accept-Encoding no longer advertises it.
        debugLog("[fetchUrl] Unsupported Content-Encoding '" + enc
                + "' — pattern matching may fail for: " + url);
        return new String(raw, StandardCharsets.UTF_8);
    }

    /** Appends one row to the Target Status table and refreshes the summary bar. */
    private void recordTargetStatus(String url, String icon, String detail) {
        String display;
        try { display = new java.net.URL(url).getHost(); }
        catch (Exception e) { display = url.length() > 50 ? url.substring(0, 50) + "…" : url; }
        String d = display;
        SwingUtilities.invokeLater(() -> {
            targetStatusModel.addRow(new Object[]{icon, d, detail});
            updateSummaryBar();
        });
    }

    /** Refreshes the three summary-bar labels from current atomic counters. */
    private void updateSummaryBar() {
        if (sumScannedLbl == null) return;
        sumScannedLbl.setText("Scanned: " + statusScanned.get());
        sumFailedLbl .setText("Failed: "  + statusFailed.get());
        sumAuthLbl   .setText("Auth: "    + statusAuth.get());
    }

    private void updateProgress() {}

    // =========================================================================
    // UI helpers
    // =========================================================================

    private List<String> parseUrls() {
        List<String> urls = new ArrayList<>();
        for (String line : urlArea.getText().split("\n")) {
            // Support comma-separated URLs on a single line (copy-paste from spreadsheets/reports)
            for (String part : line.split(",")) {
                String trimmed = part.trim();
                if (!trimmed.isEmpty()) urls.add(trimmed);
            }
        }
        return urls;
    }

    private static String normaliseUrl(String raw) {
        if (raw == null || raw.isBlank()) return null;
        String s = raw.trim();
        // Strip view-source: prefix (user may copy URLs from browser view-source: tab)
        if (s.toLowerCase().startsWith("view-source:"))
            s = s.substring("view-source:".length()).trim();
        if (!s.startsWith("http://") && !s.startsWith("https://"))
            s = "https://" + s;
        return s;
    }

    private void importUrlFile() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Import URL list");
        fc.setFileFilter(new FileNameExtensionFilter("Text files (*.txt, *.csv)", "txt", "csv"));
        if (fc.showOpenDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;
        try (BufferedReader br = new BufferedReader(
                new FileReader(fc.getSelectedFile(), StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder(urlArea.getText().trim());
            String line;
            while ((line = br.readLine()) != null) {
                String t = line.trim();
                if (!t.isEmpty()) {
                    if (!sb.isEmpty()) sb.append('\n');
                    sb.append(t);
                }
            }
            urlArea.setText(sb.toString());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(rootPanel,
                    "Could not read file: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Opens a .har file chooser, parses the HAR, and scans every JS/HTML/JSON/XML response
     * body directly — no live-fetch needed. This is the preferred path for targets where the
     * scanner cannot reach the server (VPN, self-signed cert, auth-wall) but the tester has
     * already captured traffic in the browser via DevTools → Network → Save as HAR.
     */
    private void importAndScanHar() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Import HAR file");
        fc.setFileFilter(new FileNameExtensionFilter("HAR files (*.har)", "har"));
        if (fc.showOpenDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;
        File harFile = fc.getSelectedFile();

        statusLabel.setText("Reading " + harFile.getName() + "…");
        statusLabel.setForeground(new Color(0, 100, 200));
        progressBar.setIndeterminate(true);

        // Run on background thread — HAR files can be several MB
        Thread harThread = new Thread(() -> {
            try {
                // Read entire file
                String raw;
                try (InputStream is = new FileInputStream(harFile)) {
                    raw = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                }

                JsonObject har     = JsonParser.parseString(raw).getAsJsonObject();
                JsonArray  entries = har.getAsJsonObject("log").getAsJsonArray("entries");
                int total   = entries.size();
                int scanned = 0;

                for (int i = 0; i < total; i++) {
                    JsonObject entry    = entries.get(i).getAsJsonObject();
                    JsonObject request  = entry.getAsJsonObject("request");
                    JsonObject response = entry.getAsJsonObject("response");
                    String     url      = gOptString(request, "url", "");
                    int        status   = gOptInt(response, "status", 0);
                    if (status < 200 || status >= 300) continue;

                    JsonObject content  = gOptObject(response, "content");
                    if (content == null) continue;
                    String mimeType = gOptString(content, "mimeType", "");
                    String body     = gOptString(content, "text",     "");
                    if (body.isBlank()) continue;

                    // Only scan text-based content types that may contain secrets
                    String mt = mimeType.toLowerCase();
                    if (!mt.contains("javascript") && !mt.contains("text/html")
                            && !mt.contains("application/json") && !mt.contains("text/plain")
                            && !mt.contains("application/xml") && !mt.contains("text/xml")) continue;

                    if (settings.isExternalCdn(url)) continue;

                    final String fUrl  = url;
                    final String fMime = mimeType;
                    final String fBody = body;
                    SwingUtilities.invokeLater(() -> {
                        currentFileLabel.setText("→ " + fUrl);
                        scanAndAppend(fBody, fMime, fUrl);
                    });
                    scanned++;
                }

                final int fScanned = scanned;
                final int fTotal   = total;
                SwingUtilities.invokeLater(() -> {
                    progressBar.setIndeterminate(false);
                    progressBar.setValue(0);
                    currentFileLabel.setText("");
                    statusLabel.setText("HAR scan complete — " + fScanned + " responses scanned ("
                            + fTotal + " entries in file)." + severitySummary());
                    statusLabel.setForeground(new Color(0, 140, 60));
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    progressBar.setIndeterminate(false);
                    statusLabel.setText("HAR import failed: " + ex.getMessage());
                    statusLabel.setForeground(Color.RED);
                    JOptionPane.showMessageDialog(rootPanel,
                            "Could not parse HAR file:\n" + ex.getMessage(),
                            "Error", JOptionPane.ERROR_MESSAGE);
                });
            }
        }, "SecretSifter-HarImport");
        harThread.setDaemon(true);
        harThread.start();
    }

    private void clearResults() {
        tableModel.setRowCount(0);
        tableFindings.clear();
        seenUrls.clear();
        seenFindings.clear();
        scanner.clearRequestDedup();
        siteMapIndex = Collections.emptyMap();
        urlArea.setText("");
        progressBar.setIndeterminate(false);
        progressBar.setValue(0);
        progressBar.setString("");
        timerLabel.setText("");
        currentFileLabel.setText("");
        statusLabel.setText("Results cleared.");
        statusLabel.setForeground(Color.GRAY);
        // Also clear the Target Status table and reset summary counters
        targetStatusModel.setRowCount(0);
        statusScanned.set(0);
        statusFailed.set(0);
        statusAuth.set(0);
        updateSummaryBar();
        updateCountBadges();
    }

    private void copyTableCell(int col) {
        int viewRow = resultsTable.getSelectedRow();
        if (viewRow < 0) return;
        int row = sorter.convertRowIndexToModel(viewRow);
        Object val = tableModel.getValueAt(row, col);
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(val != null ? val.toString() : ""), null);
    }

    private void copyTableRow() {
        int viewRow = resultsTable.getSelectedRow();
        if (viewRow < 0) return;
        int row = sorter.convertRowIndexToModel(viewRow);
        StringBuilder sb = new StringBuilder();
        for (int c = 0; c < tableModel.getColumnCount(); c++) {
            if (c > 0) sb.append('\t');
            Object val = tableModel.getValueAt(row, c);
            sb.append(val != null ? val : "");
        }
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(sb.toString()), null);
    }

    private void openUrlInBrowser() {
        int viewRow = resultsTable.getSelectedRow();
        if (viewRow < 0) return;
        int row = sorter.convertRowIndexToModel(viewRow);
        Object val = tableModel.getValueAt(row, COL_URL);
        if (val == null) return;
        try {
            Desktop.getDesktop().browse(URI.create(val.toString()));
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(rootPanel,
                    "Cannot open browser: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    // =========================================================================
    // Export
    // =========================================================================

    private void exportCsv() {
        List<SecretFinding> snapshot = collectForExport();
        if (snapshot.isEmpty()) {
            JOptionPane.showMessageDialog(rootPanel, "No findings to export.", "Export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Export findings as CSV");
        fc.setFileFilter(new FileNameExtensionFilter("CSV files (*.csv)", "csv"));
        fc.setSelectedFile(new File("secretsifter-findings.csv"));
        if (fc.showSaveDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;
        File out = ensureExtension(fc.getSelectedFile(), ".csv");
        try (PrintWriter pw = new PrintWriter(new FileWriter(out, StandardCharsets.UTF_8))) {
            // Header
            pw.println("Rule ID,Rule Name,Key,Value,Severity,Confidence,Line,URL,Context");
            for (SecretFinding f : snapshot) {
                pw.printf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",%d,\"%s\",\"%s\"%n",
                        csvEsc(f.ruleId()), csvEsc(f.ruleName()),
                        csvEsc(f.keyName()), csvEsc(f.matchedValue()),
                        f.severity(), f.confidence(), f.lineNumber(),
                        csvEsc(f.sourceUrl()),
                        csvEsc(f.context() != null ? f.context().replace("\n", " ") : ""));
            }
            statusLabel.setText("CSV saved: " + out.getName());
            statusLabel.setForeground(new Color(0, 130, 0));
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(rootPanel,
                    "Failed to save CSV: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportJson() {
        List<SecretFinding> snapshot = collectForExport();
        if (snapshot.isEmpty()) {
            JOptionPane.showMessageDialog(rootPanel, "No findings to export.", "Export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Export findings as JSON");
        fc.setFileFilter(new FileNameExtensionFilter("JSON files (*.json)", "json"));
        fc.setSelectedFile(new File("secretsifter-findings.json"));
        if (fc.showSaveDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;
        File out = ensureExtension(fc.getSelectedFile(), ".json");
        try (PrintWriter pw = new PrintWriter(new FileWriter(out, StandardCharsets.UTF_8))) {
            JsonArray arr = new JsonArray();
            for (SecretFinding f : snapshot) {
                JsonObject obj = new JsonObject();
                obj.addProperty("ruleId",       f.ruleId());
                obj.addProperty("ruleName",     f.ruleName());
                obj.addProperty("keyName",      f.keyName());
                obj.addProperty("matchedValue", f.matchedValue());
                obj.addProperty("severity",     f.severity());
                obj.addProperty("confidence",   f.confidence());
                obj.addProperty("lineNumber",   f.lineNumber());
                obj.addProperty("sourceUrl",    f.sourceUrl() != null ? f.sourceUrl() : "");
                obj.addProperty("context",      f.context()   != null ? f.context()   : "");
                arr.add(obj);
            }
            pw.print(new GsonBuilder().setPrettyPrinting().create().toJson(arr));
            statusLabel.setText("JSON saved: " + out.getName());
            statusLabel.setForeground(new Color(0, 130, 0));
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(rootPanel,
                    "Failed to save JSON: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportHtml() {
        List<SecretFinding> snapshot = collectForExport();
        if (snapshot.isEmpty()) {
            JOptionPane.showMessageDialog(rootPanel, "No findings to export.", "Export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Export findings as HTML Report");
        fc.setFileFilter(new FileNameExtensionFilter("HTML files (*.html)", "html"));
        fc.setSelectedFile(new File("secret-scanner-report.html"));
        if (fc.showSaveDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;
        File out = ensureExtension(fc.getSelectedFile(), ".html");

        String mode   = (String) tierCombo.getSelectedItem();

        try (FileWriter fw = new FileWriter(out, StandardCharsets.UTF_8)) {
            fw.write(HtmlReportGenerator.generate(snapshot, null, mode));
            statusLabel.setText("HTML report saved: " + out.getName());
            statusLabel.setForeground(new Color(0, 130, 0));
            // Offer to open
            int open = JOptionPane.showConfirmDialog(rootPanel,
                    "Report saved to:\n" + out.getAbsolutePath() + "\n\nOpen in browser?",
                    "Report Saved", JOptionPane.YES_NO_OPTION, JOptionPane.INFORMATION_MESSAGE);
            if (open == JOptionPane.YES_OPTION) {
                try { Desktop.getDesktop().browse(out.toURI()); } catch (Exception ignored) {}
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(rootPanel,
                    "Failed to save report: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Exports one HTML report per base domain into a single ZIP file.
     *
     * Each entry inside the ZIP is named:
     *   &lt;domain&gt;_secretsifter_&lt;timestamp&gt;.html
     * e.g.  example.com_secretsifter_20260319_143022.html
     *
     * Findings with an unparseable URL are grouped under "unknown_domain".
     * After saving, offers to open the containing folder in the OS file manager.
     */
    private void exportHtmlPerDomain() {
        List<SecretFinding> snapshot = collectForExport();
        if (snapshot.isEmpty()) {
            JOptionPane.showMessageDialog(rootPanel,
                    "No findings to export.", "Export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String timestamp = java.time.LocalDateTime.now()
                .format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));

        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Save Per-Domain Reports as ZIP");
        fc.setFileFilter(new FileNameExtensionFilter("ZIP files (*.zip)", "zip"));
        fc.setSelectedFile(new File("secretsifter_reports_" + timestamp + ".zip"));
        if (fc.showSaveDialog(rootPanel) != JFileChooser.APPROVE_OPTION) return;
        File out = ensureExtension(fc.getSelectedFile(), ".zip");

        String mode = (String) tierCombo.getSelectedItem();
        Map<String, String> domainReports = HtmlReportGenerator.generatePerDomain(snapshot, mode);

        try (java.util.zip.ZipOutputStream zos = new java.util.zip.ZipOutputStream(
                new java.io.BufferedOutputStream(new java.io.FileOutputStream(out)))) {
            for (Map.Entry<String, String> entry : domainReports.entrySet()) {
                // Sanitise domain name for use as a filename
                String safeName = entry.getKey().replaceAll("[^a-zA-Z0-9._-]", "_");
                String entryName = safeName + "_secretsifter_" + timestamp + ".html";
                zos.putNextEntry(new java.util.zip.ZipEntry(entryName));
                zos.write(entry.getValue().getBytes(StandardCharsets.UTF_8));
                zos.closeEntry();
            }
            statusLabel.setText("ZIP saved: " + out.getName()
                    + "  (" + domainReports.size() + " domain report"
                    + (domainReports.size() == 1 ? "" : "s") + ")");
            statusLabel.setForeground(new Color(0, 130, 0));

            int open = JOptionPane.showConfirmDialog(rootPanel,
                    "Per-domain ZIP saved to:\n" + out.getAbsolutePath() + "\n\n"
                    + domainReports.size() + " domain report"
                    + (domainReports.size() == 1 ? "" : "s") + " generated.\n\n"
                    + "Open containing folder?",
                    "Reports Saved", JOptionPane.YES_NO_OPTION, JOptionPane.INFORMATION_MESSAGE);
            if (open == JOptionPane.YES_OPTION) {
                try { Desktop.getDesktop().open(out.getParentFile()); } catch (Exception ignored) {}
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(rootPanel,
                    "Failed to save ZIP: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private static File ensureExtension(File f, String ext) {
        return f.getName().toLowerCase().endsWith(ext) ? f
                : new File(f.getAbsolutePath() + ext);
    }

    private static String csvEsc(String s) {
        if (s == null) return "";
        return s.replace("\"", "\"\"");
    }

    // ── Gson helper utilities (replaces org.json convenience methods) ──────────

    private static String gOptString(JsonObject j, String key) {
        return gOptString(j, key, "");
    }
    private static String gOptString(JsonObject j, String key, String def) {
        JsonElement el = j == null ? null : j.get(key);
        return (el != null && !el.isJsonNull() && el.isJsonPrimitive()) ? el.getAsString() : def;
    }
    private static int gOptInt(JsonObject j, String key, int def) {
        JsonElement el = j == null ? null : j.get(key);
        return (el != null && !el.isJsonNull() && el.isJsonPrimitive()) ? el.getAsInt() : def;
    }
    private static boolean gOptBoolean(JsonObject j, String key, boolean def) {
        JsonElement el = j == null ? null : j.get(key);
        return (el != null && !el.isJsonNull() && el.isJsonPrimitive()) ? el.getAsBoolean() : def;
    }
    private static JsonObject gOptObject(JsonObject j, String key) {
        JsonElement el = j == null ? null : j.get(key);
        return (el != null && el.isJsonObject()) ? el.getAsJsonObject() : null;
    }
    private static JsonArray gOptArray(JsonObject j, String key) {
        JsonElement el = j == null ? null : j.get(key);
        return (el != null && el.isJsonArray()) ? el.getAsJsonArray() : null;
    }
    private static JsonObject gParseObject(String s) {
        try { return JsonParser.parseString(s).getAsJsonObject(); } catch (Exception e) { return null; }
    }
    private static JsonArray gParseArray(String s) {
        try { return JsonParser.parseString(s).getAsJsonArray(); } catch (Exception e) { return null; }
    }

    // =========================================================================
    // Cell renderer — colour rows by severity
    // =========================================================================

    /** Returns a severity breakdown suffix like "  ·  C:1 H:3 M:1 L:2" for the status label. */
    private String severitySummary() {
        int c = 0, h = 0, m = 0, l = 0;
        for (int r = 0; r < tableModel.getRowCount(); r++) {
            Object sev = tableModel.getValueAt(r, COL_SEV);
            if (sev == null) continue;
            switch (sev.toString().toUpperCase()) {
                case "CRITICAL" -> c++;
                case "HIGH"     -> h++;
                case "MEDIUM"   -> m++;
                case "LOW"      -> l++;
            }
        }
        return String.format("  ·  C:%d  H:%d  M:%d  L:%d", c, h, m, l);
    }

    /**
     * Called when a severity badge toggle button is clicked.
     * Deselects all other badges, then applies or clears the filter.
     * Clicking the already-active badge clears the filter (shows all).
     */
    private void onBadgeClicked(JToggleButton clicked) {
        boolean nowSelected = clicked.isSelected();
        // Deselect all others
        for (JToggleButton btn : new JToggleButton[]{critCountBtn, highCountBtn, medCountBtn, lowCountBtn}) {
            if (btn != clicked) btn.setSelected(false);
        }
        if (!nowSelected) {
            // Was already active — second click clears filter
            sorter.setRowFilter(null);
        } else {
            applySeverityFilter();
        }
    }

    /** Updates the sorter's RowFilter based on whichever severity badge is currently selected. */
    private void applySeverityFilter() {
        if (sorter == null) return;
        int maxOrder;
        if      (critCountBtn != null && critCountBtn.isSelected()) maxOrder = 0;
        else if (highCountBtn != null && highCountBtn.isSelected()) maxOrder = 1;
        else if (medCountBtn  != null && medCountBtn .isSelected()) maxOrder = 2;
        else if (lowCountBtn  != null && lowCountBtn .isSelected()) maxOrder = 3;
        else { sorter.setRowFilter(null); return; }

        final int threshold = maxOrder;
        sorter.setRowFilter(new RowFilter<DefaultTableModel, Integer>() {
            @Override
            public boolean include(Entry<? extends DefaultTableModel, ? extends Integer> entry) {
                Object sev = entry.getValue(COL_SEV);
                int order = SEV_ORDER.getOrDefault(
                        sev != null ? sev.toString().toUpperCase() : "", 99);
                return order <= threshold;
            }
        });
    }

    /** Refreshes the CRITICAL / HIGH / MEDIUM / LOW count badges in the findings header. Must be called on EDT. */
    private void updateCountBadges() {
        int c = 0, h = 0, m = 0, l = 0;
        for (int r = 0; r < tableModel.getRowCount(); r++) {
            Object sev = tableModel.getValueAt(r, COL_SEV);
            if (sev == null) continue;
            switch (sev.toString().toUpperCase()) {
                case "CRITICAL" -> c++;
                case "HIGH"     -> h++;
                case "MEDIUM"   -> m++;
                case "LOW"      -> l++;
            }
        }
        critCountBtn.setText("Critical: " + c);
        highCountBtn.setText("High: "    + h);
        medCountBtn .setText("Medium: "  + m);
        lowCountBtn .setText("Low: "     + l);
    }

    /** Logs to Burp's output only when the Debug checkbox is checked. */
    private void debugLog(String msg) {
        if (debugModeBox != null && debugModeBox.isSelected())
            api.logging().logToOutput(msg != null ? msg : "");
    }

    /** Creates a coloured badge toggle button for the given severity with an initial count.
     *  Click to filter the table to that severity+; click again to clear. */
    private static JToggleButton makeSevBadge(String sev, int count) {
        String label;
        Color bg, fg;
        switch (sev) {
            case "CRITICAL" -> { bg = new Color(220, 180, 220); fg = new Color(120,  0, 120); label = "Critical: " + count; }
            case "HIGH"     -> { bg = new Color(255, 215, 215); fg = new Color(180,  0,   0); label = "High: "     + count; }
            case "MEDIUM"   -> { bg = new Color(255, 235, 200); fg = new Color(160, 80,   0); label = "Medium: "   + count; }
            default         -> { bg = new Color(255, 252, 200); fg = new Color(140, 120,  0); label = "Low: "      + count; }
        }
        JToggleButton btn = new JToggleButton(label);
        btn.setFont(btn.getFont().deriveFont(Font.BOLD, 11f));
        btn.setOpaque(true);
        btn.setBackground(bg);
        btn.setForeground(fg);
        btn.setFocusPainted(false);
        btn.setBorderPainted(true);
        btn.setContentAreaFilled(true);
        btn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(fg, 1, true),
                BorderFactory.createEmptyBorder(2, 8, 2, 8)));
        btn.setToolTipText("Click to filter — show only " + sev + " and above. Click again to clear.");
        // Keep badge colours when selected (pressed state), darken slightly
        btn.addChangeListener(e -> {
            if (btn.isSelected()) {
                btn.setBackground(fg);
                btn.setForeground(Color.WHITE);
            } else {
                btn.setBackground(bg);
                btn.setForeground(fg);
            }
        });
        return btn;
    }

    /**
     * Builds the export list from the current table state, respecting any severity/confidence
     * edits the user made and rows the user deleted via the × button.
     */
    private List<SecretFinding> collectForExport() {
        List<SecretFinding> result = new ArrayList<>();
        synchronized (tableFindings) {
            int rows = Math.min(tableModel.getRowCount(), tableFindings.size());
            for (int r = 0; r < rows; r++) {
                SecretFinding f   = tableFindings.get(r);
                String sev  = String.valueOf(tableModel.getValueAt(r, COL_SEV));
                String conf = String.valueOf(tableModel.getValueAt(r, COL_CONF));
                result.add(SecretFinding.of(f.ruleId(), f.ruleName(), f.keyName(),
                        f.matchedValue(), sev, conf, f.lineNumber(), f.context(), f.sourceUrl()));
            }
        }
        return result;
    }

    /** Renders the delete column as a small red × button. */
    private static class DeleteButtonRenderer extends DefaultTableCellRenderer {
        private final JButton btn;
        DeleteButtonRenderer() {
            btn = new JButton("✕");
            btn.setFont(btn.getFont().deriveFont(Font.BOLD, 11f));
            btn.setForeground(new Color(180, 0, 0));
            btn.setBorderPainted(false);
            btn.setContentAreaFilled(false);
            btn.setFocusPainted(false);
            btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            btn.setToolTipText("Remove this finding");
        }
        @Override
        public Component getTableCellRendererComponent(JTable t, Object v,
                boolean sel, boolean foc, int row, int col) {
            return btn;
        }
    }

    private class SeverityCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean selected, boolean focused, int row, int col) {
            // Apply mask before rendering
            Object display = value;
            if (col == COL_VAL && maskValues && value != null && !value.toString().isEmpty())
                display = "••••••••••••";
            else if (col == COL_URL && maskUrls && value != null && !value.toString().isEmpty())
                display = "••••••••••••";
            Component c = super.getTableCellRendererComponent(
                    table, display, selected, focused, row, col);
            if (!selected) {
                int modelRow = table.convertRowIndexToModel(row);
                Object sev = tableModel.getValueAt(modelRow, COL_SEV);
                Color bg = sev != null
                        ? SEV_BG.getOrDefault(sev.toString().toUpperCase(), Color.WHITE)
                        : Color.WHITE;
                c.setBackground(bg);
            }
            if (col == COL_URL || col == 8) {
                setFont(getFont().deriveFont(Font.PLAIN, 11f));
                setForeground(selected ? Color.WHITE : Color.BLACK);
            } else {
                setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
                setForeground(selected ? Color.WHITE : Color.BLACK);
            }
            return c;
        }
    }
}
