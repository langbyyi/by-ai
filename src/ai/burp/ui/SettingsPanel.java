package ai.burp.ui;

import java.awt.*;
import java.awt.Desktop;
import java.io.File;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.swing.*;
import javax.swing.border.EmptyBorder;

import ai.burp.config.ExtensionConfig;
import ai.burp.provider.StreamingAIProvider;

import static ai.burp.ui.ChineseUI.*;

/**
 * 设置面板 - 嵌入标签页中，不再弹窗。
 */
public class SettingsPanel extends JPanel
{
    private static class ConfigSnapshot
    {
        final String apiUrl;
        final String apiKey;
        final String model;
        final String systemPrompt;
        final int suspicionThreshold;
        final long debounceMs;
        final boolean useCollaborator;
        final String dnslogDomain;

        ConfigSnapshot(ExtensionConfig config)
        {
            this.apiUrl = config.getApiUrl();
            this.apiKey = config.getApiKey();
            this.model = config.getModel();
            this.systemPrompt = config.getSystemPrompt();
            this.suspicionThreshold = config.getSuspicionThreshold();
            this.debounceMs = config.getDebounceMs();
            this.useCollaborator = config.isUseCollaborator();
            this.dnslogDomain = config.getDnslogDomain();
        }

        void restore(ExtensionConfig config)
        {
            config.setApiUrl(apiUrl);
            config.setApiKey(apiKey);
            config.setModel(model);
            config.setSystemPrompt(systemPrompt);
            config.setSuspicionThreshold(suspicionThreshold);
            config.setDebounceMs(debounceMs);
            config.setUseCollaborator(useCollaborator);
            config.setDnslogDomain(dnslogDomain);
        }
    }

    private final ExtensionConfig config;
    private final StreamingAIProvider provider;

    private JTextField apiUrlField;
    private JPasswordField apiKeyField;
    private JTextField modelField;
    private JTextArea systemPromptArea;
    private JCheckBox streamingCheckbox;
    private JSpinner thresholdSpinner;
    private JSpinner debounceSpinner;
    private JCheckBox collaboratorCheckbox;
    private JTextField dnslogDomainField;
    private JLabel statusLabel;

    public SettingsPanel(ExtensionConfig config, StreamingAIProvider provider)
    {
        this.config = config;
        this.provider = provider;
        initUI();
    }

    private void initUI()
    {
        setLayout(new BorderLayout(8, 8));
        setBorder(new EmptyBorder(12, 12, 12, 12));

        // ===== 预设面板 =====
        JPanel presetsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        presetsPanel.add(new JLabel(SETTINGS_QUICK));
        String[] presets = {
            PRESET_OPENAI, PRESET_OLLAMA,
            PRESET_LMSTUDIO, PRESET_DEEPSEEK, PRESET_CUSTOM
        };
        JComboBox<String> presetCombo = new JComboBox<>(presets);
        presetCombo.addActionListener(e -> applyPreset((String) presetCombo.getSelectedItem()));
        presetsPanel.add(presetCombo);
        add(presetsPanel, BorderLayout.NORTH);

        // ===== 表单面板 =====
        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.insets = new Insets(4, 4, 4, 4);

        int row = 0;

        // API URL
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        formPanel.add(new JLabel(SETTINGS_URL), gbc);
        gbc.gridx = 1; gbc.weightx = 1;
        apiUrlField = new JTextField(config.getApiUrl(), 40);
        formPanel.add(apiUrlField, gbc);
        row++;

        // API Key
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        formPanel.add(new JLabel(SETTINGS_KEY), gbc);
        gbc.gridx = 1; gbc.weightx = 1;
        apiKeyField = new JPasswordField(config.getApiKey(), 40);
        formPanel.add(apiKeyField, gbc);
        row++;

        // Model
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        formPanel.add(new JLabel(SETTINGS_MODEL), gbc);
        gbc.gridx = 1; gbc.weightx = 1;
        modelField = new JTextField(config.getModel(), 40);
        formPanel.add(modelField, gbc);
        row++;

        // Streaming
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2; gbc.weightx = 1;
        streamingCheckbox = new JCheckBox(SETTINGS_STREAMING, config.isStreamingEnabled());
        formPanel.add(streamingCheckbox, gbc);
        gbc.gridwidth = 1;
        row++;

        // System Prompt
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0; gbc.anchor = GridBagConstraints.NORTHWEST;
        formPanel.add(new JLabel(SETTINGS_PROMPT), gbc);
        gbc.gridx = 1; gbc.weightx = 1; gbc.anchor = GridBagConstraints.WEST;
        systemPromptArea = new JTextArea(config.getSystemPrompt(), 5, 40);
        systemPromptArea.setLineWrap(true);
        systemPromptArea.setWrapStyleWord(true);
        formPanel.add(new JScrollPane(systemPromptArea), gbc);
        row++;

        // ===== 实时分析配置区块 =====
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2; gbc.weightx = 1;
        gbc.insets = new Insets(16, 4, 4, 4);
        JLabel realtimeSectionLabel = new JLabel(SETTINGS_REALTIME_SECTION);
        realtimeSectionLabel.setFont(realtimeSectionLabel.getFont().deriveFont(Font.BOLD, 13f));
        formPanel.add(realtimeSectionLabel, gbc);
        gbc.insets = new Insets(4, 4, 4, 4);
        row++;

        // 可疑度阈值
        JLabel thresholdLabel = new JLabel(SETTINGS_THRESHOLD);
        thresholdLabel.setToolTipText(SETTINGS_THRESHOLD_TIP);
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 1; gbc.weightx = 0;
        formPanel.add(thresholdLabel, gbc);
        SpinnerNumberModel thresholdModel = new SpinnerNumberModel(
            config.getSuspicionThreshold(), 0, 20, 1);
        thresholdSpinner = new JSpinner(thresholdModel);
        thresholdSpinner.setToolTipText(SETTINGS_THRESHOLD_TIP);
        gbc.gridx = 1; gbc.weightx = 1;
        formPanel.add(thresholdSpinner, gbc);
        row++;

        // 防抖间隔
        JLabel debounceLabel = new JLabel(SETTINGS_DEBOUNCE);
        debounceLabel.setToolTipText(SETTINGS_DEBOUNCE_TIP);
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 1; gbc.weightx = 0;
        formPanel.add(debounceLabel, gbc);
        SpinnerNumberModel debounceModel = new SpinnerNumberModel(
            (int)(config.getDebounceMs() / 1000), 5, 300, 5);
        debounceSpinner = new JSpinner(debounceModel);
        debounceSpinner.setToolTipText(SETTINGS_DEBOUNCE_TIP);
        gbc.gridx = 1; gbc.weightx = 1;
        formPanel.add(debounceSpinner, gbc);
        row++;

        // ===== OOB 带外测试配置区块 =====
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2; gbc.weightx = 1;
        gbc.insets = new Insets(16, 4, 4, 4);
        JLabel oobSectionLabel = new JLabel(SETTINGS_OOB_SECTION);
        oobSectionLabel.setFont(oobSectionLabel.getFont().deriveFont(Font.BOLD, 13f));
        formPanel.add(oobSectionLabel, gbc);
        gbc.insets = new Insets(4, 4, 4, 4);
        row++;

        // 使用 Burp Collaborator
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2; gbc.weightx = 1;
        collaboratorCheckbox = new JCheckBox(SETTINGS_USE_COLLABORATOR, config.isUseCollaborator());
        collaboratorCheckbox.setToolTipText(SETTINGS_USE_COLLABORATOR_TIP);
        formPanel.add(collaboratorCheckbox, gbc);
        row++;

        // 自定义 DNSLog 域名
        JLabel dnslogLabel = new JLabel(SETTINGS_DNSLOG_DOMAIN);
        dnslogLabel.setToolTipText(SETTINGS_DNSLOG_TIP);
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 1; gbc.weightx = 0;
        formPanel.add(dnslogLabel, gbc);
        gbc.gridx = 1; gbc.weightx = 1;
        dnslogDomainField = new JTextField(config.getDnslogDomain(), 40);
        dnslogDomainField.setToolTipText(SETTINGS_DNSLOG_TIP);
        dnslogDomainField.setEnabled(!config.isUseCollaborator());
        formPanel.add(dnslogDomainField, gbc);
        row++;

        // Collaborator 选中时禁用自定义域名输入
        collaboratorCheckbox.addActionListener(e -> {
            dnslogDomainField.setEnabled(!collaboratorCheckbox.isSelected());
            if (collaboratorCheckbox.isSelected())
            {
                dnslogDomainField.setText("");
            }
        });

        // 状态标签
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2; gbc.weightx = 1; gbc.weighty = 1.0;
        statusLabel = new JLabel(" ");
        formPanel.add(statusLabel, gbc);

        add(new JScrollPane(formPanel), BorderLayout.CENTER);

        // ===== 按钮面板 =====
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));

        JButton openConfigButton = new JButton(BTN_OPEN_CONFIG);
        openConfigButton.setToolTipText(config.getConfigDir().toString());
        openConfigButton.addActionListener(e -> {
            try
            {
                File configDir = config.getConfigDir().toFile();
                if (!configDir.exists()) configDir.mkdirs();
                Desktop.getDesktop().open(configDir);
            }
            catch (IOException ex)
            {
                JOptionPane.showMessageDialog(this,
                    "无法打开配置目录: " + ex.getMessage(),
                    "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
        buttonPanel.add(openConfigButton);

        JButton testButton = new JButton(BTN_TEST_CONN);
        testButton.addActionListener(e -> testConnection());
        buttonPanel.add(testButton);

        JButton saveButton = new JButton(BTN_SAVE);
        saveButton.addActionListener(e -> save());
        buttonPanel.add(saveButton);

        add(buttonPanel, BorderLayout.SOUTH);
    }

    private void applyPreset(String preset)
    {
        switch (preset)
        {
            case PRESET_OPENAI:
                apiUrlField.setText("https://api.openai.com/v1");
                modelField.setText("gpt-4o");
                break;
            case PRESET_OLLAMA:
                apiUrlField.setText("http://localhost:11434/v1");
                modelField.setText("llama3");
                apiKeyField.setText("ollama");
                break;
            case PRESET_LMSTUDIO:
                apiUrlField.setText("http://localhost:1234/v1");
                modelField.setText("default");
                apiKeyField.setText("lm-studio");
                break;
            case PRESET_DEEPSEEK:
                apiUrlField.setText("https://api.deepseek.com/v1");
                modelField.setText("deepseek-chat");
                break;
            default:
                break;
        }
    }

    private void save()
    {
        config.setApiUrl(apiUrlField.getText().trim());
        config.setApiKey(new String(apiKeyField.getPassword()).trim());
        config.setModel(modelField.getText().trim());
        config.setSystemPrompt(systemPromptArea.getText().trim());
        config.setStreamingEnabled(streamingCheckbox.isSelected());
        config.setSuspicionThreshold((Integer) thresholdSpinner.getValue());
        config.setDebounceMs(((Integer) debounceSpinner.getValue()) * 1000L);
        config.setUseCollaborator(collaboratorCheckbox.isSelected());
        config.setDnslogDomain(dnslogDomainField.getText().trim());
        config.save();
        statusLabel.setText(String.format(MSG_SETTINGS_SAVED, config.getApiUrl()));
    }

    private void testConnection()
    {
        ConfigSnapshot snapshot = new ConfigSnapshot(config);

        // 临时应用设置
        config.setApiUrl(apiUrlField.getText().trim());
        config.setApiKey(new String(apiKeyField.getPassword()).trim());
        config.setModel(modelField.getText().trim());
        config.setSystemPrompt(systemPromptArea.getText().trim());
        config.setSuspicionThreshold((Integer) thresholdSpinner.getValue());
        config.setDebounceMs(((Integer) debounceSpinner.getValue()) * 1000L);
        config.setUseCollaborator(collaboratorCheckbox.isSelected());
        config.setDnslogDomain(dnslogDomainField.getText().trim());

        statusLabel.setText(STATUS_THINKING);

        SwingWorker<String, Void> worker = new SwingWorker<>()
        {
            @Override
            protected String doInBackground() throws Exception
            {
                return provider.testConnection();
            }

            @Override
            protected void done()
            {
                try
                {
                    String result = get();
                    statusLabel.setText(String.format(MSG_TEST_OK, result));
                }
                catch (Exception e)
                {
                    String msg = e.getMessage();
                    if (e.getCause() != null) msg = e.getCause().getMessage();
                    statusLabel.setText(String.format(MSG_TEST_FAIL, msg));
                }
                finally
                {
                    snapshot.restore(config);
                }
            }
        };
        worker.execute();
    }

    /**
     * 获取当前是否已保存配置。
     */
    public boolean isConfigured()
    {
        return config.isConfigured();
    }
}
