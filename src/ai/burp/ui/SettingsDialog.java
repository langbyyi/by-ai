package ai.burp.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

import ai.burp.config.ExtensionConfig;

/**
 * Settings dialog for AI provider configuration.
 */
class SettingsDialog extends JDialog
{
    private final ExtensionConfig config;
    private boolean saved = false;

    private JTextField apiUrlField;
    private JPasswordField apiKeyField;
    private JTextField modelField;
    private JTextArea systemPromptArea;

    SettingsDialog(Frame parent, ExtensionConfig config)
    {
        super(parent, "AI Extension Settings", true);
        this.config = config;
        initUI();
        setLocationRelativeTo(parent);
    }

    private void initUI()
    {
        JPanel mainPanel = new JPanel(new BorderLayout(8, 8));
        mainPanel.setBorder(new EmptyBorder(12, 12, 12, 12));

        // ===== Presets panel =====
        JPanel presetsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        presetsPanel.add(new JLabel("Quick Setup:"));
        String[] presets = {
            "OpenAI",
            "Ollama",
            "LM Studio",
            "DeepSeek",
            "Custom"
        };
        JComboBox<String> presetCombo = new JComboBox<>(presets);
        presetCombo.addActionListener(e -> applyPreset((String) presetCombo.getSelectedItem()));
        presetsPanel.add(presetCombo);
        mainPanel.add(presetsPanel, BorderLayout.NORTH);

        // ===== Form panel =====
        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(4, 4, 4, 4);

        int row = 0;

        // API URL
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        formPanel.add(new JLabel("API URL:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1;
        apiUrlField = new JTextField(config.getApiUrl(), 40);
        formPanel.add(apiUrlField, gbc);
        row++;

        // API Key
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        formPanel.add(new JLabel("API Key:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1;
        apiKeyField = new JPasswordField(config.getApiKey(), 40);
        formPanel.add(apiKeyField, gbc);
        row++;

        // Model
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;
        formPanel.add(new JLabel("Model:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1;
        modelField = new JTextField(config.getModel(), 40);
        formPanel.add(modelField, gbc);
        row++;

        // System Prompt
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0; gbc.anchor = GridBagConstraints.NORTHWEST;
        formPanel.add(new JLabel("System Prompt:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1; gbc.anchor = GridBagConstraints.WEST;
        systemPromptArea = new JTextArea(config.getSystemPrompt(), 5, 40);
        systemPromptArea.setLineWrap(true);
        systemPromptArea.setWrapStyleWord(true);
        formPanel.add(new JScrollPane(systemPromptArea), gbc);
        row++;

        // Compatible services info
        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 2; gbc.weightx = 1;
        gbc.insets = new Insets(12, 4, 4, 4);
        JLabel infoLabel = new JLabel("<html><b>Compatible Services:</b> OpenAI, Azure OpenAI, Ollama, "
            + "LM Studio, vLLM, LocalAI, DeepSeek, ChatGLM, Moonshot, and any OpenAI-compatible API</html>");
        infoLabel.setFont(infoLabel.getFont().deriveFont(Font.PLAIN, 11f));
        formPanel.add(infoLabel, gbc);

        mainPanel.add(formPanel, BorderLayout.CENTER);

        // ===== Buttons =====
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton testButton = new JButton("Test Connection");
        testButton.addActionListener(e -> testConnection());
        buttonPanel.add(testButton);

        JButton saveButton = new JButton("Save");
        saveButton.addActionListener(e -> save());
        buttonPanel.add(saveButton);

        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> dispose());
        buttonPanel.add(cancelButton);

        mainPanel.add(buttonPanel, BorderLayout.SOUTH);

        setContentPane(mainPanel);
        pack();
        setMinimumSize(new Dimension(500, 400));
    }

    private void applyPreset(String preset)
    {
        switch (preset)
        {
            case "OpenAI":
                apiUrlField.setText("https://api.openai.com/v1/chat/completions");
                modelField.setText("gpt-4o");
                break;
            case "Ollama":
                apiUrlField.setText("http://localhost:11434/v1/chat/completions");
                modelField.setText("llama3");
                apiKeyField.setText("ollama");
                break;
            case "LM Studio":
                apiUrlField.setText("http://localhost:1234/v1/chat/completions");
                modelField.setText("default");
                apiKeyField.setText("lm-studio");
                break;
            case "DeepSeek":
                apiUrlField.setText("https://api.deepseek.com/v1/chat/completions");
                modelField.setText("deepseek-chat");
                break;
            case "Custom":
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
        saved = true;
        dispose();
    }

    private void testConnection()
    {
        // Temporarily apply settings for testing
        config.setApiUrl(apiUrlField.getText().trim());
        config.setApiKey(new String(apiKeyField.getPassword()).trim());
        config.setModel(modelField.getText().trim());
        config.setSystemPrompt(systemPromptArea.getText().trim());

        setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));

        SwingWorker<String, Void> worker = new SwingWorker<>()
        {
            @Override
            protected String doInBackground() throws Exception
            {
                return new ai.burp.provider.OpenAICompatibleProvider(config).testConnection();
            }

            @Override
            protected void done()
            {
                setCursor(Cursor.getDefaultCursor());
                try
                {
                    String result = get();
                    JOptionPane.showMessageDialog(SettingsDialog.this,
                        result, "Connection Test", JOptionPane.INFORMATION_MESSAGE);
                }
                catch (Exception e)
                {
                    String msg = e.getMessage();
                    if (e.getCause() != null) msg = e.getCause().getMessage();
                    JOptionPane.showMessageDialog(SettingsDialog.this,
                        "Connection failed: " + msg, "Connection Test", JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        worker.execute();
    }

    boolean isSaved()
    {
        return saved;
    }
}
