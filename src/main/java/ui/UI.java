package ui;

import signature.DSAKeyPair;
import signature.DSASignature;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class UI extends JFrame {

    private static final String PUBLIC_KEY_FILENAME = "key.pub";
    private static final String PRIVATE_KEY_FILENAME = "_key";


    private final JButton openBtn = new JButton("Open");


    private final JButton verifyBtn = new JButton("Verify");
    private final JButton saveSign = new JButton("Generate signature");
    private final JTextArea signatureInput = new JTextArea();
    private final JLabel fileLabel = new JLabel("Not selected");
    private final JFileChooser fileChooser = new JFileChooser();
    private final JLabel statusLabel = new JLabel("False");

    private DSAKeyPair keyPair;

    public UI() throws HeadlessException {
        keyPair = DSAKeyPair.read(new File(PRIVATE_KEY_FILENAME), new File(PUBLIC_KEY_FILENAME));

        setContentPane(new JPanel());
        add(fileLabel);
        add(openBtn);
        openBtn.addActionListener(e -> {
            fileChooser.showOpenDialog(this);
            File selectedFile = fileChooser.getSelectedFile();
            if (selectedFile == null)
                return;
            try {
                fileLabel.setText(selectedFile.getCanonicalPath());
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        });

        verifyBtn.addActionListener(e -> {
            byte[] signature = Base64.getDecoder().decode(signatureInput.getText().getBytes(StandardCharsets.UTF_8));
            try (InputStream inputStream = new FileInputStream(fileChooser.getSelectedFile())) {
                boolean isVerified = new DSASignature().verify(keyPair.getPublicKey(),
                        inputStream.readAllBytes(),
                        signature);
                statusLabel.setText(Boolean.toString(isVerified).toUpperCase());
                setVisible(true);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        });

        saveSign.addActionListener(e -> {
            try (InputStream inputStream = new FileInputStream(fileChooser.getSelectedFile())) {
                byte[] sign = new DSASignature().sign(keyPair.getPrivateKey(),
                        inputStream.readAllBytes());
                signatureInput.setText(Base64.getEncoder().encodeToString(sign));
                setVisible(true);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        });

        signatureInput.setColumns(40);
        signatureInput.setRows(3);
        signatureInput.setWrapStyleWord(true);
        add(new JScrollPane(signatureInput,
                JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER));


        add(saveSign);
        add(verifyBtn);
        add(statusLabel);
        setTitle("Signature (DSA)");
        setVisible(true);
        setSize(500, 700);
    }
}
