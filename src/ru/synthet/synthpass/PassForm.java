package ru.synthet.synthpass;
/*
 * Copyright 2014 Vladimir Synthet
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class PassForm extends JFrame {
    private JPasswordField passField;
    private JTextField domainField;
    private JButton genButton;
    private JPanel rootPanel;
    private JLabel passLabel;
    private JSlider passlenSlider;

    private final PassGenerator passGenerator = new PassGenerator();
    private String resultString = "password";
    private char[] masterPassword;
    private char[] domainName;

    public PassForm() {
        super("SynthPass");

        setContentPane(rootPanel);
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        pack();
        setLocationRelativeTo(null);
        setResizable(false);
        setAlwaysOnTop(true);

        genButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                click();
            }
        });

        domainField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                click();
            }
        });

    }

    private void click() {
        PassGenerator.PassRules.generatedPasswordLength = passlenSlider.getValue();

        masterPassword = passField.getPassword();
        domainName = domainField.getText().toCharArray();
        passLabel.setText(gen());
    }

    private String gen() {
        char[] resultArray;
        do {
            resultArray = passGenerator.synthEncrypt(masterPassword, domainName,
                    PassGenerator.PassRules.generatedPasswordLength);
            masterPassword = resultArray;
            domainName = "".toCharArray();
        } while (!passGenerator.validate(resultArray));
        resultString = String.copyValueOf(resultArray);
        return resultString;
    }
}
