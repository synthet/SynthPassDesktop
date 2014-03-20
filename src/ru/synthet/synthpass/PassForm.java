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

    private final PassGenerator passGenerator = new PassGenerator();
    private String resultString = "password";
    private String masterPassword = "";
    private String domainName = "";

    public PassForm() {
        super("SynthPass");

        setContentPane(rootPanel);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        pack();
        setLocationRelativeTo(null);
        //centreWindow(this);

        genButton.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                masterPassword = passField.getText();
                domainName = domainField.getText();
                passLabel.setText(gen());
            }
        });

        PassGenerator.PassRules.generatedPasswordLength = 16;

    }


    private String gen() {
        String inputString = masterPassword + domainName;
        do {
            resultString = passGenerator.synthEncrypt(inputString,
                    PassGenerator.PassRules.generatedPasswordLength);
            inputString = resultString;

        } while (!passGenerator.validate(resultString));
        return resultString;
    }
}
