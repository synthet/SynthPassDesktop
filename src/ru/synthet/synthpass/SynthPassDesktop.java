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
import java.awt.*;

public class SynthPassDesktop extends JFrame {

    private PassGenerator passGenerator = new PassGenerator();
    private String resultString = "password";
    private String masterPassword = "1234";
    private String domainName = "";

    private JPanel jpnlMain = new JPanel(new BorderLayout());
    private JPanel jpnlBoutton = new JPanel(new GridLayout(5,5));
    private JPanel jpnlLogo = new JPanel();
    private JButton[] jbtnAllo = new JButton[10];

    public static void main(String[] args) {

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                SynthPassDesktop ex = new SynthPassDesktop();
                ex.setVisible(true);

            }
        });

    }

    public SynthPassDesktop()  {

        setTitle("Simple example");
        setSize(300, 200);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(EXIT_ON_CLOSE);

        this.add(jpnlMain);
        for(int i =0;i<jbtnAllo.length;i++){
            masterPassword = String.valueOf(i);
            jbtnAllo[i] = new JButton();
            jbtnAllo[i].setText(gen());

            jpnlBoutton.add(jbtnAllo[i]);
        }
        jpnlMain.add(jpnlBoutton,"North");
        jpnlMain.add(jpnlLogo, "Center");
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
