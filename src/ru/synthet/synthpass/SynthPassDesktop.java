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

public class SynthPassDesktop extends JApplet {

    private final PassGenerator passGenerator = new PassGenerator();
    private volatile String resultString = "password";
    private String masterPassword = "12345";
    private String domainName = "";

    public void init() {
        //Execute a job on the event-dispatching thread:
        //creating this applet's GUI.
        try {
            javax.swing.SwingUtilities.invokeAndWait(new Runnable() {
                public void run() {
                    createGUI();
                }
            });
        } catch (Exception e) {
            System.err.println("createGUI didn't successfully complete");
        }
    }

    public void createGUI () {
        JLabel label = new JLabel(gen());
        label.setHorizontalAlignment(JLabel.CENTER);
        label.setBorder(BorderFactory.createMatteBorder(1,1,1,1, Color.black));
        getContentPane().add(label, BorderLayout.CENTER);
    }

    private String gen() {
        String inputString = masterPassword + domainName;
        do {
            resultString = passGenerator.synthEncrypt(inputString,
                    PassGenerator.PassRules.generatedPasswordLength);
            inputString = resultString;
            //if (generationThread.isInterrupted()) {
            //    break;
            //}
        } while (!passGenerator.validate(resultString));
        return resultString;
    }

}
