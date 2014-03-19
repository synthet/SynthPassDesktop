package ru.synthet.synthpass;

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
