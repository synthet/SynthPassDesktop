package ru.synthet.synthpass;

import java.awt.*;
import java.applet.Applet;

/**
 * Created by bragin_va on 19.03.14.
 */
public class SynthPassDesktop extends Applet {

    private final PassGenerator passGenerator = new PassGenerator();
    private volatile String resultString = "password";
    private String masterPassword = "12345";
    private String domainName;

    public void paint (Graphics g) {
        g.drawString(gen(), 50, 25);
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
