![cryptomator](cryptomator.png)

**Cryptomator Sanitizer** - Utilities to find and fix problems within vaults

## Usage

```
java -jar sanitizer-0.1.jar -vault vaultToCheck
            [-passphraseFile passphraseFile] [-solve enabledSolution ...]
            [-output outputFile]

Detects problems in Cryptomator vaults.

    --output <outputFile>               The file to write results to.
                                        Default:
                                        {vaultname}.vaultcheck.txt
    --passphrase <passphrase>           DO NOT USE. ONLY FOR TESTING
                                        PURPOSES. The cleartext vault
                                        passphrase. Omit this and you will
                                        be promted for the passphrase.
    --passphraseFile <passphraseFile>   A file to read the password from.
                                        Omit this and you will be promted
                                        for the passphrase.
    --solve <solve>                     Name of one or more problems to
                                        solve. Available:
                                        MissingEqualsSign, UppercasedFile,
                                        LowercasedFile, OrphanMFile
    --vault <vaultPath>                 The vault to check.
```

### Examples

You need to have Java 8 and the JCE unlimited strength policy files installed to run this tool.

You can download these on
* http://www.oracle.com/technetwork/java/javase/downloads/jre8-downloads-2133155.html
* http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html

Install the JCE files following the description in the README.txt file inside the downloaded zip archive.

When you have everything setup you can run the integrity check from the command line (cmd.exe on Windows) using:

```
java -jar sanitizer-0.1.jar -vault <pathToYourVault>
```

You will be asked for the vault passphrase in this case. If that fails you may store your passphrase in a file (without line break at the end!) and use

```
java -jar sanitizer-0.1.jar -vault <pathToYourVault> -passphraseFile <pathToThePassphraseFile>
```

After completion the tool will print how many problems were found and create a file `<vaultname>.vaultcheck.txt`.

## Building

### Dependencies

* Java 8 + JCE unlimited strength policy files (needed for 256-bit keys)
* Maven 3

### Run Maven

```bash
mvn clean install
```

## License

Distributed under the GPLv3. See the `LICENSE.txt` file for more info.
