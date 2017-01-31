![sanitizer](sanitizer.png)

Utility to find and fix problems within vaults.

## Usage

```
usage: java -jar sanitizer-x.y.jar -vault vaultToCheck -cmd
            check|deepCheck|solve|encryptPath [-passphraseFile
            passphraseFile] [-solve enabledSolution ...] [-output
            outputPrefix]

Detects problems in Cryptomator vaults.

    --cmd <command>                     What to do
                                        (check,deepCheck,solve,encryptPath
                                        )
    --output <outputPrefix>             The prefix of the output files to
                                        write results to. Will create two
                                        output files:
                                        * <outputPrefix>.structure.txt and
                                        * <outputPrefix>.check.txt.
                                        Default: name of vault
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
    --vault <vaultPath>                 On which vault to work.
```

You need to have Java 8 and JCE unlimited strength policy files installed to run this tool.

You can download these on
* http://www.oracle.com/technetwork/java/javase/downloads/jre8-downloads-2133155.html
* http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html

Install the JCE files following the description in the `README.txt` file inside the downloaded zip archive.

### Examples

When you have everything set up, you can run the integrity check from the command line (cmd.exe on Windows) using:

```
java -jar sanitizer-x.y.jar --cmd check --vault <pathToYourVault>
```

You will be asked for the vault passphrase in this case. If that fails, you may store your passphrase in a file (without line break at the end!) and use:

```
java -jar sanitizer-x.y.jar --cmd --vault <pathToYourVault> --passphraseFile <pathToThePassphraseFile>
```

After completion, the tool will print how many problems were found and create two files:

* `<vault name>.structure.txt`: The full structure of the vault including all files and directories. Contains only encrypted names and the exact size of small and the approximate size of larger ones so we can not see your data. This may help us to diagnose issues not already handled by the sanitizer.
* `<vault name>.check.txt`: A list of known issues and some information. This includes the name of the encrypted root directory. This is useful to check how the root directory looks like when analyzing the structure file.

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
