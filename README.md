![sanitizer](sanitizer.png)

Utility to find and fix problems within vaults, restoring files and mapping cleartext to encrypted paths.

## Download

Sanitizer is a Java program. The current version can be downloaded from the [releases page](https://github.com/cryptomator/sanitizer/releases).

You will need Java 9 installed to run it.

## Usage

```
java -jar sanitizer-0.16.jar command ...

commands:
* check - check a vault for problems
* decryptFile - decrypt the contents of a single file
* encryptPath - encrypt a cleartext path
* decryptVault - decrypt a complete vault and restore inaccessible data
```

A more detailed guide on how to use Sanitizer can be found [here](https://community.cryptomator.org/t/sanitizer-how-to-use/43).

### check command usage

```
java -jar sanitizer-0.16.jar check -vault vaultPath [-passphraseFile passphraseFile] [-deep] [-solve enabledSolution ...] [-output outputPrefix]

Detects problems in Cryptomator vaults.

    --deep                              Check file integrity (Could take a long
                                        time).
    --output <outputPrefix>             The prefix of the output files to write
                                        results to. Will create two output
                                        files:
                                        * <outputPrefix>.structure.txt and
                                        * <outputPrefix>.check.txt.
                                        Default: name of vault
    --passphrase <passphrase>           DO NOT USE. ONLY FOR TESTING PURPOSES.
                                        The cleartext vault passphrase. Omit
                                        this and you will be promted for the
                                        passphrase.
    --passphraseFile <passphraseFile>   A file to read the password from. Omit
                                        this and you will be promted for the
                                        passphrase.
    --solve <solve>                     Name of one or more problems to solve.
                                        Available: MissingEqualsSign,
                                        UppercasedFile, LowercasedFile,
                                        OrphanMFile, FileSizeOfZeroInHeader,
                                        FileSizeInHeader, NameNormalization
    --vault <vaultPath>                 On which vault to work.
```

### decryptFile command usage

```
java -jar sanitizer-0.16.jar decryptFile -vault vaultPath [-passphraseFile passphraseFile]

Decrypts single Cryptomator files.

    --passphrase <passphrase>           DO NOT USE. ONLY FOR TESTING PURPOSES.
                                        The cleartext vault passphrase. Omit
                                        this and you will be promted for the
                                        passphrase.
    --passphraseFile <passphraseFile>   A file to read the password from. Omit
                                        this and you will be promted for the
                                        passphrase.
    --vault <vaultPath>                 On which vault to work.
```

### encryptPath command usage

```
java -jar sanitizer-0.16.jar encryptPath -vault vaultPath [-passphraseFile passphraseFile] [-cleartextPath cleartextPath] [-cleartextListFile cleartextListFile] [-outputPath outputPath]

Encrypt cleartext paths for a Cryptomator vault.

    --passphrase <passphrase>           DO NOT USE. ONLY FOR TESTING PURPOSES.
                                        The cleartext vault passphrase. Omit
                                        this and you will be promted for the
                                        passphrase.
    --passphraseFile <passphraseFile>   A file to read the password from. Omit
                                        this and you will be promted for the
                                        passphrase.
    --vault <vaultPath>                 On which vault to work.
    --cleartextPath <cleartextPath>     Path of the cleartext file in the
                                        vault. Omit this and you will be
                                        prompted for the path.
    --cleartextListFile <cleartextListFile>
                                        Path to a line-separated file that
                                        lists cleartexts in the vault. This
                                        can be used to substitute for
                                        cleartextPath.
    --outputPath <outputPath>           Path of the output file.
                                        Supported extensions: txt, csv
```

### decryptVault command usage

```
java -jar sanitizer-0.16.jar decryptVault -vault vaultPath -target targetPath [-passphraseFile passphraseFile]

Decrypts all data from a vault and tries to restore inaccessible data.

    --passphrase <passphrase>           DO NOT USE. ONLY FOR TESTING PURPOSES.
                                        The cleartext vault passphrase. Omit
                                        this and you will be promted for the
                                        passphrase.
    --passphraseFile <passphraseFile>   A file to read the password from. Omit
                                        this and you will be promted for the
                                        passphrase.
    --target <targetPath>               Where to place the exported data.
    --vault <vaultPath>                 On which vault to work.
```

### Requirements

You need to have Java 9 installed to run this tool.

### Examples

When you have everything set up, you can run the integrity check from the command line (cmd.exe on Windows) using:

```
java -jar sanitizer-x.y.jar check --vault <vaultPath>
```

You will be asked for the vault passphrase in this case. If that fails, you may store your passphrase in a file (without line break at the end!) and use:

```
java -jar sanitizer-x.y.jar check --vault <vaultPath> --passphraseFile <passphraseFile>
```

After completion, the tool will print how many problems were found and create two files:

* `<vaultName>.structure.txt`: The full structure of the vault including all files and directories. Contains only encrypted names and the exact size of small and the approximate size of larger ones so we can not see your data. This may help us to diagnose issues not already handled by Sanitizer.
* `<vaultName>.check.txt`: A list of known issues and some information. This includes the name of the encrypted root directory. This is useful to check how the root directory looks like when analyzing the structure file.

## Building

### Dependencies

* Java 9
* Maven 3

### Run Maven

```bash
mvn clean install
```

## License

Distributed under the GPLv3. See the `LICENSE.txt` file for more info.
