# Spice86 Ghidra Plugin
## What it is
- Imports Spice86 data into Ghidra
- Generates C# code from the imported data

Everything is under the new menu Spice86 that you will get after installing the plugin
## Requirement
- Java 17
- Ghidra (of course!)

## Building the plugin
Prerequisites:
- Create an environment variable pointing to you ghidra local install called GHIDRA_INSTALL_DIR. Example: GHIDRA_INSTALL_DIR=/home/kevin/ghidra_10.1.2_PUBLIC
- Install JDK 17
- Install Gradle 7.5 or above

Run the following command in a terminal of your choice.
```
gradle buildExtension
```
Upon completion the output will be located in the dist folder.

Sometimes ghidra doesn't like a plugin being redeployed over and over. When you do changes, you can alternatively just redeploy the jar to the correct folder. Here is what I added to my .zshrc to do it:
```
export GHIDRA_VERSION="10.1.5_PUBLIC"
alias deployghidra='unzip -f dist/ghidra_${GHIDRA_VERSION}_`date +"%Y%m%d"`_spice86-ghidra-plugin.zip -d dist && cp dist/spice86-ghidra-plugin/lib/* ~/.ghidra/.ghidra_${GHIDRA_VERSION}/Extensions/spice86-ghidra-plugin/lib'
```
Then once build is done simply type deployghidra