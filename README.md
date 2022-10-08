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