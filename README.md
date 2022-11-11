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

## Testing the plugin
The script in ci/testRunner can be used locally to test new builds of the plugin.

It works by running various binaries in emulated and generated mode:
- Spice86 vanilla is run for each binary, and run data are collected
- The plugin is called with the run data to generate code
- Generated code is built and run, run data are collected
- Emulated and geneated code ram are compared, if there is any difference the script stops.

Before you run it you need:
- Spice86 compiled somewhere
- Ghidra installed
- The plugin installed in Ghidra (Until I figure out how to do a headless plugin install :) )
- The spice86 cpu tests somewhere

Example run:
```
./ci/testRunner \
--spice86Exe=/path/to/spice86exe/Spice86 \
--testBinRoot=/path/to/cpuTests/ \
--ghidraHome=/path/to/ghidra_10.1.5_PUBLIC/ \
--scriptPath=/path/to/spice86-ghidra-plugin/src/main/java/
```

If you specify a folder to --workspace, the script will run there, otherwise it will create a temp folder.

If you don't want it to update the spice86 template from nuget (used to generate a project for generated code), you can say so by specifying --skipTemplateUpdate=true