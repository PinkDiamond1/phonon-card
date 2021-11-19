# Phonon Card
## This is the reference implementation of the card specification of the [phonon](https://github.com/GridPlus/phonon-network) project by [GridPlus](https://gridplus.io)

## Building
building this is a little difficult. You will first need the following things downladed and the following env vars set:

`JAVA_8_ROOT=/path/to/java/8/root`
`JAVACARD_TOOLS_ROOT=/path/to/java_card_tools-win-bin-b_17-06_jul_2021`
`GLOBAL_PLATFORM_JAR=/path/to/gp.jar`
Java 8 can be downloaded from: [here](https://www.oracle.com/java/technologies/downloads/#java8)

Javacard tools can be downloaded from: [here](https://www.oracle.com/java/technologies/javacard-sdk-downloads.html)
note: the javacard tools say it's a windows version. The build commands just use the jar files within the javacard sdk tools and don't use the windows shell scripts. 
the gp.jar file can be downloaded from [here](https://javacard.pro/globalplatform/)

### Compiling the class files
`$JAVA_8_ROOT/Contents/Home/bin/javac -O -g -classpath "${JAVACARD_TOOLS_ROOT/lib/api_classic-3.0.4.jar" -target 1.6 -source 1.6 -d "./outputs/classfiles" ./Phonon/src/io.gridplus/phonon/*.java`
### Generating phonon.cap
`${JAVA_8_ROOT}/Contents/Home/bin/java -classpath "${JAVACARD_TOOLS_ROOT}/lib/tools.jar" com.sun.javacard.converter.Main \
	-applet 0xA0:0x00:0x00:0x08:0x20:0x00:0x03:0x01 io.gridplus.phonon.PhononApplet \
	-classdir "./outputs/classfiles" \
	-out CAP \
	-d ./outputs \
	-v \
	-target 3.0.4 \
	io.gridplus.phonon \
	0xA0:0x00:0x00:0x08:0x20:0x00:0x03 \
	1.1`
### Installing the cap to a card
`java -jar GLOBAL_PLATFORM_JAR --delete A0000008200003`
and then
`java -jar GLOBAL_PLATFORM_JAR --install "./outputs/io/gridplus/phonon/javacard/phonon.cap" --applet A000000820000301 --package A0000008200003


