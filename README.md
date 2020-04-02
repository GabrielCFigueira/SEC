# SECproj
SEC project

## Requirements

Java version: 8 or higher
Maven version: 3.6.3

## Compile and run the tests

1) mvn clean install in project folder

2) mvn clean test in project folder

## Run the interface:

1)On the Server directory: mvn exec:java -Dexec.mainClass="sec.dpas.Server"

2)On the Client directory: mvn exec:java -Dexec.mainClass="sec.dpas.Client"

## After running the interface

Remove the .txt files to avoid conflicts with the automatic tests: rm resources/*.txt
