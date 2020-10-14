# @Author: Guillermo Escobero, Alvaro Santos
# @Date:   11-10-2020
# @Project: Data Protection Lab
# @Filename: run-tests.sh
# @Last modified by:   Guillermo Escobero, Alvaro Santos
# @Last modified time: 12-10-2020



#!/bin/bash

# Enter in classpath
cd src/

# Compile java files
javac main/java/lab1/SymmetricEncryption.java
javac main/java/lab1/SymmetricCipher.java
javac main/java/lab2/RSALibrary.java
javac main/java/lab3/SimpleSec.java

# Compile tests
javac test/java/lab1/TestSymmetricCipher.java
javac test/java/lab2/TestRSALibrary.java

# Execute tests
echo -e "\nLab 1 tests..."
java test/java/lab1/TestSymmetricCipher

echo -e "\nLab 2 tests..."
java test/java/lab2/TestRSALibrary

echo -e "\nLab 3 tests..."
echo -e "\nGenerating SimpleSec.jar file..."
jar cfe ../SimpleSec.jar main.java.lab3.SimpleSec main/java/lab1/*.class main/java/lab2/*.class main/java/lab3/*.class

echo "encrypt this" > readme.txt
java -jar ../SimpleSec.jar g
java -jar ../SimpleSec.jar e readme.txt readme.txt.enc
java -jar ../SimpleSec.jar d readme.txt.enc readme.out

diff readme.txt readme.out

if [ $? -eq 0 ];
then
    echo -e "SimpleSec basic test PASS"
else
    echo -e "SimpleSec basic test FAILED"
fi

echo -e "--Decrypt plain file:"
java -jar ../SimpleSec.jar g
java -jar ../SimpleSec.jar d readme.txt readme.txt.enc

echo -e "--Decrypt non-existing file:"
java -jar ../SimpleSec.jar g
java -jar ../SimpleSec.jar d doesnotexist.txt readme.txt.enc

echo -e "--Encrypt non-existing file:"
java -jar ../SimpleSec.jar g
java -jar ../SimpleSec.jar e doesnotexist.txt readme.txt.enc

echo -e "--No private key found:"
java -jar ../SimpleSec.jar g
rm private.key
java -jar ../SimpleSec.jar d readme.txt.enc readme.txt
java -jar ../SimpleSec.jar e readme.txt readme.txt.enc

echo -e "--No public key found:"
java -jar ../SimpleSec.jar g
rm public.key
java -jar ../SimpleSec.jar d readme.txt.enc readme.txt
java -jar ../SimpleSec.jar e readme.txt readme.txt.enc

echo -e "--Try to decrypt with wrong keys"
java -jar ../SimpleSec.jar g
java -jar ../SimpleSec.jar d readme.txt.enc readme.txt

echo -e "--Corrupt private.key file"
java -jar ../SimpleSec.jar g
java -jar ../SimpleSec.jar e readme.txt readme.txt.enc
rm private.key
echo "not valid" > private.key
java -jar ../SimpleSec.jar d readme.txt.enc readme.txt
java -jar ../SimpleSec.jar e readme.txt readme.txt.enc

echo -e "--Corrupt public.key file"
java -jar ../SimpleSec.jar g
java -jar ../SimpleSec.jar e readme.txt readme.txt.enc
rm public.key
echo "not valid" > public.key
java -jar ../SimpleSec.jar d readme.txt.enc readme.txt
java -jar ../SimpleSec.jar e readme.txt readme.txt.enc

echo -e "Done."
