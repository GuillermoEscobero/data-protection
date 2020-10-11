# @Author: Guillermo Escobero, Alvaro Santos
# @Date:   11-10-2020
# @Project: Data Protection Lab
# @Filename: run-tests.sh
# @Last modified by:   Guillermo Escobero, Alvaro Santos
# @Last modified time: 11-10-2020



# Enter in classpath
cd src/

# Compile java files
javac main/java/lab1/SymmetricEncryption.java
javac main/java/lab1/SymmetricCipher.java
javac main/java/lab2/RSALibrary.java

# Compile tests
javac test/java/lab1/TestSymmetricCipher.java
javac test/java/lab2/TestRSALibrary.java

# Execute tests
echo -e "\nLab 1 tests..."
java test/java/lab1/TestSymmetricCipher

echo -e "\nLab 2 tests..."
java test/java/lab2/TestRSALibrary

echo -e "\nLab 3 tests..."
#java main/java/lab3/SimpleSec g
#java main/java/lab3/SimpleSec e readme.txt readme.txt.enc
java main/java/lab3/SimpleSec d readme.txt.enc readme2.txt
