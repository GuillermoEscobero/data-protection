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
java test/java/lab1/TestSymmetricCipher

java test/java/lab2/TestRSALibrary
