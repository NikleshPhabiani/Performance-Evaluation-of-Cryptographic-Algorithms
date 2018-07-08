#
#defining makefile variable for java compiler
#
JCC = javac

#
#defining a makefile variable for compilation flags
#
JFLAGS = -g

#
#defining the default target entry in the makefile which comprises of the names of our .class file
#In our case, it is Cryptotest.class
#Cryptotest.class file is dependent on Cryptotest.java file
#
default: Cryptotest.class

#
#defining the target entry in which the rule associated 
#with the entry gives the command to create Cryptotest.class file
#
Cryptotest.class: Cryptotest.java
	$(JCC) $(JFLAGS) Cryptotest.java

#	
#To start over from scratch, type 'make clean'
#This will remove all .class file, so that the next make rebuilds them
#
clean:
	$(RM) *.class