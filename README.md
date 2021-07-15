# cryptography_a1
### tess.txt

This is the ASCII text of Tess of the d'Urbervilles from the Project Gutenberg website. Provided mainly for interest, and for the licensing information at the end.

### tess27.txt

This is tess.txt reduced to a 27-character alphabet in the following way:
=Prefatory and ending material from Project Gutenberg that isn't part of the novel itself has been removed;
=Apostrophes have been removed;
=Lower-case letters have been converted to upper case;
=Each sequence of one or more non-letter characters (including for example digits, punctuation, hyphens and whitespace) has been replaced by a single '|' (vertical bar) character.

### tess26.txt

A further reduction to a 26-character alphabet, obtained by omitting the vertical bars from tess27.txt.



For most exercises, the plaintext is a randomly chosen string of 840 characters taken from tess26.txt; the exceptions are Exercise 2, where the extract is only 30 characters long, and Exercise 7, where the extract comes from tess27.txt. You therefore cannot assume that the extract will start at the beginning of a word in the original novel, nor that it ends at the end of a word.


### Exercise 1 (2 marks)

The plaintext comes from tess26.txt and is encoded with a Caesar cipher.

### Exercise 2 (3 marks)

The plaintext comes from tess26.txt and is encoded with a Vigenere cipher using the 21-letter key TESSOFTHEDURBERVILLES.

### Exercise 3 (4 marks)

The plaintext comes from tess26.txt and is encoded with a Vigenere cipher. The key is an arbitrary sequence of six letters (i.e. not necessarily forming an English word).

### Exercise 4 (5 marks)

The plaintext comes from tess26.txt and is encoded with a Vigenere cipher. The key is an arbitrary sequence of between 4 and 6 letters.

### Exercise 5 (5 marks)

The plaintext comes from tess26.txt and is encoded with a transposition cipher, as follows: the plaintext is written row-wise across a certain number of columns,

between 4 and 6. (You must figure out how many columns were used.) The ciphertext is formed by reading out successive columns from left to right.

### Exercise 6 (5 marks)

The plaintext comes from tess26.txt and is encoded with a transposition cipher, as follows: the plaintext is written row-wise across six columns. The ciphertext is formed by reading out successive columns in an arbitrary order (which you must figure out to decipher the message). Hint:look for common pairs of letters, such as 'th'.

### Exercise 7 (6 marks)

The plaintext comes from tess27.txt and is encoded with a general substitution cipher, using a randomly chosen mapping from the 27-character alphabet onto itself. Note that normally (i.e. except by chance) a vertical bar will be mapped onto some other letter of the alphabet.
