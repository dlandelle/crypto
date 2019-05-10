#!/bin/sh

#$DATA/crypto.exe entree.txt crypt.txt -k "coca cola ma jolie clef"
#$DATA/crypto.exe crypt.txt decrypt.txt -d -k "coca cola ma jolie clef"
#diff entree.txt decrypt.txt |more

#/home/david/projects/crypto/crypto $DATA/crypt.txt $DATA/decrypt.txt -d -k "coca cola ma jolie clef"
#diff $DATA/entree.txt $DATA/decrypt.txt |more

#non reg cryptage
echo "*** NON REGRESSION ***"
CRYPTO=$HOME/Dev/crypt/
echo "cryptage..."
#CRYPTO=/media/DATA/DONNEES/david/Dev/crypto
DATA=$CRYPTO/data
touch $DATA/message0.txt
$CRYPTO/crypto $DATA/message0.txt $DATA/message0.txt.cry -k "coca cola ma jolie clef"
$CRYPTO/crypto $DATA/message1.txt $DATA/message1.txt.cry -k "coca cola ma jolie clef"
$CRYPTO/crypto $DATA/message9.txt $DATA/message9.txt.cry -k "coca cola ma jolie clef"
$CRYPTO/crypto $CRYPTO/crypto.c   $DATA/crypto.txt.cry   -k "coca cola ma jolie clef"
#$CRYPTO/crypto $DATA/big.MOV     $DATA/big.MOV.cry      -k "coca cola ma jolie clef"

echo "decryptage..."
$CRYPTO/crypto $DATA/message0.txt.cry $DATA/_message0.txt -d -k "coca cola ma jolie clef"
$CRYPTO/crypto $DATA/message1.txt.cry $DATA/_message1.txt -d -k "coca cola ma jolie clef"
$CRYPTO/crypto $DATA/message9.txt.cry $DATA/_message9.txt -d -k "coca cola ma jolie clef"
$CRYPTO/crypto $DATA/crypto.txt.cry   $DATA/_crypto.txt   -d -k "coca cola ma jolie clef"
#$CRYPTO/crypto $DATA/big.MOV.cry     $DATA/_big.MOV    -d -k "coca cola ma jolie clef"

echo "diff..."
diff $DATA/message0.txt $DATA/_message0.txt
diff $DATA/message1.txt $DATA/_message1.txt
diff $DATA/message9.txt $DATA/_message9.txt
diff $CRYPTO/crypto.c $DATA/_crypto.txt

#current
echo "*** CUSTOM TEST ***"
echo "entree.txt -> sortie.txt -> decrypt.txt"
$CRYPTO/crypto $DATA/entree.txt $DATA/entree.txt.cry -k "coca cola ma jolie clef"
$CRYPTO/crypto $DATA/entree.txt.cry $DATA/_entree.txt -d -k "coca cola ma jolie clef"
diff $DATA/entree.txt $DATA/_entree.txt

echo "Done."
exit 0
# end
