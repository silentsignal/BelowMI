#!/bin/sh

TMPFILE=$(mktemp)

MYDATE=`date +'%F'`
MYCOMMIT=`git log -1 | fgrep commit | cut -d ' ' -f 2`

echo '% Below MI - IBM i for Hackers' >> $TMPFILE
echo '% PUBLIC' >> $TMPFILE
echo "% Version: $MYDATE ($MYCOMMIT)" >> $TMPFILE
echo '' >> $TMPFILE

cat BelowMI.md >> $TMPFILE

pandoc $TMPFILE -f markdown -o index.html --standalone -c https://neat.joeldare.com/neat.css

# head -n 10 $TMPFILE # debug
rm $TMPFILE
