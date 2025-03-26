#!/bin/bash

#FILE="/home/simpuar/Desktop/tmp.txt"

export DISPLAY=:0
export XAUTHORITY=/home/astra/.Xauthority

#sudo -u simpuar bash -c 'echo $DISPLAY' >> "$FILE"
#sudo -E -u simpuar bash -c 'echo $XAUTHORITY' >> "$FILE"

./sbin/coretaskd &
