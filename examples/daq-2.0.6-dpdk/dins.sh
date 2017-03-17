#!/bin/bash

rm -R /usr/local/include
rm -R /usr/local/lib
ln -s /usr/local/lib_daq_206 /usr/local/lib
ln -s /usr/local/include_daq_206 /usr/local/include

mv /usr/local/include /usr/local/include_zz
make install
rm -R /usr/local/include
mv /usr/local/include_zz /usr/local/include


