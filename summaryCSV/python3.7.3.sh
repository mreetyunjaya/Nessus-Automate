#!/bin/bash
# A bash script for installing Python 3.7.3.
# (c) 2021 Mreetyunjaya Daas.
#
# Open your terminal and type the following command:
# sudo wget https://gist.githubusercontent.com/itsVale/5619215a46d363ece9fc7cdfdfa301c8/raw/raspberry_python.sh && chmod +x raspberry_python.sh && ./raspberry_python.sh

sudo apt-get update -y
sudo apt-get upgrade
sudo apt-get dist-upgrade

sudo apt-get install build-essential libncurses5-dev libncursesw5-dev libreadline6-dev libdb5.3-dev libgdbm-dev libc6-dev libbz2-dev libexpat1-dev liblzma-dev zlib1g-dev libsqlite3-dev tk-dev libssl-dev openssl libffi-dev -y

mkdir Python-Installation
cd Python-Installation

wget https://www.python.org/ftp/python/3.7.3/Python-3.7.3.tgz
tar xzvf Python-3.7.3.tgz
rm -f Python-3.7.3.tgz

cd Python-3.7.3
sudo ./configure --enable-optimizations
sudo make -j 4
sudo make altinstall

cd ../..
sudo rm -rf Python-Installation

sudo apt-get --purge remove build-essential libncurses5-dev libncursesw5-dev libreadline6-dev libdb5.3-dev libgdbm-dev libc6-dev libz2-dev libexpat1-dev liblzma-dev zlib1g-dev libsqlite3-dev tk-dev libssl-dev openssl libffi-dev -y
sudo apt-get autoremove -y
sudo apt-get clean

python3.7.3 -m pip install --upgrade pip
sudo echo 'alias pip3="python3.7.3 -m pip"' >> ~/.bashrc
