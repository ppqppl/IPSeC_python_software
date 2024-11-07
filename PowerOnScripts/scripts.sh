#!/bin/sh
echo "Usb NIC enable"
echo 64 > /sys/class/gpio/export
sleep 2
echo out > /sys/class/gpio/gpio64/direction
sleep 2
echo 1 > /sys/class/gpio/gpio64/value
sleep 2

echo "Reset net server side"
if [ -f "/usr/data/backend_api_server/worker/W.pyc" ];then
#  echo "1"
  rm /usr/data/backend_api_server/worker/W.pyc
  echo "Net server side has been reset"
else
  echo "Net server side has been reset"
fi

for ((a = 0;a < 10; a++))
do
  if ifconfig -a |grep eth0 >/dev/null ;then
    a=10
    echo "eth0 up"
    ifconfig eth0 up
    sleep 2
    echo "eth0 ip set"
    ifconfig eth0 10.10.1.7 netmask 255.255.255.0
  else
          echo "Finding eth0 now " + $a
  fi
  sleep 1
done