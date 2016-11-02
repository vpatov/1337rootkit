import os
os.system('sudo insmod rootkit.ko')
os.system('sudo rmmod rootkit.ko')
print ''
os.system('cat /var/log/syslog | tail -5') 
print ''
