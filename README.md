figure out the scoring check
```sudo ./moni.sh -d```
 reinstall all services and update packages and check keyring
```sudo package_install.sh```
 implement firewall
```sudo init_firewall.sh --remove-whitelist```
 general ubuntu auto hardening
```sudo ubuntu_setup.sh```
 periodically run 
```sudo ./enum.sh | less -R```

# harden your service
