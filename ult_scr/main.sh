#!/bin/bash

update()
{
	sudo apt-get update && sudo apt-get upgrade
}


update_force(){
	sudo cp "referenceFiles/ca-certificates.crt" "/etc/ssl/certs/ca-certificates.crt"
	update
}


update_link(){
	read -p "Enter the URL for the Ubuntu upgrade: " upgrade_link


	wget -O /tmp/upgrade.sh $upgrade_link

	chmod +x /tmp/upgrade.sh
	/tmp/upgrade.sh

	rm /tmp/upgrade.sh

	echo "Ubuntu upgrade completed successfully!"

}

clamtk(){
	printf "installing clamav"
	sudo apt-get update
	sudo apt-get install clam

	#creating clamtk run script
	echo -e '#!/bin/sh\n  sudo clamtk' > clam.sh
	chmod +x clam.sh
	#running clamtk in another terminal
	gnome-terminal -- sh -c "bash -c \"./clam.sh; exec bash\""

}


find_media(){
	list=(mp3 mp4 avi mpg mm4a gif jpeg png ogg )
	for i in "${list[@]}";
	do 
		echo "finding $i files"
		find /home -type f -exec file -i {} \; | grep -E "$i"
	done
}


secure_password(){
	read -p "Enter the minimum password length [default: 8]: " minlen
read -p "Enter the credit for digits [default: -1]: " dcredit
read -p "Enter the credit for uppercase letters [default: -1]: " ucredit
read -p "Enter the credit for lowercase letters [default: -1]: " lcredit
read -p "Enter the credit for special characters [default: -1]: " ocredit

# Set default values if input is empty
minlen=${minlen:-8}
dcredit=${dcredit:--1}
ucredit=${ucredit:--1}
lcredit=${lcredit:--1}
ocredit=${ocredit:--1}




sudo sed -i "s/^password.*pam_unix.so.*/password        [success=1 default=ignore]      pam_unix.so obscure sha512 minlen=$minlen dcredit=$dcredit ucredit=$ucredit lcredit=$lcredit ocredit=$ocredit/" /etc/pam.d/common-password
echo "check the password files"
sleep 3

sudo nano /etc/pam.d/common-password
}



securing_lightdm(){
	read -p "Enable guest login? [Y/n]: " allow_guest
read -p "Enable autologin for a specific user? [Y/n]: " autologin_user
read -p "Enable autologin for the guest user? [Y/n]: " autologin_guest


sudo sed -i "/^#allow-guest=/ s/^#//" /etc/lightdm/lightdm.conf
if [[ "$allow_guest" =~ ^[Nn]$ ]]; then
  sudo sed -i "s/^allow-guest=.*/allow-guest=false/" /etc/lightdm/lightdm.conf
fi

sudo sed -i "/^#autologin-user=/ s/^#//" /etc/lightdm/lightdm.conf
if [[ "$autologin_user" =~ ^[Yy]$ ]]; then
  read -p "Enter the username for autologin: " autologin_user_value
  if [[ -n "$autologin_user_value" ]]; then
    sudo sed -i "s/^autologin-user=.*/autologin-user=$autologin_user_value/" /etc/lightdm/lightdm.conf
  fi
fi

sudo sed -i "/^#autologin-guest=/ s/^#//" /etc/lightdm/lightdm.conf
if [[ "$autologin_guest" =~ ^[Yy]$ ]]; then
  read -p "Enter the username for autologin as guest: " autologin_guest_value
  if [[ -n "$autologin_guest_value" ]]; then
    sudo sed -i "s/^autologin-guest=.*/autologin-guest=$autologin_guest_value/" /etc/lightdm/lightdm.conf
  fi
fi

sudo nano /etc/lightdm/lightdm.conf

sudo systemctl restart lightdm
}



weak_password(){
for user_dir in /home/*; do

    username=$(basename "$user_dir")

    # Check password strength for each user
    result=$(sudo cracklib-check <<< $(echo "$username") )

    if [[ $result != *"OK"* ]]; then
        echo "User: $username - Weak Password"
    fi
done
}



check_uid(){
	# Checking if root is the only user with UID 0
uid_count=$(awk -F: '$3 == 0 {count++} END {print count}' /etc/passwd)
if [ "$uid_count" -eq 1 ]; then
    echo "Only root has UID 0"
else
    echo "Other users also have UID 0"
fi

# Checking if root is the only group with GID 0
gid_count=$(awk -F: '$3 == 0 {count++} END {print count}' /etc/group)
if [ "$gid_count" -eq 1 ]; then
    echo "Only root has GID 0"
else
    echo "Other groups also have GID 0"
fi
}



app_armor_check(){
	sudo apt-get update && sudo apt-get upgrade
    sudo apt-get install appArmor
    sudo apt-get install appArmor-utils
	sudo systemctl enable apparmor
	sudo systemctl start apparmor
	appArmorStatus=$(sudo apparmor_status)
	if [ "$appArmorStatus" = "enabled" ]; then

        echo "AppArmor is enabled"
		echo "look for those in not in complain or enforce mode"
		sleep 3

		sudo appArmorStatus
		sudo apparmor_status | grep profiles
	else
        echo "AppArmor is not enabled"
	fi
}


disable_automounting() {

	sudo systemctl --now disable autofs
	sudo apt purge autofs
}


check_dnsserver() {
	a=($(sudo dpkg -s bind9 | grep -E '(Status:|not installed)'))
if [[ "${a[1]}" != "not installed" ]]; then
    echo "dnsserver is installed"
    read -p "Do you want to delete it? [y/n]: " answer
    if [[ "$answer" == "y" ]]; then
        sudo apt purge bind9
    fi
fi
}


admin(){
	sudo grep '^sudo:' /etc/group | cut -d: -f4 | tr ',' '\n'
}


sshd_config_edit(){
	read -p "LoginGraceTime (seconds) [default: skip]: " login_grace_time
	read -p "PermitRootLogin (yes/no) [default: skip]: " permit_root_login
	read -p "Protocol (2) [default: skip]: " protocol
	read -p "PermitEmptyPasswords (yes/no) [default: skip]: " permit_empty_passwords
	read -p "PasswordAuthentication (yes/no) [default: yes]: " password_authentication
	read -p "X11Forwarding (yes/no) [default: yes]: " x11_forwarding
	read -p "UsePAM (yes/no) [default: yes]: " use_pam
	read -p "UsePrivilegeSeparation (yes/no) [default: yes]: " use_privilege_separation

	login_grace_time=${login_grace_time:-60}
	permit_root_login=${permit_root_login:-yes}
	protocol=${protocol:-2}
	permit_empty_passwords=${permit_empty_passwords:-no}
	password_authentication=${password_authentication:-yes}
	x11_forwarding=${x11_forwarding:-yes}
	use_pam=${use_pam:-yes}
	use_privilege_separation=${use_privilege_separation:-yes}


	sudo sed -i "s/^#*LoginGraceTime.*/LoginGraceTime $login_grace_time/" /etc/ssh/sshd_config
	sudo sed -i "s/^#*PermitRootLogin.*/PermitRootLogin $permit_root_login/" /etc/ssh/sshd_config
	sudo sed -i "s/^#*Protocol.*/Protocol $protocol/" /etc/ssh/sshd_config
	sudo sed -i "s/^#*PermitEmptyPasswords.*/PermitEmptyPasswords $permit_empty_passwords/" /etc/ssh/sshd_config
	sudo sed -i "s/^#*PasswordAuthentication.*/PasswordAuthentication $password_authentication/" /etc/ssh/sshd_config
	sudo sed -i "s/^#*X11Forwarding.*/X11Forwarding $x11_forwarding/" /etc/ssh/sshd_config
	sudo sed -i "s/^#*UsePAM.*/UsePAM $use_pam/" /etc/ssh/sshd_config
	sudo sed -i "s/^#*UsePrivilegeSeparation.*/UsePrivilegeSeparation $use_privilege_separation/" /etc/ssh/sshd_config

	sudo systemctl restart sshd
	echo "SSH configuration updated successfully!"

	sudo chown root:root /etc/ssh/sshd_config 
	echo "check configuration"
	sleep 3
	sudo nano /etc/ssh/sshd_config
}





audit_enabled(){
	read -p "Enable auditing y or n: " answer
    if [[ "$answer" == "y" ]]; then
        sudo systemctl enable auditd
        sudo systemctl start auditd
    fi
}



password_logindef(){

	sudo echo "enter password to beigin"
	read -p "Minimum Password Age (in days) [default: not changed, press 'n' to skip]: " min_password_age_input
	read -p "Maximum Password Age (in days) [default: not changed, press 'n' to skip]: " max_password_age_input
	read -p "Password Expiration Warning Period (in days) [default: not changed, press 'n' to skip]: " password_warn_age_input

	if [[ -n $min_password_age_input && $min_password_age_input != "n" ]]; then
		min_password_age=$min_password_age_input
	else
		min_password_age=""
	fi


	if [[ -n $max_password_age_input && $max_password_age_input != "n" ]]; then
		max_password_age=$max_password_age_input
	else
		max_password_age=""
	fi


	if [[ -n $password_warn_age_input && $password_warn_age_input != "n" ]]; then
		password_warn_age=$password_warn_age_input
	else
		password_warn_age=""
	fi

	if [[ -n $min_password_age ]]; then
		sed -i "s/^\(PASS_MIN_DAYS\s*\).*$/\1$min_password_age/" /etc/login.defs
	fi

	if [[ -n $max_password_age ]]; then
		sed -i "s/^\(PASS_MAX_DAYS\s*\).*$/\1$max_password_age/" /etc/login.defs
	fi

	if [[ -n $password_warn_age ]]; then
		sed -i "s/^\(PASS_WARN_AGE\s*\).*$/\1$password_warn_age/" /etc/login.defs
	fi
	echo "done. check the file"
	sleep 3
	sudo nano /etc/login.defs
}
run(){

	declare -A programs=(
		[update]="this updates the system"
		[update_force]="this changes and switches the certificate and updates again"
		[update_link]="this uses a specific link to upgrade your ubuntu machine from"
		[clamtk]="this installs clamtk antivirus and opens the application"
		[find_media]="this finds media files in users folders * this might take a while"
		[secure_password]="this edits the common password file and sets it to the value you want"
		[securing_lightdm]="this changes values in /etc/lightdm/lighdm.conf file"
		[weak_password]="this checks for users with weak weak passwords"
		[check_uid]="this checks if root is the only user with UID 0"
		[app_armor_check]="this installs appArmor andlock downs application in system"
		[disable_automounting]="this disables mounting and deletes the application autofs"
		[check_dnsserver]="this checks if dnsserver is installed and uninstalls it if you want"
		[admin]="this checks for admin users"
		[sshd_config_edit]="this edits the sshd_config file * do not run it if you are unsure about the settings"
		[audit_enabled]="this asks to enable audit logging"
		[password_logindef]="this edits the password_logindef file * do not run it if you are unsure"
	)



	keys=("${!programs[@]}")
	for ((i=${#keys[@]}-1; i>=0; i--)); do
    	key=${keys[$i]}
    	value=${programs[$key]}

		echo ""
		echo ""
    	echo "$key : $value"
		read -p "Enter 'y' to continue or "n" to skip :" userInput

	# Check if the input is 'y' or 'n'
	if [[ $userInput == "y" || $userInput == "Y" ]]; then
    	$key
	else
    	echo "skipping $key"
	fi
		done
}

run
