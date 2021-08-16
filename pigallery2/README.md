Run the runfirst.sh script to make the directory where pigallery2 writes all it's internal config to. Then edit the docker-compose.yml file to point to your media store. I have mine at /mnt/stuffmnt.

Also this line (modify to your liking) will mount a publically accessible samba share to your server.

//192.168.1.17/Movies/Stuff /mnt/stuffmnt cifs guest,uid=1000,iocharset=utf8 0 0 

