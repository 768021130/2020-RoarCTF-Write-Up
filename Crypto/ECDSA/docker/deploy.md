执行命令示范：
sudo docker build -t "roarctf2020_ecdsa" .
sudo docker run -dit -p 10305:10305 --name "roarctf2020_ecdsa" roarctf2020_ecdsa

注意：
题目端口由运维自行确定，可以在dockerfile中修改PORT的值

