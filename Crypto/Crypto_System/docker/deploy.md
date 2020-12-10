执行命令示范：
sudo docker build -t "roarctf2020_cryptosystem" .
sudo docker run -dit -p 10306:10306 --name "roarctf2020_cryptosystem" roarctf2020_cryptosystem

注意：
题目端口由运维自行确定，可以在dockerfile中修改PORT的值

