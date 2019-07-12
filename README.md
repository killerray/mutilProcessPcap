# mutilProcessPcap
用python封装tshark对多个pcap文件并行的进行相同处理
使用前请先安装Wireshark，如果是Windows系统，请将Wireshark安装路径添加到环境变量
# 使用举例：
python packet_extract.py <pcap文件夹路径> 4（进程数） "tcp"（过滤表达式）
# 适用场景：
适合多文件夹多文件的进行相同处理
