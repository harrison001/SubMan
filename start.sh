#!/bin/bash

# 查找并结束之前创建的进程
pid=$(ps -ef | grep "subman.py" | grep -v grep | awk '{print $2}')
if [ -n "$pid" ]; then
    echo "Stopping previous process with PID $pid"
    kill $pid
fi

# 启动新的后台进程
nohup python subman.py > subman.log 2>&1 &
echo "New process started"
