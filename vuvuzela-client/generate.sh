num_clients=1000
for client in $(seq 1 $num_clients)
do
    echo "[Removing] Client ${client}"
    rm ../confs/${client}.conf
    rm ../results/${client}.lat
done
for client in $(seq 1 $num_clients)
do
    echo "[Initializing] Client ${client}"
    go run . -init -conf ../confs/${client}.conf -name ${client}
done
