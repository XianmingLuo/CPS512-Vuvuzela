num_clients=10
for client in $(seq 1 $num_clients)
do
    echo "[Removing] Client $client Result"
    rm ../results/${client}.lat
done

for client in $(seq 1 $num_clients)
do
    echo "[Starting] Client ${client}"
    go run . -conf ../confs/${client}.conf  >/dev/null &
done


for iter in {1..50}
do
    echo "[Running] ${iter}..."
    sleep 2
done
echo "[Cleaning] Terminating Clients"
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT


