num_clients=64
sums = []
for client in range(1, num_clients+1):
    filepath = "../results/{client:d}.lat".format(client = client)
    file = open(filepath, 'r')
    lines = file.readlines()

    latencies = [eval(line) for line in lines]
    sums.append(sum(latencies) / len(latencies))
print(sum(sums) / len(sums))
    
