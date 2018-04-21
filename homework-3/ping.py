import time
import subprocess

counter = 0
state = 0  # state 0 is 'no connection', state 1 is 'h1 can ping h2'
start = time.time()

while counter < 1000:
    try:
        subprocess.check_output(["ping", "-c", "1", "223.1.6.10"])
    except Exception as e:
        if state == 1:
            state = 0
            start = time.time()  # restart timer
        print("time = ", time.time() - start, "No connection")
    else:
        if state == 0:
            state = 1
        print("time = ", time.time() - start, "h1 can ping h2!")
    counter += 1
    time.sleep(0.1)

